"""The fixer's `PreToolUse` deny hook and its `Stop` regression-test gate.

The fixer is the only agent in Pramaan that can write. Everything it is *not*
allowed to do is enforced here rather than described in a prompt, because a
prompt is a request and a hook is a decision: the SDK applies hook denials even
under `bypassPermissions`, so this is the layer that still holds when the
permission mode is wrong or an injected instruction talks the model into trying.

The deny list is the guardrails table's, plus its obvious cousins. `curl` and
`wget` are named in the contract; `nc`, `socat`, `ssh` and `scp` move bytes off
the box exactly as well, and a deny list that stops only the two spellings
someone thought of is a deny list that has not been tested against an adversary.

Three fail-closed rules, in order of how easy they are to get wrong:

1. **A command that cannot be parsed is denied.** Unbalanced quotes are not a
   reason to guess.
2. **Command substitution, `eval` and nested shells are denied wholesale.**
   `$(printf '\\x63url')` is a `curl` this module cannot see by name, so the
   construct goes rather than the name.
3. **Secret-shaped paths are checked on every token of every command**, not just
   on the tool's `file_path`. `grep -r . --include=*.pem` is a read of a private
   key through a tool whose arguments nobody thought to check.

The `Stop` gate is the other half. A patch with no regression test is a patch
that can silently regress on the next refactor, and PROJECT-BRAINSTORM's fixer
row requires one in the diff. The gate blocks the agent from finishing until a
test appears - but only a bounded number of times, because an unbounded Stop
loop burns the $5 budget arguing with a model that has already decided. When the
bound is hit the gate gives up and records `satisfied=False`, which
`regression_test_validator` turns into a failing validator, which blocks the PR.
Giving up on the loop is not giving up on the requirement.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any, Callable, Iterable, Mapping, Sequence

from pramaan.schemas import ValidatorResult
from pramaan.validators.diff_scope import DiffParseError, is_test_path, parse_unified_diff

__all__ = [
    "DENIED_BINARIES",
    "DENIED_GIT_SUBCOMMANDS",
    "FIXER_HOOK_MATCHER",
    "SECRET_PATH_GLOBS",
    "SECRET_PATH_SEGMENTS",
    "Denial",
    "RegressionTestGate",
    "check_bash",
    "check_path",
    "check_tool",
    "denials_summary",
    "has_regression_test",
    "make_deny_hook",
    "make_regression_test_hook",
    "regression_test_validator",
]

# Every tool. A deny hook scoped to `Bash` is a deny hook that misses
# `Read(".env")`.
FIXER_HOOK_MATCHER = ".*"

DENIED_BINARIES: frozenset[str] = frozenset(
    {
        # named in the guardrails table
        "curl", "wget",
        # the same capability, other spellings
        "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp",
        "ssh", "scp", "sftp", "rsync", "aria2c", "axel", "lynx", "links", "w3m",
        "httpie", "http", "https", "xh",
        # credential-bearing clients and package installers (egress + supply chain)
        "gh", "hub", "glab", "aws", "gcloud", "az", "kubectl", "docker", "podman",
        "pip", "pip3", "pipx", "poetry", "uv", "npx",
        "gem", "bundle", "cargo", "brew", "apt", "apt-get", "yum", "dnf",
    }
)

# `Bash(composer test *)` and `Bash(npm test*)` are in the fixer's tool allowlist,
# so these four cannot be denied outright - but every other subcommand of them
# installs code from a registry, which is a supply-chain decision the proof
# bundle cannot validate.
_PACKAGE_MANAGERS: frozenset[str] = frozenset({"composer", "npm", "yarn", "pnpm"})
_PM_DIRECT_OK: frozenset[str] = frozenset({"test", "t"})
_PM_INDIRECT: frozenset[str] = frozenset({"run", "run-script", "exec"})

# All of these reach the network or set up something that will.
DENIED_GIT_SUBCOMMANDS: frozenset[str] = frozenset(
    {"push", "fetch", "pull", "clone", "remote", "submodule", "request-pull", "send-email"}
)

_NESTED_SHELLS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh", "ash", "busybox"}
)

# `-c` / `-e` turn an interpreter into an arbitrary-code channel that no binary
# name check can inspect.
_EVAL_INTERPRETERS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "node": frozenset({"-e", "--eval", "-p"}),
    "php": frozenset({"-r"}),
}

_WRAPPERS: frozenset[str] = frozenset(
    {"env", "sudo", "doas", "nohup", "nice", "time", "timeout", "stdbuf",
     "command", "exec", "xargs", "setsid", "ionice"}
)

# Whole-command shapes. Only constructs that cannot plausibly appear inside an
# ordinary test selector - `eval` and `base64` are checked per-segment as command
# names instead, so `pytest -k eval` is not denied.
_OBFUSCATION: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("command_substitution", re.compile(r"\$\(|`")),
    ("process_substitution", re.compile(r"<\(|>\(")),
    ("redirect_to_network", re.compile(r"/dev/(?:tcp|udp)/")),
)

_EVAL_BUILTINS: frozenset[str] = frozenset({"eval", "source", "."})
_DECODERS: frozenset[str] = frozenset({"base64", "xxd", "uudecode", "openssl"})

# Path segments that are a credential store on sight.
SECRET_PATH_SEGMENTS: frozenset[str] = frozenset(
    {".env", ".envrc", ".netrc", "_netrc", ".npmrc", ".pypirc", ".ssh", ".aws",
     ".gnupg", ".docker", ".kube", "credentials.json",
     "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
)

SECRET_PATH_GLOBS: tuple[str, ...] = (
    ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", "service-account*.json",
    "*credentials*.json", "*.kdbx",
)

_RM_RECURSIVE = re.compile(r"^-[a-zA-Z]*[rR]")
_RM_FORCE = re.compile(r"^-[a-zA-Z]*f")


@dataclass(frozen=True, slots=True)
class Denial:
    rule: str
    reason: str

    def as_hook_output(self) -> dict[str, Any]:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": self.reason,
            }
        }


def _basename(token: str) -> str:
    name = token.replace("\\", "/").rsplit("/", 1)[-1]
    return name[:-4].lower() if name.lower().endswith(".exe") else name.lower()


def check_path(path: str | None) -> Denial | None:
    """Deny `.env`, `*.pem` and the rest of the credential shapes.

    Segment-exact or glob on the basename, never a substring: `environment.php`
    contains `.env` as a substring and is an ordinary source file. A detector
    that fires on it gets switched off, and a detector that is switched off
    protects nothing.
    """
    if not path:
        return None
    cleaned = str(path).strip().strip("\"'").replace("\\", "/")
    if not cleaned:
        return None
    for segment in cleaned.split("/"):
        low = segment.lower()
        if not low or low in (".", ".."):
            continue
        if low in SECRET_PATH_SEGMENTS:
            return Denial(
                "secret_path", f"denied: {segment!r} is a credential path ({path!r})"
            )
        if any(fnmatch(low, glob) for glob in SECRET_PATH_GLOBS):
            return Denial(
                "secret_path", f"denied: {segment!r} matches a secret-file pattern ({path!r})"
            )
    return None


def _real_binary(tokens: Sequence[str]) -> tuple[str | None, list[str]]:
    """Strip `VAR=value` prefixes and wrappers (`env`, `sudo`, `timeout 5`)."""
    i = 0
    while i < len(tokens):
        token = tokens[i]
        head = token.split("=", 1)[0]
        if "=" in token and head and "/" not in head and not head.startswith("-"):
            i += 1
            continue
        base = _basename(token)
        if base in _WRAPPERS:
            i += 1
            while i < len(tokens) and (
                tokens[i].startswith("-") or tokens[i].replace(".", "", 1).isdigit()
            ):
                i += 1
            continue
        return base, list(tokens[i:])
    return None, []


def check_bash(command: str | None) -> Denial | None:
    """Deny `git push`, `curl`, `wget`, `rm -rf`, and anything touching a secret."""
    if command is None or not isinstance(command, str):
        return Denial("unparseable_command", "denied: Bash call carried no command string")
    if not command.strip():
        return Denial("unparseable_command", "denied: empty Bash command")

    for rule, pattern in _OBFUSCATION:
        if pattern.search(command):
            return Denial(
                rule,
                f"denied: {rule.replace('_', ' ')} in a Bash command hides what would "
                "actually run",
            )

    for segment in _split_segments(command):
        try:
            tokens = shlex.split(segment)
        except ValueError as exc:
            return Denial(
                "unparseable_command",
                f"denied: could not parse the command ({exc}); an unparseable command "
                "is an unknown command",
            )
        if not tokens:
            continue

        for token in tokens:
            denial = check_path(token)
            if denial is not None:
                return denial
            for prefix in ("--file=", "--include=", "--exclude=", "-f=", "--path="):
                if token.startswith(prefix):
                    denial = check_path(token[len(prefix) :])
                    if denial is not None:
                        return denial

        binary, rest = _real_binary(tokens)
        if binary is None:
            continue

        if binary in DENIED_BINARIES:
            return Denial("denied_binary", f"denied: {binary!r} is not available to the fixer")
        if binary in _PACKAGE_MANAGERS:
            denial = _check_package_manager(binary, rest[1:])
            if denial is not None:
                return denial
        if binary in _NESTED_SHELLS:
            return Denial(
                "nested_shell",
                f"denied: {binary!r} spawns a shell whose command line is not inspectable",
            )
        if binary in _EVAL_BUILTINS:
            return Denial(
                "eval", f"denied: {binary!r} runs a command this hook cannot read"
            )
        if binary in _DECODERS:
            return Denial(
                "encoded_payload",
                f"denied: {binary!r} decodes a payload whose contents are not inspectable",
            )
        eval_flags = _EVAL_INTERPRETERS.get(binary)
        if eval_flags and any(t in eval_flags for t in rest[1:]):
            return Denial(
                "code_eval", f"denied: {binary} inline code execution bypasses the tool policy"
            )
        if binary == "git":
            subcommand = _git_subcommand(rest[1:])
            if subcommand in DENIED_GIT_SUBCOMMANDS:
                return Denial(
                    "git_network",
                    f"denied: `git {subcommand}` reaches the network or prepares to; the "
                    "fixer's work leaves the sandbox as a diff, never as a push",
                )
        if binary == "rm":
            flags = [t for t in rest[1:] if t.startswith("-")]
            recursive = any(_RM_RECURSIVE.match(f) for f in flags) or "--recursive" in flags
            force = any(_RM_FORCE.match(f) for f in flags) or "--force" in flags
            if recursive and force:
                return Denial(
                    "rm_rf", "denied: `rm -rf` is never part of a security fix"
                )
    return None


# git's global options that consume the token after them. Without these,
# `git -C /worktree push` reads as the subcommand `/worktree` and slips past.
_GIT_VALUE_OPTS: frozenset[str] = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
)


def _git_subcommand(args: Sequence[str]) -> str | None:
    i = 0
    while i < len(args):
        token = args[i]
        if token in _GIT_VALUE_OPTS:
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        return token.lower()
    return None


def _check_package_manager(binary: str, args: Sequence[str]) -> Denial | None:
    """Only the test entry point. `npm install` is a supply-chain change."""
    positional = [a for a in args if not a.startswith("-")]
    if not positional:
        return Denial(
            "package_manager",
            f"denied: bare `{binary}` - only the test entry point is available to the fixer",
        )
    first = positional[0].lower()
    if first in _PM_DIRECT_OK:
        return None
    if first in _PM_INDIRECT:
        if len(positional) > 1 and positional[1].lower().startswith("test"):
            return None
        return Denial(
            "package_manager",
            f"denied: `{binary} {first}` may only run a script named test*",
        )
    return Denial(
        "package_manager",
        f"denied: `{binary} {first}` installs or publishes code; the fixer may only "
        f"run `{binary} test`",
    )


def _split_segments(command: str) -> list[str]:
    """Split on shell control operators, honouring quotes."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if quote is not None:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue
        if command[i : i + 2] in ("&&", "||"):
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in (";", "|", "&", "\n"):
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


_PATH_KEYS = ("file_path", "path", "notebook_path", "filePath", "target_file")
_EGRESS_TOOLS = frozenset({"webfetch", "websearch", "fetch", "browser"})


def check_tool(tool_name: str, tool_input: Mapping[str, Any] | None) -> Denial | None:
    """The single decision function. Unknown shapes are inspected, not waved through."""
    name = (tool_name or "").strip()
    low = name.lower()
    data = tool_input if isinstance(tool_input, Mapping) else {}

    if low in _EGRESS_TOOLS:
        return Denial("egress_tool", f"denied: {name} is network egress; the fixer runs offline")

    if low == "bash" or low.startswith("bash"):
        return check_bash(data.get("command"))

    for key in _PATH_KEYS:
        denial = check_path(data.get(key))
        if denial is not None:
            return denial

    # Some tools carry a command under another name (`Bash` via MCP wrappers).
    command = data.get("command")
    if isinstance(command, str):
        return check_bash(command)
    return None


def make_deny_hook(
    recorder: list[dict[str, Any]] | None = None,
) -> Callable[..., Any]:
    """The `PreToolUse` hook. Returns `{}` to stay out of the way when allowing."""

    async def deny_dangerous(
        input_data: dict[str, Any], tool_use_id: str | None, context: Any
    ) -> dict[str, Any]:
        denial = check_tool(input_data.get("tool_name", ""), input_data.get("tool_input"))
        if denial is None:
            return {}
        if recorder is not None:
            recorder.append(
                {
                    "tool_name": input_data.get("tool_name"),
                    "tool_use_id": tool_use_id or input_data.get("tool_use_id"),
                    "rule": denial.rule,
                    "reason": denial.reason,
                }
            )
        return denial.as_hook_output()

    return deny_dangerous


# --------------------------------------------------------------------------- #
# Stop gate: a regression test must be in the diff
# --------------------------------------------------------------------------- #

_ADDED_TEST = re.compile(
    r"(?:^|\s)(?:async\s+)?def\s+test\w*\s*\("
    r"|(?:public|protected|private)?\s*function\s+test\w*\s*\("
    r"|func\s+Test\w*\s*\("
    r"|\b(?:it|test)\s*\(\s*['\"`]"
    r"|@Test\b|#\[Test\]",
    re.IGNORECASE,
)


def has_regression_test(diff_text: str | None) -> tuple[bool | None, str]:
    """`(True, why)` / `(False, why)` / `(None, why)` when the diff is unreadable."""
    if diff_text is None:
        return None, "no diff was available to inspect"
    try:
        files = parse_unified_diff(diff_text)
    except DiffParseError as exc:
        return None, f"unparseable diff: {exc}"

    for fd in files:
        if not (is_test_path(fd.new_path) or is_test_path(fd.old_path)):
            continue
        if fd.is_new and fd.added:
            return True, f"new test file {fd.path}"
        for line in fd.added:
            if _ADDED_TEST.search(line.text):
                return True, f"new test case at {fd.path}:{line.line_no}"
    return False, "no added test case in the diff"


@dataclass(slots=True)
class RegressionTestGate:
    """Mutable record of what the Stop hook decided, read after the run."""

    max_blocks: int = 2
    blocks: int = 0
    satisfied: bool | None = None
    detail: str = "the fixer never reached a Stop event"
    history: list[str] = field(default_factory=list)

    def evaluate(self, diff_text: str | None) -> bool | None:
        self.satisfied, self.detail = has_regression_test(diff_text)
        self.history.append(self.detail)
        return self.satisfied


def make_regression_test_hook(
    gate: RegressionTestGate, diff_fn: Callable[[], str | None]
) -> Callable[..., Any]:
    """The `Stop` hook. Blocks until a regression test appears, at most
    `gate.max_blocks` times - see the module docstring on why it stops asking."""

    async def require_regression_test(
        input_data: dict[str, Any], tool_use_id: str | None, context: Any
    ) -> dict[str, Any]:
        satisfied = gate.evaluate(diff_fn())
        if satisfied is True:
            return {}
        if gate.blocks >= gate.max_blocks:
            # Recorded, not forgiven: `regression_test_validator` fails from here.
            return {}
        gate.blocks += 1
        return {
            "decision": "block",
            "reason": (
                "This patch has no regression test. Add a test that fails on the "
                "unpatched code and passes on yours, in the project's existing test "
                f"suite, then finish. ({gate.detail})"
            ),
        }

    return require_regression_test


def regression_test_validator(gate: RegressionTestGate) -> ValidatorResult:
    """The gate as a bundle row. `None` is `unavailable`, never a pass."""
    if gate.satisfied is True:
        return ValidatorResult(
            "regression_test", "pass", gate.detail, {"stop_blocks": gate.blocks}
        )
    if gate.satisfied is False:
        return ValidatorResult(
            "regression_test",
            "fail",
            f"{gate.detail}; the Stop gate asked {gate.blocks} time(s)",
            {"stop_blocks": gate.blocks, "history": list(gate.history)},
        )
    return ValidatorResult(
        "regression_test", "unavailable", gate.detail, {"stop_blocks": gate.blocks}
    )


def denials_summary(denials: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for d in denials:
        rule = str(d.get("rule", "unknown"))
        counts[rule] = counts.get(rule, 0) + 1
    return counts
