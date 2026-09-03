"""`diff_in_scope`: the patch may touch the defect and its regression test. Nothing else.

This validator and `cheating.py` both read the same unified diff, so the parser
lives here and `cheating` imports it.

The rule is deliberately narrow. A one-line XSS fix that also edits eleven other
files, bumps a dependency and rewrites a CI workflow is not a fix with some
housekeeping attached — it is a change nobody reviewed, arriving under the
authority of a proof bundle. Widening scope has to be an explicit, per-run
decision by a human (`extra_allowed`), never something a patch grants itself.

Dependency manifests are out of scope even when the edit looks innocuous.
"Add a package that sanitises this" is the single easiest way for an agent to
turn a code review into a supply-chain decision, and a supply-chain decision is
not something four deterministic validators can prove.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Iterable, Sequence

from pramaan.schemas import ValidatorResult

__all__ = [
    "DEPENDENCY_MANIFESTS",
    "MAX_CHANGED_LINES",
    "MAX_FILES",
    "TEST_PATH_GLOBS",
    "VENDOR_DIRS",
    "DiffLine",
    "DiffParseError",
    "FileDiff",
    "ScopeReport",
    "is_dependency_manifest",
    "is_test_path",
    "is_vendored",
    "normalise_path",
    "parse_unified_diff",
    "validate_diff_scope",
]

VALIDATOR_NAME = "diff_in_scope"

# A fix for one finding, plus its regression test, plus a comment. Anything past
# this is a refactor wearing a security patch's clothes.
MAX_CHANGED_LINES = 400
MAX_FILES = 10

DEPENDENCY_MANIFESTS: frozenset[str] = frozenset(
    {
        "composer.json", "composer.lock",
        "package.json", "package-lock.json", "npm-shrinkwrap.json",
        "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
        "requirements.txt", "requirements-dev.txt", "constraints.txt",
        "pipfile", "pipfile.lock", "poetry.lock", "pdm.lock", "uv.lock",
        "pyproject.toml", "setup.py", "setup.cfg",
        "go.mod", "go.sum",
        "gemfile", "gemfile.lock",
        "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
        "cargo.toml", "cargo.lock",
    }
)

VENDOR_DIRS: frozenset[str] = frozenset(
    {"vendor", "vendors", "node_modules", "third_party", "thirdparty", "bower_components"}
)

_TEST_DIR_SEGMENTS: frozenset[str] = frozenset(
    {"test", "tests", "spec", "specs", "__tests__", "testing"}
)

TEST_PATH_GLOBS: tuple[str, ...] = (
    "test_*.py", "*_test.py", "conftest.py",
    "*Test.php", "Test*.php", "*TestCase.php", "*Spec.php",
    "*_test.go",
    "*.test.js", "*.test.jsx", "*.test.ts", "*.test.tsx",
    "*.spec.js", "*.spec.jsx", "*.spec.ts", "*.spec.tsx",
    "*Test.java", "*Tests.java", "*_spec.rb", "*_test.rb",
)

_DIFF_GIT_RE = re.compile(r"^diff --git (?:\"?a/)(.+?)(?:\"?) (?:\"?b/)(.+?)\"?$")
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffParseError(ValueError):
    """The diff could not be parsed.

    Callers turn this into `unavailable`, never into a pass: a patch whose diff
    we cannot read is a patch whose scope we cannot check.
    """


@dataclass(frozen=True, slots=True)
class DiffLine:
    line_no: int
    text: str


@dataclass(frozen=True, slots=True)
class FileDiff:
    old_path: str | None
    new_path: str | None
    added: tuple[DiffLine, ...] = ()
    removed: tuple[DiffLine, ...] = ()
    is_new: bool = False
    is_deleted: bool = False
    is_rename: bool = False
    is_binary: bool = False
    mode_change: str | None = None

    @property
    def path(self) -> str:
        """The path as it exists after the patch, or before it for a deletion."""
        return self.new_path or self.old_path or ""

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(p for p in (self.old_path, self.new_path) if p)

    @property
    def changed_lines(self) -> int:
        return len(self.added) + len(self.removed)


@dataclass(slots=True)
class _Builder:
    old_path: str | None = None
    new_path: str | None = None
    added: list[DiffLine] = field(default_factory=list)
    removed: list[DiffLine] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False
    is_rename: bool = False
    is_binary: bool = False
    mode_change: str | None = None

    def build(self) -> FileDiff:
        return FileDiff(
            old_path=self.old_path,
            new_path=self.new_path,
            added=tuple(self.added),
            removed=tuple(self.removed),
            is_new=self.is_new,
            is_deleted=self.is_deleted,
            is_rename=self.is_rename,
            is_binary=self.is_binary,
            mode_change=self.mode_change,
        )


def normalise_path(path: str | None) -> str | None:
    """`a/includes/x.php`, `./includes/x.php`, `includes\\x.php` -> `includes/x.php`.

    `/dev/null` becomes None, which is how a creation or deletion is spelled.
    """
    if path is None:
        return None
    p = path.strip().strip('"')
    if p in ("/dev/null", "dev/null", ""):
        return None
    p = p.replace("\\", "/")
    for prefix in ("a/", "b/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix) :]
            break
    return p.lstrip("/") or None


def parse_unified_diff(text: str) -> list[FileDiff]:
    """Parse `git diff` output into per-file records.

    Hand-rolled because the stdlib has a differ but no parser, and because the
    fields that matter here — new/deleted/rename/binary/mode — live in git's
    extended headers rather than in the unified-diff body.
    """
    if text is None:
        raise DiffParseError("diff text is None")
    files: list[FileDiff] = []
    current: _Builder | None = None
    old_line = new_line = 0
    in_hunk = False

    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            if current is not None:
                files.append(current.build())
            current = _Builder()
            in_hunk = False
            match = _DIFF_GIT_RE.match(raw)
            if match:
                current.old_path = normalise_path(match.group(1))
                current.new_path = normalise_path(match.group(2))
            continue

        if current is None:
            # Preamble (commit headers from `git show`, or a bare `--- / +++`
            # patch with no `diff --git`). Start a file on the `---` marker so
            # plain `diff -u` output still parses.
            if raw.startswith("--- "):
                current = _Builder()
                current.old_path = normalise_path(raw[4:].split("\t", 1)[0])
                in_hunk = False
            continue

        if raw.startswith("new file mode"):
            current.is_new = True
        elif raw.startswith("deleted file mode"):
            current.is_deleted = True
        elif raw.startswith(("old mode ", "new mode ")):
            current.mode_change = raw.strip()
        elif raw.startswith("rename from "):
            current.is_rename = True
            current.old_path = normalise_path(raw[len("rename from ") :])
        elif raw.startswith("rename to "):
            current.is_rename = True
            current.new_path = normalise_path(raw[len("rename to ") :])
        elif raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            current.is_binary = True
        elif raw.startswith("--- "):
            current.old_path = normalise_path(raw[4:].split("\t", 1)[0])
            if current.old_path is None:
                current.is_new = True
        elif raw.startswith("+++ "):
            current.new_path = normalise_path(raw[4:].split("\t", 1)[0])
            if current.new_path is None:
                current.is_deleted = True
        elif raw.startswith("@@"):
            match = _HUNK_RE.match(raw)
            if not match:
                raise DiffParseError(f"malformed hunk header: {raw[:80]!r}")
            old_line = int(match.group(1))
            new_line = int(match.group(3))
            in_hunk = True
        elif in_hunk:
            if raw.startswith("+"):
                current.added.append(DiffLine(new_line, raw[1:]))
                new_line += 1
            elif raw.startswith("-"):
                current.removed.append(DiffLine(old_line, raw[1:]))
                old_line += 1
            elif raw.startswith("\\"):
                pass  # "\ No newline at end of file"
            elif raw.startswith(" ") or raw == "":
                old_line += 1
                new_line += 1
            else:
                in_hunk = False

    if current is not None:
        files.append(current.build())
    return files


def is_test_path(path: str | None) -> bool:
    if not path:
        return False
    parts = path.split("/")
    if any(seg.lower() in _TEST_DIR_SEGMENTS for seg in parts[:-1]):
        return True
    base = parts[-1]
    return any(fnmatch(base, glob) for glob in TEST_PATH_GLOBS)


def is_dependency_manifest(path: str | None) -> bool:
    if not path:
        return False
    return path.split("/")[-1].lower() in DEPENDENCY_MANIFESTS


def is_vendored(path: str | None) -> bool:
    if not path:
        return False
    return any(seg.lower() in VENDOR_DIRS for seg in path.split("/")[:-1])


@dataclass(frozen=True, slots=True)
class ScopeReport:
    files: tuple[FileDiff, ...]
    in_scope: tuple[str, ...] = ()
    unrelated: tuple[str, ...] = ()
    dependency_edits: tuple[str, ...] = ()
    vendored: tuple[str, ...] = ()
    binary: tuple[str, ...] = ()
    mode_changes: tuple[str, ...] = ()
    changed_lines: int = 0
    violations: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.violations

    def as_evidence(self) -> dict[str, object]:
        return {
            "files_changed": len(self.files),
            "changed_lines": self.changed_lines,
            "in_scope": list(self.in_scope),
            "unrelated": list(self.unrelated),
            "dependency_edits": list(self.dependency_edits),
            "vendored": list(self.vendored),
            "binary": list(self.binary),
            "mode_changes": list(self.mode_changes),
            "violations": list(self.violations),
        }


def _allowed(path: str, finding_paths: frozenset[str], extra_allowed: Sequence[str]) -> bool:
    if path in finding_paths:
        return True
    if is_test_path(path):
        return True
    return any(fnmatch(path, glob) for glob in extra_allowed)


def analyse_scope(
    diff_text: str,
    *,
    finding_path: str | Iterable[str] | None,
    extra_allowed: Sequence[str] = (),
    max_changed_lines: int = MAX_CHANGED_LINES,
    max_files: int = MAX_FILES,
) -> ScopeReport:
    """Classify every file in the diff. Raises `DiffParseError` on unreadable input."""
    files = tuple(parse_unified_diff(diff_text))

    raw_targets = (
        [finding_path]
        if isinstance(finding_path, str) or finding_path is None
        else list(finding_path)
    )
    targets = frozenset(p for p in (normalise_path(t) for t in raw_targets) if p)

    in_scope: list[str] = []
    unrelated: list[str] = []
    dependency_edits: list[str] = []
    vendored: list[str] = []
    binary: list[str] = []
    mode_changes: list[str] = []
    changed_lines = 0

    for fd in files:
        path = fd.path
        changed_lines += fd.changed_lines
        if fd.is_binary:
            binary.append(path)
        if fd.mode_change:
            mode_changes.append(f"{path}: {fd.mode_change}")
        if any(is_dependency_manifest(p) for p in fd.paths):
            dependency_edits.append(path)
        elif any(is_vendored(p) for p in fd.paths):
            vendored.append(path)
        elif all(_allowed(p, targets, extra_allowed) for p in fd.paths) and fd.paths:
            in_scope.append(path)
        else:
            unrelated.append(path)

    violations: list[str] = []
    if not files:
        # An empty diff is the quietest possible false pass: every other check
        # trivially holds on a patch that changed nothing.
        violations.append("empty diff: the fixer changed nothing")
    if unrelated:
        violations.append(f"unrelated files: {', '.join(sorted(unrelated))}")
    if dependency_edits:
        violations.append(
            f"dependency manifest modified: {', '.join(sorted(dependency_edits))}"
        )
    if vendored:
        violations.append(f"vendored code modified: {', '.join(sorted(vendored))}")
    if binary:
        violations.append(f"binary file in diff: {', '.join(sorted(binary))}")
    if mode_changes:
        violations.append(f"file mode changed: {', '.join(sorted(mode_changes))}")
    if len(files) > max_files:
        violations.append(f"{len(files)} files changed, limit is {max_files}")
    if changed_lines > max_changed_lines:
        violations.append(
            f"{changed_lines} lines changed, limit is {max_changed_lines}"
        )
    if targets and not any(p in targets for fd in files for p in fd.paths):
        # The finding's own file is untouched. Whatever this patch is, it is not
        # a fix for this finding.
        violations.append(
            f"diff does not touch the finding's file ({', '.join(sorted(targets))})"
        )

    return ScopeReport(
        files=files,
        in_scope=tuple(in_scope),
        unrelated=tuple(unrelated),
        dependency_edits=tuple(dependency_edits),
        vendored=tuple(vendored),
        binary=tuple(binary),
        mode_changes=tuple(mode_changes),
        changed_lines=changed_lines,
        violations=tuple(violations),
    )


def validate_diff_scope(
    diff_text: str | None,
    *,
    finding_path: str | Iterable[str] | None,
    extra_allowed: Sequence[str] = (),
    max_changed_lines: int = MAX_CHANGED_LINES,
    max_files: int = MAX_FILES,
) -> ValidatorResult:
    """`pass` only when every changed file is the defect's file or a test file."""
    if diff_text is None:
        return ValidatorResult(
            VALIDATOR_NAME, "unavailable", "no diff was captured for this patch"
        )
    try:
        report = analyse_scope(
            diff_text,
            finding_path=finding_path,
            extra_allowed=extra_allowed,
            max_changed_lines=max_changed_lines,
            max_files=max_files,
        )
    except DiffParseError as exc:
        return ValidatorResult(VALIDATOR_NAME, "unavailable", f"unparseable diff: {exc}")

    if report.clean:
        return ValidatorResult(
            VALIDATOR_NAME,
            "pass",
            f"{len(report.files)} file(s), {report.changed_lines} line(s), all in scope",
            report.as_evidence(),
        )
    return ValidatorResult(
        VALIDATOR_NAME, "fail", "; ".join(report.violations), report.as_evidence()
    )
