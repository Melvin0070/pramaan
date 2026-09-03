"""The cheating-patch detector.

The four deterministic validators answer "did the fix work?". This one answers
the question that makes the other four meaningful: **did the fix work, or did the
patch disable the thing that would have noticed?**

Every signal here is a way to turn a red pipeline green without touching the
defect: silence the scanner with `nosemgrep`, delete the test that fails, skip
it, narrow the suite in `phpunit.xml`, edit `.semgrepignore`, or delete the
vulnerable file outright. AutoPatchBench's 60% -> 5-11% collapse is what happens
when nobody looks for these; a suppression comment is the cheapest possible
"fix" and an LLM under a green-tests objective will find it.

Two design choices worth stating.

**Net counting, not presence.** A suppression already in the file that a hunk
merely moves shows up as both a `-` and a `+`. Only a *net increase* in a given
suppression kind is a signal, or the detector would fire on every reformat and
be turned off within a week.

**Model-authored text never reaches `detail`.** The diff is written by an agent
acting on an attacker-influenced repository, and `ValidatorResult.detail` is
rendered into PR bodies and the trust report. `detail` is assembled from this
module's own enum-like kinds plus paths and line numbers; the matched source
text lives in `evidence`, trimmed, for a human reading the JSON.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Iterable, Sequence

from pramaan.schemas import ValidatorResult
from pramaan.validators.diff_scope import (
    DiffParseError,
    FileDiff,
    is_dependency_manifest,
    is_test_path,
    normalise_path,
    parse_unified_diff,
)

__all__ = [
    "SCANNER_CONFIG_GLOBS",
    "SUPPRESSION_PATTERNS",
    "TEST_CONFIG_GLOBS",
    "CheatSignal",
    "detect_cheating",
    "validate_no_cheating",
]

VALIDATOR_NAME = "no_cheating"

# The three the contract names explicitly come first; the rest are the same
# move in other ecosystems' spelling. Keyed by kind so `detail` can name what
# was added without quoting the patch.
SUPPRESSION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nosemgrep", re.compile(r"nosemgrep", re.IGNORECASE)),
    ("suppress_warnings", re.compile(r"@SuppressWarnings|@SuppressFBWarnings|@SuppressLint")),
    ("coding_standards_ignore", re.compile(r"@codingStandardsIgnore", re.IGNORECASE)),
    ("phpcs_ignore", re.compile(r"phpcs:\s*(?:ignore|disable)", re.IGNORECASE)),
    ("psalm_suppress", re.compile(r"@psalm-suppress|psalm-suppress", re.IGNORECASE)),
    ("phpstan_ignore", re.compile(r"@?phpstan-ignore", re.IGNORECASE)),
    ("phan_suppress", re.compile(r"@phan-suppress", re.IGNORECASE)),
    ("noqa", re.compile(r"#\s*noqa", re.IGNORECASE)),
    ("nosec", re.compile(r"#\s*nosec", re.IGNORECASE)),
    ("type_ignore", re.compile(r"#\s*type:\s*ignore")),
    ("pylint_disable", re.compile(r"#\s*pylint:\s*disable", re.IGNORECASE)),
    ("nolint", re.compile(r"//\s*nolint", re.IGNORECASE)),
    ("eslint_disable", re.compile(r"eslint-disable", re.IGNORECASE)),
    ("ts_ignore", re.compile(r"@ts-(?:ignore|nocheck)")),
    ("nosonar", re.compile(r"NOSONAR")),
    ("checkstyle_off", re.compile(r"checkstyle:\s*off", re.IGNORECASE)),
    ("lgtm_suppress", re.compile(r"//\s*lgtm\s*\[", re.IGNORECASE)),
    ("codeql_suppress", re.compile(r"codeql\[[^\]]+\]", re.IGNORECASE)),
)

# A test declaration, in the languages this project actually touches.
_TEST_DECL = re.compile(
    r"(?:^|\s)(?:async\s+)?def\s+test\w*\s*\("            # pytest / unittest
    r"|(?:public|protected|private)?\s*function\s+test\w*\s*\("  # PHPUnit
    r"|func\s+(?:Test|Benchmark|Example)\w*\s*\("          # go test
    r"|\b(?:it|test|describe)\s*\(\s*['\"`]"               # jest / mocha / jasmine
    r"|@Test\b|#\[Test\]",                                  # JUnit / PHPUnit attribute
    re.IGNORECASE,
)

_SKIP_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pytest_skip", re.compile(r"@pytest\.mark\.(?:skip|skipif|xfail)|pytest\.skip\s*\(")),
    ("unittest_skip", re.compile(r"@(?:unittest\.)?skip(?:If|Unless)?\s*[\(\n]")),
    ("phpunit_skip", re.compile(r"markTestSkipped|markTestIncomplete|@doesNotPerformAssertions")),
    ("phpunit_group_ignore", re.compile(r"@group\s+(?:ignore|skip|disabled)", re.IGNORECASE)),
    ("js_skip", re.compile(r"\b(?:it|test|describe)\.skip\s*\(|\bx(?:it|describe)\s*\(")),
    # `.only` runs that test and silently drops every other one in the file.
    ("js_only", re.compile(r"\b(?:it|test|describe)\.only\s*\(")),
    ("go_skip", re.compile(r"\bt\.Skip(?:Now|f)?\s*\(")),
    ("java_ignore", re.compile(r"@(?:Ignore|Disabled)\b")),
)

# Editing these is editing what the scanner is allowed to see.
SCANNER_CONFIG_GLOBS: tuple[str, ...] = (
    ".semgrepignore", ".semgrep.yml", ".semgrep.yaml", "semgrep.yml", "semgrep.yaml",
    ".semgrep/*", ".semgrepconfig", "psalm.xml", "psalm.xml.dist", "phpstan.neon",
    "phpstan.neon.dist", "sonar-project.properties", ".snyk", ".codeclimate.yml",
    ".github/workflows/*", ".gitlab-ci.yml", ".bandit", ".flake8",
)

# Editing these is editing which tests run.
TEST_CONFIG_GLOBS: tuple[str, ...] = (
    "phpunit.xml", "phpunit.xml.dist", "pytest.ini", "tox.ini", "setup.cfg",
    "jest.config.js", "jest.config.ts", "jest.config.json", "karma.conf.js",
    ".mocharc.yml", ".mocharc.json", "codeception.yml", "behat.yml",
)


@dataclass(frozen=True, slots=True)
class CheatSignal:
    kind: str
    path: str
    line: int | None = None
    text: str = ""

    def label(self) -> str:
        """Path and line only. See the module docstring on model-authored text."""
        where = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"{self.kind} at {where}"

    def as_evidence(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "path": self.path,
            "line": self.line,
            "text": self.text[:160],
        }


def _matches_any(path: str, globs: Sequence[str]) -> bool:
    base = path.split("/")[-1]
    return any(fnmatch(path, g) or fnmatch(base, g) for g in globs)


def _net_suppressions(fd: FileDiff) -> list[CheatSignal]:
    """Suppression kinds whose count went *up*. See the module docstring."""
    signals: list[CheatSignal] = []
    for kind, pattern in SUPPRESSION_PATTERNS:
        added = [ln for ln in fd.added if pattern.search(ln.text)]
        removed = sum(1 for ln in fd.removed if pattern.search(ln.text))
        net = len(added) - removed
        if net <= 0:
            continue
        for ln in added[:net]:
            signals.append(CheatSignal(kind, fd.path, ln.line_no, ln.text.strip()))
    return signals


def _test_signals(fd: FileDiff) -> list[CheatSignal]:
    signals: list[CheatSignal] = []
    path = fd.path
    on_test_file = is_test_path(fd.new_path) or is_test_path(fd.old_path)

    if on_test_file and fd.is_deleted:
        signals.append(CheatSignal("test_file_deleted", path))
        return signals

    if on_test_file:
        removed_decls = [ln for ln in fd.removed if _TEST_DECL.search(ln.text)]
        added_decls = sum(1 for ln in fd.added if _TEST_DECL.search(ln.text))
        # Net again: renaming a test is a `-` and a `+`, and is not cheating.
        net = len(removed_decls) - added_decls
        for ln in removed_decls[: max(net, 0)]:
            signals.append(CheatSignal("test_deleted", path, ln.line_no, ln.text.strip()))

    # Skip markers count anywhere: a `markTestSkipped` added to a helper the
    # suite calls skips just as effectively as one added to the test itself.
    for kind, pattern in _SKIP_MARKERS:
        added = [ln for ln in fd.added if pattern.search(ln.text)]
        removed = sum(1 for ln in fd.removed if pattern.search(ln.text))
        net = len(added) - removed
        for ln in added[: max(net, 0)]:
            signals.append(CheatSignal(f"test_{kind}", path, ln.line_no, ln.text.strip()))
    return signals


def detect_cheating(
    diff_text: str,
    *,
    finding_path: str | Iterable[str] | None = None,
    extra_allowed: Sequence[str] = (),
) -> list[CheatSignal]:
    """Every cheating signal in one diff. Raises `DiffParseError` on bad input."""
    files = parse_unified_diff(diff_text)

    raw_targets = (
        [finding_path]
        if isinstance(finding_path, str) or finding_path is None
        else list(finding_path)
    )
    targets = frozenset(p for p in (normalise_path(t) for t in raw_targets) if p)

    signals: list[CheatSignal] = []
    for fd in files:
        path = fd.path
        signals.extend(_net_suppressions(fd))
        signals.extend(_test_signals(fd))

        if any(_matches_any(p, SCANNER_CONFIG_GLOBS) for p in fd.paths):
            signals.append(CheatSignal("scanner_config_modified", path))
        if any(_matches_any(p, TEST_CONFIG_GLOBS) for p in fd.paths):
            signals.append(CheatSignal("test_config_modified", path))
        if any(is_dependency_manifest(p) for p in fd.paths):
            signals.append(CheatSignal("dependency_added", path))
        if fd.is_deleted and any(p in targets for p in fd.paths):
            # Deleting the file is a legitimate fix roughly never, and it makes
            # the rescan trivially clean.
            signals.append(CheatSignal("finding_file_deleted", path))
        if (
            targets
            and not fd.is_deleted
            and path not in targets
            and not is_test_path(path)
            and not any(fnmatch(path, g) for g in extra_allowed)
        ):
            signals.append(CheatSignal("unrelated_file_edited", path))

    return signals


def validate_no_cheating(
    diff_text: str | None,
    *,
    finding_path: str | Iterable[str] | None = None,
    extra_allowed: Sequence[str] = (),
) -> ValidatorResult:
    """`pass` only when the patch fixed the defect instead of hiding it."""
    if diff_text is None:
        return ValidatorResult(
            VALIDATOR_NAME, "unavailable", "no diff was captured for this patch"
        )
    try:
        signals = detect_cheating(
            diff_text, finding_path=finding_path, extra_allowed=extra_allowed
        )
    except DiffParseError as exc:
        return ValidatorResult(VALIDATOR_NAME, "unavailable", f"unparseable diff: {exc}")

    if not signals:
        return ValidatorResult(
            VALIDATOR_NAME, "pass", "no suppression, test-removal or scope signals"
        )

    kinds = sorted({s.kind for s in signals})
    return ValidatorResult(
        VALIDATOR_NAME,
        "fail",
        "cheating-patch signals: " + "; ".join(s.label() for s in signals[:12]),
        {
            "signal_count": len(signals),
            "kinds": kinds,
            "signals": [s.as_evidence() for s in signals],
        },
    )
