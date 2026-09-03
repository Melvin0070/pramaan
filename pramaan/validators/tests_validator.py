"""`tests_green`: tri-state PASS / FAIL / NO_SUITE, with counts from both trees (D5).

Two independent questions, deliberately answered by two different signals.

**Did the suite pass?** The runner's exit code. Not a parsed count — every test
framework in this project reports a summary line, and every one of them formats
it differently across versions, so a parser is the wrong thing to bet a security
gate on.

**Did the same tests run?** The parsed counts, from *both* trees. This is the
only question that catches the cheating patch, and it is the reason
`TestsValidation` carries four numbers rather than a boolean. A patch that
deletes the failing test leaves a green suite behind it;
`TestsValidation.fewer_tests_ran` is what notices, and it can only notice if
this module populates the counts truthfully. So: when the counts cannot be
parsed, this returns `NO_SUITE` rather than guessing. An unparsed count reported
as zero fabricates a cheating signal; reported as the base count hides one.

`NO_SUITE` fails closed — the frozen schema grades it `unavailable`. "No test
suite" is not evidence that a fix works. It is the absence of evidence, and the
whole project exists because those two get conflated.

**Running a suite executes code the fixer just wrote**, and for `npm test` and
`vendor/bin/phpunit` the tree itself supplies the command. That is why the
validators run inside the same egress-free sandbox as the fixer, and why
`diff_scope` refuses a patch that touches `package.json` or `composer.json`:
those are exactly the files that would let a patch choose what "the tests" means.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from pramaan.schemas import TestsValidation
from pramaan.validators.process import (
    CommandResult,
    CommandRunner,
    run_command,
    which,
)

__all__ = [
    "TESTS_TIMEOUT_S",
    "SuiteCounts",
    "SuiteSpec",
    "detect_suite",
    "parse_go_counts",
    "parse_jest_counts",
    "parse_phpunit_counts",
    "parse_pytest_counts",
    "run_suite",
    "validate_tests",
]

TESTS_TIMEOUT_S = 1800.0


@dataclass(frozen=True, slots=True)
class SuiteCounts:
    """What one suite run actually executed.

    `executed` excludes skipped and deselected tests on purpose: a test that was
    skipped did not run, and "add `@pytest.mark.skip`" is a cheating patch that
    would be invisible if skips counted as executions.
    """

    executed: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    parsed: bool = False
    detail: str = ""


@dataclass(frozen=True, slots=True)
class SuiteSpec:
    """A resolved test command for one tree."""

    name: str
    argv: tuple[str, ...]
    bin_name: str
    marker: str = ""

    @property
    def command(self) -> str:
        return " ".join(self.argv)


# --------------------------------------------------------------------------- #
# Count parsers
# --------------------------------------------------------------------------- #

_PYTEST_SUMMARY = re.compile(
    r"(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed|deselected)", re.IGNORECASE
)
_PYTEST_NO_TESTS = re.compile(r"no tests ran", re.IGNORECASE)


def parse_pytest_counts(result: CommandResult) -> SuiteCounts:
    text = result.output
    raw: dict[str, int] = {}
    for count, kind in _PYTEST_SUMMARY.findall(text):
        key = kind.lower().rstrip("s") if kind.lower().startswith("error") else kind.lower()
        raw[key] = raw.get(key, 0) + int(count)
    if not raw:
        if _PYTEST_NO_TESTS.search(text) or result.returncode == 5:
            return SuiteCounts(parsed=True, detail="pytest collected no tests")
        return SuiteCounts(parsed=False, detail="no pytest summary line in output")

    passed = raw.get("passed", 0) + raw.get("xfailed", 0) + raw.get("xpassed", 0)
    failed = raw.get("failed", 0) + raw.get("error", 0)
    skipped = raw.get("skipped", 0) + raw.get("deselected", 0)
    return SuiteCounts(
        executed=passed + failed,
        passed=passed,
        failed=failed,
        skipped=skipped,
        parsed=True,
    )


_PHPUNIT_OK = re.compile(r"^OK\s*\((\d+)\s+tests?", re.MULTILINE)
_PHPUNIT_NO_TESTS = re.compile(r"No tests executed", re.IGNORECASE)
_PHPUNIT_FIELD = re.compile(
    r"\b(Tests|Assertions|Failures|Errors|Skipped|Incomplete|Risky|Warnings?):\s*(\d+)"
)


def parse_phpunit_counts(result: CommandResult) -> SuiteCounts:
    text = result.output
    ok = _PHPUNIT_OK.search(text)
    if ok:
        total = int(ok.group(1))
        return SuiteCounts(executed=total, passed=total, parsed=True)
    if _PHPUNIT_NO_TESTS.search(text):
        return SuiteCounts(parsed=True, detail="phpunit executed no tests")

    fields = {k.lower(): int(v) for k, v in _PHPUNIT_FIELD.findall(text)}
    if "tests" not in fields:
        return SuiteCounts(parsed=False, detail="no phpunit summary line in output")
    total = fields["tests"]
    skipped = fields.get("skipped", 0) + fields.get("incomplete", 0)
    failed = fields.get("failures", 0) + fields.get("errors", 0)
    executed = max(total - skipped, 0)
    return SuiteCounts(
        executed=executed,
        passed=max(executed - failed, 0),
        failed=failed,
        skipped=skipped,
        parsed=True,
    )


_GO_LINE = re.compile(r"^\s*--- (PASS|FAIL|SKIP):", re.MULTILINE)
_GO_NO_TESTS = re.compile(r"no test files", re.IGNORECASE)


def parse_go_counts(result: CommandResult) -> SuiteCounts:
    outcomes = _GO_LINE.findall(result.output)
    if not outcomes:
        if _GO_NO_TESTS.search(result.output):
            return SuiteCounts(parsed=True, detail="go: no test files")
        return SuiteCounts(parsed=False, detail="no `--- PASS/FAIL/SKIP` lines in output")
    passed = outcomes.count("PASS")
    failed = outcomes.count("FAIL")
    skipped = outcomes.count("SKIP")
    return SuiteCounts(
        executed=passed + failed, passed=passed, failed=failed, skipped=skipped, parsed=True
    )


_JEST_LINE = re.compile(r"^Tests:\s*(.+)$", re.MULTILINE)
_JEST_FIELD = re.compile(r"(\d+)\s+(passed|failed|skipped|todo|total)", re.IGNORECASE)


def parse_jest_counts(result: CommandResult) -> SuiteCounts:
    line = _JEST_LINE.search(result.output)
    if not line:
        return SuiteCounts(parsed=False, detail="no jest `Tests:` summary line in output")
    fields = {k.lower(): int(v) for v, k in _JEST_FIELD.findall(line.group(1))}
    total = fields.get("total", 0)
    skipped = fields.get("skipped", 0) + fields.get("todo", 0)
    failed = fields.get("failed", 0)
    passed = fields.get("passed", 0)
    executed = max(total - skipped, passed + failed)
    return SuiteCounts(
        executed=executed, passed=passed, failed=failed, skipped=skipped, parsed=True
    )


_PARSERS: dict[str, Callable[[CommandResult], SuiteCounts]] = {
    "pytest": parse_pytest_counts,
    "phpunit": parse_phpunit_counts,
    "go": parse_go_counts,
    "jest": parse_jest_counts,
}


# --------------------------------------------------------------------------- #
# Suite detection
# --------------------------------------------------------------------------- #

def _has_npm_test_script(tree: Path) -> bool:
    pkg = tree / "package.json"
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    scripts = data.get("scripts")
    return isinstance(scripts, dict) and bool(scripts.get("test"))


def detect_suite(tree: str | Path) -> SuiteSpec | None:
    """Find the test command for `tree`, or `None` when there is no suite.

    Ordered by how specific the marker is. `pyproject.toml` alone is not taken
    as evidence of a pytest suite — plenty of PHP and JS repos carry one for
    tooling — so a `tests/` directory or a real pytest config file is required.
    """
    root = Path(tree)

    for marker in ("phpunit.xml", "phpunit.xml.dist"):
        if (root / marker).is_file():
            local = root / "vendor" / "bin" / "phpunit"
            argv = (
                (str(Path("vendor") / "bin" / "phpunit"), "--no-coverage")
                if local.is_file()
                else ("phpunit", "--no-coverage")
            )
            return SuiteSpec("phpunit", argv, argv[0], marker)

    pytest_markers = [m for m in ("pytest.ini", "tox.ini", "setup.cfg", "conftest.py")
                      if (root / m).is_file()]
    if pytest_markers or (root / "tests").is_dir() or (root / "test").is_dir():
        # `python3` rather than `python`: the latter is absent on a plain Linux
        # image, and "the interpreter is not installed" would then be reported
        # as NO_SUITE on a target that has a perfectly good suite.
        return SuiteSpec(
            "pytest",
            ("python3", "-m", "pytest", "-q", "--no-header"),
            "python3",
            pytest_markers[0] if pytest_markers else "tests/",
        )

    if (root / "go.mod").is_file():
        return SuiteSpec("go", ("go", "test", "./...", "-v", "-count=1"), "go", "go.mod")

    if (root / "package.json").is_file() and _has_npm_test_script(root):
        return SuiteSpec("jest", ("npm", "test", "--silent"), "npm", "package.json")

    return None


def run_suite(
    tree: str | Path,
    spec: SuiteSpec,
    *,
    runner: CommandRunner = run_command,
    timeout_s: float = TESTS_TIMEOUT_S,
) -> tuple[CommandResult, SuiteCounts]:
    result = runner(spec.argv, cwd=tree, timeout_s=timeout_s)
    if not result.usable:
        return result, SuiteCounts(parsed=False, detail=result.summary())
    parser = _PARSERS.get(spec.name)
    if parser is None:
        return result, SuiteCounts(parsed=False, detail=f"no parser for {spec.name}")
    return result, parser(result)


# --------------------------------------------------------------------------- #
# The validator
# --------------------------------------------------------------------------- #

def _no_suite(detail: str, *, base: SuiteCounts | None = None) -> TestsValidation:
    return TestsValidation(
        result="NO_SUITE",
        base_executed=base.executed if base else 0,
        base_passed=base.passed if base else 0,
        detail=detail,
    )


def validate_tests(
    *,
    base_tree: str | Path,
    patched_tree: str | Path,
    suite: SuiteSpec | None = None,
    runner: CommandRunner = run_command,
    timeout_s: float = TESTS_TIMEOUT_S,
    which_fn: Callable[[str], str | None] = which,
) -> TestsValidation:
    """Run the suite on both trees and report the tri-state with all four counts.

    Args:
        base_tree: the unpatched checkout. Not optional: without it there is no
            count to compare against and `fewer_tests_ran` can never fire.
        patched_tree: the fixer's worktree.
        suite: pin the command explicitly. Juice Shop needs this — its Cypress
            challenge tests assert *exploitability*, so "the suite" for proof
            purposes is the unit suite, not everything `npm test` would run.
    """
    base_root, patched_root = Path(base_tree), Path(patched_tree)

    base_spec = suite or detect_suite(base_root)
    patched_spec = suite or detect_suite(patched_root)

    if base_spec is None and patched_spec is None:
        return _no_suite("target has no test suite in either tree")

    if base_spec is None:
        # A suite that exists only after the patch cannot be compared, so it
        # cannot support a fix claim either.
        return _no_suite(
            f"base tree has no test suite; patched tree has {patched_spec.name} "
            "- no baseline to compare against"
        )

    if which_fn(base_spec.bin_name) is None:
        return _no_suite(
            f"test runner {base_spec.bin_name!r} is not installed; the suite exists "
            f"({base_spec.marker}) but did not run"
        )

    base_result, base_counts = run_suite(
        base_root, base_spec, runner=runner, timeout_s=timeout_s
    )
    if not base_result.usable:
        return _no_suite(f"base-tree suite did not complete: {base_result.summary()}")
    if not base_counts.parsed:
        return _no_suite(
            f"could not parse base-tree test counts ({base_counts.detail}); "
            "D5 needs truthful counts and will not guess them"
        )
    if base_counts.executed == 0:
        # A suite that collects nothing is green for free.
        return _no_suite(
            f"base tree executed 0 tests ({base_counts.detail or base_spec.command}); "
            "a green run over zero tests is not evidence",
            base=base_counts,
        )

    if patched_spec is None:
        # The patch removed the suite. Reported as FAIL with a zeroed patched
        # count rather than NO_SUITE, so `fewer_tests_ran` fires and the
        # cheating-patch flag - not merely "unavailable" - is what blocks.
        return TestsValidation(
            result="FAIL",
            base_executed=base_counts.executed,
            base_passed=base_counts.passed,
            patched_executed=0,
            patched_passed=0,
            detail=(
                f"patched tree has no test suite; base tree had {base_spec.name} "
                f"({base_spec.marker}). The patch removed the suite."
            ),
        )

    patched_result, patched_counts = run_suite(
        patched_root, patched_spec, runner=runner, timeout_s=timeout_s
    )
    if not patched_result.usable:
        return _no_suite(
            f"patched-tree suite did not complete: {patched_result.summary()}",
            base=base_counts,
        )
    if not patched_counts.parsed:
        return _no_suite(
            f"could not parse patched-tree test counts ({patched_counts.detail})",
            base=base_counts,
        )

    notes = [
        f"{patched_spec.name}: base {base_counts.passed}/{base_counts.executed} passed, "
        f"patched {patched_counts.passed}/{patched_counts.executed} passed"
    ]
    if not base_result.ok:
        notes.append("base tree was already red")
    if patched_counts.skipped > base_counts.skipped:
        notes.append(
            f"skips rose from {base_counts.skipped} to {patched_counts.skipped}"
        )

    return TestsValidation(
        result="PASS" if patched_result.ok else "FAIL",
        base_executed=base_counts.executed,
        base_passed=base_counts.passed,
        patched_executed=patched_counts.executed,
        patched_passed=patched_counts.passed,
        detail="; ".join(notes),
    )
