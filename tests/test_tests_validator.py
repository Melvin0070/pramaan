"""Lane E — tri-state tests validation (D5) and the fewer-tests-ran flag."""

from __future__ import annotations

import json

import pytest

from pramaan.validators.process import CommandResult
from pramaan.validators.tests_validator import (
    SuiteSpec,
    detect_suite,
    parse_go_counts,
    parse_jest_counts,
    parse_phpunit_counts,
    parse_pytest_counts,
    validate_tests,
)

PYTEST_SPEC = SuiteSpec("pytest", ("python", "-m", "pytest", "-q"), "python", "tests/")
PHPUNIT_SPEC = SuiteSpec("phpunit", ("phpunit", "--no-coverage"), "phpunit", "phpunit.xml")


class StageRunner:
    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.cwds: list[str] = []

    def __call__(self, argv, *, cwd, timeout_s=600.0, env=None):
        self.cwds.append(str(cwd))
        return self.results.pop(0)


def _installed(_name: str) -> str:
    return "/usr/bin/python"


def _missing(_name: str) -> None:
    return None


def _out(stdout: str, code: int = 0) -> CommandResult:
    return CommandResult(argv=("python", "-m", "pytest"), returncode=code, stdout=stdout)


def pytest_summary(passed: int, failed: int = 0, skipped: int = 0) -> str:
    parts = [f"{passed} passed"]
    if failed:
        parts.append(f"{failed} failed")
    if skipped:
        parts.append(f"{skipped} skipped")
    return f"==== {', '.join(parts)} in 1.23s ===="


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #

def test_pytest_counts_exclude_skips_from_executed():
    counts = parse_pytest_counts(_out(pytest_summary(8, failed=2, skipped=3)))
    assert counts.parsed and counts.executed == 10
    assert counts.passed == 8 and counts.failed == 2 and counts.skipped == 3


def test_pytest_no_tests_ran_parses_to_zero():
    counts = parse_pytest_counts(_out("==== no tests ran in 0.01s ===="))
    assert counts.parsed and counts.executed == 0


def test_pytest_unparseable_output_is_not_parsed():
    assert parse_pytest_counts(_out("Traceback (most recent call last)")).parsed is False


def test_phpunit_ok_line():
    counts = parse_phpunit_counts(_out("OK (25 tests, 40 assertions)"))
    assert counts.executed == 25 and counts.passed == 25 and counts.failed == 0


def test_phpunit_failure_line_excludes_skips():
    counts = parse_phpunit_counts(
        _out("FAILURES!\nTests: 25, Assertions: 40, Failures: 2, Skipped: 3.", code=1)
    )
    assert counts.executed == 22 and counts.failed == 2 and counts.passed == 20


def test_go_counts_from_verbose_lines():
    counts = parse_go_counts(
        _out("--- PASS: TestA (0.00s)\n--- FAIL: TestB (0.00s)\n--- SKIP: TestC (0.00s)\n")
    )
    assert counts.executed == 2 and counts.passed == 1 and counts.skipped == 1


def test_jest_counts_from_summary_line():
    counts = parse_jest_counts(_out("Tests:       1 failed, 2 skipped, 5 passed, 8 total"))
    assert counts.executed == 6 and counts.passed == 5 and counts.skipped == 2


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

def test_detects_phpunit_before_pytest(tmp_path):
    (tmp_path / "phpunit.xml.dist").write_text("<phpunit/>")
    (tmp_path / "tests").mkdir()
    spec = detect_suite(tmp_path)
    assert spec is not None and spec.name == "phpunit"


def test_detects_local_vendor_phpunit(tmp_path):
    (tmp_path / "phpunit.xml").write_text("<phpunit/>")
    vendor = tmp_path / "vendor" / "bin"
    vendor.mkdir(parents=True)
    (vendor / "phpunit").write_text("#!/bin/sh\n")
    spec = detect_suite(tmp_path)
    assert spec.argv[0].endswith("phpunit")
    assert "vendor" in spec.argv[0]


def test_detects_pytest_from_a_tests_directory(tmp_path):
    (tmp_path / "tests").mkdir()
    assert detect_suite(tmp_path).name == "pytest"


def test_detects_npm_only_with_a_test_script(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    assert detect_suite(tmp_path) is None
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "scripts": {"test": "jest"}})
    )
    assert detect_suite(tmp_path).name == "jest"


def test_no_markers_means_no_suite(tmp_path):
    (tmp_path / "index.php").write_text("<?php")
    assert detect_suite(tmp_path) is None


# --------------------------------------------------------------------------- #
# The validator
# --------------------------------------------------------------------------- #

def test_green_on_both_trees_passes(tmp_path):
    runner = StageRunner(_out(pytest_summary(12)), _out(pytest_summary(13)))
    tv = validate_tests(
        base_tree=tmp_path / "base",
        patched_tree=tmp_path / "patched",
        suite=PYTEST_SPEC,
        runner=runner,
        which_fn=_installed,
    )
    assert tv.result == "PASS"
    assert (tv.base_executed, tv.patched_executed) == (12, 13)
    assert tv.fewer_tests_ran is False
    assert tv.as_validator().outcome == "pass"
    assert runner.cwds[0].endswith("base") and runner.cwds[1].endswith("patched")


def test_red_patched_tree_fails(tmp_path):
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=PYTEST_SPEC,
        runner=StageRunner(_out(pytest_summary(12)), _out(pytest_summary(11, failed=1), 1)),
        which_fn=_installed,
    )
    assert tv.result == "FAIL"
    assert tv.as_validator().outcome == "fail"


def test_no_suite_fails_closed(tmp_path):
    """NO_SUITE is graded `unavailable` and blocks the PR."""
    (tmp_path / "index.php").write_text("<?php")
    tv = validate_tests(base_tree=tmp_path, patched_tree=tmp_path, which_fn=_installed)
    assert tv.result == "NO_SUITE"
    validator = tv.as_validator()
    assert validator.outcome == "unavailable"
    assert validator.blocks_pr is True


def test_missing_runner_is_no_suite_with_a_distinguishing_detail(tmp_path):
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=PYTEST_SPEC,
        runner=StageRunner(),
        which_fn=_missing,
    )
    assert tv.result == "NO_SUITE"
    assert "not installed" in tv.detail
    # Not confused with "this target has no tests".
    assert "no test suite" not in tv.detail


def test_fewer_tests_in_the_patched_tree_is_a_cheating_patch(tmp_path):
    """A green suite that ran fewer tests is the AutoPatchBench failure mode."""
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=PYTEST_SPEC,
        runner=StageRunner(_out(pytest_summary(20)), _out(pytest_summary(17, skipped=3))),
        which_fn=_installed,
    )
    assert tv.result == "PASS"
    assert (tv.base_executed, tv.patched_executed) == (20, 17)
    assert tv.fewer_tests_ran is True
    validator = tv.as_validator()
    assert validator.outcome == "fail"
    assert "cheating-patch flag" in validator.detail
    assert "skips rose from 0 to 3" in tv.detail


def test_patch_that_deletes_the_suite_fires_the_cheating_flag(tmp_path):
    base = tmp_path / "base"
    patched = tmp_path / "patched"
    (base / "tests").mkdir(parents=True)
    patched.mkdir()
    (patched / "index.php").write_text("<?php")
    tv = validate_tests(
        base_tree=base,
        patched_tree=patched,
        runner=StageRunner(_out(pytest_summary(9))),
        which_fn=_installed,
    )
    assert tv.result == "FAIL"
    assert tv.patched_executed == 0 and tv.base_executed == 9
    assert tv.fewer_tests_ran is True
    assert tv.as_validator().outcome == "fail"


def test_base_tree_running_zero_tests_is_no_suite(tmp_path):
    """A suite that collects nothing is green for free."""
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=PYTEST_SPEC,
        runner=StageRunner(_out("==== no tests ran in 0.01s ====", 5)),
        which_fn=_installed,
    )
    assert tv.result == "NO_SUITE"
    assert "executed 0 tests" in tv.detail
    assert tv.as_validator().blocks_pr is True


def test_unparseable_counts_never_guess(tmp_path):
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=PYTEST_SPEC,
        runner=StageRunner(_out("INTERNALERROR> boom", 3)),
        which_fn=_installed,
    )
    assert tv.result == "NO_SUITE"
    assert "will not guess" in tv.detail


def test_patched_suite_timeout_is_unavailable(tmp_path):
    hung = CommandResult(argv=("python",), timed_out=True, error="timed out")
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=PYTEST_SPEC,
        runner=StageRunner(_out(pytest_summary(12)), hung),
        which_fn=_installed,
    )
    assert tv.result == "NO_SUITE"
    assert tv.base_executed == 12
    assert tv.as_validator().outcome == "unavailable"


def test_already_red_base_is_recorded(tmp_path):
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=PYTEST_SPEC,
        runner=StageRunner(
            _out(pytest_summary(11, failed=1), 1), _out(pytest_summary(12))
        ),
        which_fn=_installed,
    )
    assert tv.result == "PASS"
    assert "base tree was already red" in tv.detail


@pytest.mark.parametrize("suite", [PYTEST_SPEC, PHPUNIT_SPEC])
def test_counts_come_from_both_trees(tmp_path, suite):
    outputs = {
        "pytest": (pytest_summary(5), pytest_summary(6)),
        "phpunit": ("OK (5 tests, 9 assertions)", "OK (6 tests, 11 assertions)"),
    }[suite.name]
    tv = validate_tests(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        suite=suite,
        runner=StageRunner(_out(outputs[0]), _out(outputs[1])),
        which_fn=_installed,
    )
    assert (tv.base_executed, tv.base_passed) == (5, 5)
    assert (tv.patched_executed, tv.patched_passed) == (6, 6)
