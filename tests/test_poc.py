"""Lane E — the PoC exploit validator, run before AND after the patch."""

from __future__ import annotations

from pramaan.validators.poc import PoCSpec, run_poc, validate_poc
from pramaan.validators.process import CommandResult

SPEC = PoCSpec(argv=("python", "poc/sqli.py"), name="juice-shop-sqli", bin_name="python")


class StageRunner:
    """One queued CommandResult per stage, in call order (base, then patched)."""

    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.cwds: list[str] = []

    def __call__(self, argv, *, cwd, timeout_s=600.0, env=None):
        self.cwds.append(str(cwd))
        return self.results.pop(0)


def _exit(code: int, out: str = "") -> CommandResult:
    return CommandResult(argv=("python", "poc/sqli.py"), returncode=code, stdout=out)


def _installed(_name: str) -> str:
    return "/usr/bin/python"


def _missing(_name: str) -> None:
    return None


def test_exploited_before_and_blocked_after_passes(tmp_path):
    runner = StageRunner(_exit(0), _exit(1))
    outcome = run_poc(
        base_tree=tmp_path / "base",
        patched_tree=tmp_path / "patched",
        spec=SPEC,
        runner=runner,
        which_fn=_installed,
    )
    assert outcome.result == "BLOCKED"
    assert outcome.outcome == "pass"
    assert outcome.base_exploited is True and outcome.patched_exploited is False
    assert runner.cwds[0].endswith("base") and runner.cwds[1].endswith("patched")
    assert outcome.as_validator().name == "poc_blocked"
    assert outcome.as_validator().blocks_pr is False


def test_still_exploitable_fails(tmp_path):
    outcome = run_poc(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        spec=SPEC,
        runner=StageRunner(_exit(0), _exit(0)),
        which_fn=_installed,
    )
    assert outcome.result == "STILL_EXPLOITABLE"
    assert outcome.outcome == "fail"


def test_poc_that_fails_before_the_patch_is_invalid_not_a_pass(tmp_path):
    """The headline case: an exploit that never worked also fails after the patch."""
    runner = StageRunner(_exit(1))
    outcome = run_poc(
        base_tree=tmp_path / "base",
        patched_tree=tmp_path / "patched",
        spec=SPEC,
        runner=runner,
        which_fn=_installed,
    )
    assert outcome.result == "INVALID_POC"
    assert outcome.outcome == "fail"
    assert outcome.base_exploited is False
    assert outcome.patched_exploited is None
    assert "BASE tree" in outcome.detail
    # The patched tree is never even run: there is nothing to learn from it.
    assert len(runner.cwds) == 1
    assert outcome.as_validator().blocks_pr is True


def test_no_poc_is_skipped_and_still_blocks(tmp_path):
    outcome = run_poc(
        base_tree=tmp_path, patched_tree=tmp_path, spec=None, which_fn=_installed
    )
    assert outcome.result == "NO_POC"
    assert outcome.outcome == "skipped"
    # D4: partial_proof findings cannot reach may_open_pr, by construction.
    assert outcome.as_validator().blocks_pr is True


def test_patched_timeout_is_unavailable_not_blocked(tmp_path):
    """A hung exploit looks like a defeated one from the outside."""
    hung = CommandResult(argv=("python",), timed_out=True, error="timed out after 300s")
    outcome = run_poc(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        spec=SPEC,
        runner=StageRunner(_exit(0), hung),
        which_fn=_installed,
    )
    assert outcome.result == "INVALID_POC"
    assert outcome.outcome == "unavailable"
    assert outcome.base_exploited is True
    assert outcome.patched_exploited is None


def test_base_harness_crash_is_unavailable(tmp_path):
    crashed = CommandResult(argv=("python",), started=False, error="FileNotFoundError")
    outcome = run_poc(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        spec=SPEC,
        runner=StageRunner(crashed),
        which_fn=_installed,
    )
    assert outcome.result == "INVALID_POC"
    assert outcome.outcome == "unavailable"


def test_missing_poc_runner_is_unavailable(tmp_path):
    outcome = run_poc(
        base_tree=tmp_path, patched_tree=tmp_path, spec=SPEC, which_fn=_missing
    )
    assert outcome.result == "INVALID_POC"
    assert outcome.outcome == "unavailable"
    assert "not installed" in outcome.detail


def test_success_marker_overrides_exit_code(tmp_path):
    spec = PoCSpec(
        argv=("python", "poc.py"),
        success_marker="EXPLOITED",
        bin_name="python",
    )
    # Both runs exit 0; only the base one prints the marker.
    outcome = run_poc(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        spec=spec,
        runner=StageRunner(_exit(0, "EXPLOITED: dumped 4 rows"), _exit(0, "blocked")),
        which_fn=_installed,
    )
    assert outcome.result == "BLOCKED"
    assert outcome.outcome == "pass"


def test_non_zero_exploit_convention_is_supported(tmp_path):
    spec = PoCSpec(argv=("./poc.sh",), exploit_exit_code=42, bin_name="")
    outcome = run_poc(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        spec=spec,
        runner=StageRunner(_exit(42), _exit(0)),
        which_fn=_installed,
    )
    assert outcome.result == "BLOCKED"


def test_validate_poc_returns_a_validator_result(tmp_path):
    result = validate_poc(
        base_tree=tmp_path,
        patched_tree=tmp_path,
        spec=SPEC,
        runner=StageRunner(_exit(0), _exit(1)),
        which_fn=_installed,
    )
    assert result.name == "poc_blocked"
    assert result.outcome == "pass"
    assert result.evidence["poc_result"] == "BLOCKED"
    assert result.evidence["base_exit_code"] == 0
    assert result.evidence["patched_exit_code"] == 1
