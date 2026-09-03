"""Lane E — re-running the same Semgrep rule on the patched tree."""

from __future__ import annotations

import json

from pramaan.validators.process import CommandResult
from pramaan.validators.rescan import build_semgrep_argv, rescan, run_semgrep

RULE = "php.lang.security.var-in-href.var-in-href"


def semgrep_json(*, matches: int, scanned: int = 3, path: str = "includes/order.php") -> str:
    return json.dumps(
        {
            "version": "1.90.0",
            "errors": [],
            "paths": {"scanned": [f"file{i}.php" for i in range(scanned)]},
            "results": [
                {
                    "check_id": RULE,
                    "path": path,
                    "start": {"line": 11 + i, "col": 1},
                    "end": {"line": 11 + i, "col": 40},
                    "extra": {
                        "message": "user input in an href attribute",
                        "severity": "WARNING",
                        "lines": "echo $_GET['back'];",
                        "metadata": {"cwe": ["CWE-79: Cross-site Scripting"]},
                    },
                }
                for i in range(matches)
            ],
        }
    )


class FakeRunner:
    """Returns a queued CommandResult per call, recording the argv it saw."""

    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[tuple[str, ...], str]] = []

    def __call__(self, argv, *, cwd, timeout_s=600.0, env=None):
        self.calls.append((tuple(str(a) for a in argv), str(cwd)))
        return self.results.pop(0) if self.results else CommandResult(
            argv=tuple(argv), returncode=0, stdout=semgrep_json(matches=0)
        )


def _installed(_name: str) -> str:
    return "/usr/local/bin/semgrep"


def _missing(_name: str) -> None:
    return None


def _result(stdout: str, code: int = 0) -> CommandResult:
    return CommandResult(argv=("semgrep",), returncode=code, stdout=stdout)


def test_argv_is_offline_and_pins_the_ruleset():
    argv = build_semgrep_argv(config="rules/xss.yaml", targets=["includes/order.php"])
    assert "--metrics=off" in argv
    assert "--disable-version-check" in argv
    assert argv[argv.index("--config") + 1] == "rules/xss.yaml"
    assert argv[-1] == "includes/order.php"


def test_clean_patched_tree_passes(tmp_path):
    runner = FakeRunner(_result(semgrep_json(matches=0)))
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "pass"
    assert result.evidence["scanned_files"] == 3


def test_surviving_match_fails(tmp_path):
    runner = FakeRunner(_result(semgrep_json(matches=2), code=1))
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "fail"
    assert result.evidence["match_count"] == 2
    assert "includes/order.php:11" in result.detail


def test_other_rules_do_not_count(tmp_path):
    doc = json.loads(semgrep_json(matches=1))
    doc["results"][0]["check_id"] = "some.other.rule"
    runner = FakeRunner(_result(json.dumps(doc), code=1))
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "pass"


def test_semgrep_not_installed_is_unavailable(tmp_path):
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=FakeRunner(),
        which_fn=_missing,
    )
    assert result.outcome == "unavailable"
    assert result.blocks_pr is True
    assert "not installed" in result.detail


def test_zero_scanned_files_is_unavailable_not_clean(tmp_path):
    """`results: []` over zero files looks exactly like a clean tree."""
    runner = FakeRunner(_result(semgrep_json(matches=0, scanned=0)))
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "unavailable"
    assert "scanned 0 files" in result.detail


def test_semgrep_fatal_exit_is_unavailable(tmp_path):
    runner = FakeRunner(
        CommandResult(argv=("semgrep",), returncode=2, stderr="config not found")
    )
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "unavailable"
    assert "exited 2" in result.detail


def test_timeout_is_unavailable(tmp_path):
    runner = FakeRunner(
        CommandResult(argv=("semgrep",), timed_out=True, error="timed out after 900s")
    )
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "unavailable"


def test_non_json_output_is_unavailable(tmp_path):
    runner = FakeRunner(_result("METRICS: on\nnot json at all"))
    result = rescan(
        patched_tree=tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "unavailable"
    assert "not JSON" in result.detail


def test_base_tree_that_is_already_clean_makes_the_rescan_meaningless(tmp_path):
    """The rescan's analogue of INVALID_POC."""
    runner = FakeRunner(
        _result(semgrep_json(matches=0)),  # base: rule does not fire
        _result(semgrep_json(matches=0)),  # patched: also clean
    )
    result = rescan(
        patched_tree=tmp_path / "patched",
        base_tree=tmp_path / "base",
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "unavailable"
    assert "does not fire on the base tree" in result.detail


def test_base_hit_then_clean_patch_passes(tmp_path):
    runner = FakeRunner(
        _result(semgrep_json(matches=1), code=1),
        _result(semgrep_json(matches=0)),
    )
    result = rescan(
        patched_tree=tmp_path / "patched",
        base_tree=tmp_path / "base",
        config="rules/xss.yaml",
        rule_id=RULE,
        runner=runner,
        which_fn=_installed,
    )
    assert result.outcome == "pass"
    assert len(runner.calls) == 2
    assert runner.calls[0][1].endswith("base")
    assert runner.calls[1][1].endswith("patched")


def test_path_filter_narrows_results(tmp_path):
    runner = FakeRunner(_result(semgrep_json(matches=1, path="other/file.php"), code=1))
    out = run_semgrep(
        tmp_path,
        config="rules/xss.yaml",
        rule_id=RULE,
        path="includes/order.php",
        runner=runner,
        which_fn=_installed,
    )
    assert out.ran is True
    assert out.findings == ()
    assert "includes/order.php" in runner.calls[0][0]
