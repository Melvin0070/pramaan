"""Lane E — graded proof-bundle assembly, the PR gate, and the funnel (D4)."""

from __future__ import annotations

import pytest

from pramaan.policy.engine import decide, decide_after_proof
from pramaan.proof.bundle import (
    STAGE_ORDER,
    ProofRequest,
    build_bundle,
    funnel_report,
    run_proof,
    split_by_funnel,
)
from pramaan.schemas import BusinessImpact, Evidence, ValidatorResult, Verdict

# Underscored alias: pytest tries to collect any module-level name matching `Test*`.
from pramaan.schemas import TestsValidation as _TestsValidation
from pramaan.validators.poc import PoCOutcome, PoCSpec
from pramaan.validators.process import CommandResult

PASSING_TESTS = _TestsValidation(
    result="PASS", base_executed=20, base_passed=20, patched_executed=21, patched_passed=21
)
BLOCKED_POC = PoCOutcome("BLOCKED", "pass", "blocked", True, False)
NO_POC = PoCOutcome("NO_POC", "skipped", "no exploit harness")


def _ok(name: str) -> ValidatorResult:
    return ValidatorResult(name, "pass", "ok")


def _full_proof(**kwargs):
    defaults = dict(
        finding_id="semgrep:xss:includes/order.php:11",
        funnel="full_proof",
        tests=PASSING_TESTS,
        validators=[_ok("diff_in_scope"), _ok("no_cheating"), _ok("rescan_clean")],
        poc=BLOCKED_POC,
        reviewer_approved=True,
    )
    defaults.update(kwargs)
    return build_bundle(**defaults)


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #

def test_all_green_plus_reviewer_opens_a_pr():
    bundle = _full_proof()
    assert bundle.may_open_pr is True
    assert bundle.blocking == []
    assert bundle.grade() == {"pass": 5, "fail": 0, "skipped": 0, "unavailable": 0}


def test_validators_are_ordered_by_stage():
    bundle = _full_proof(
        validators=[_ok("rescan_clean"), _ok("no_cheating"), _ok("diff_in_scope")]
    )
    names = [v.name for v in bundle.validators]
    assert names == [n for n in STAGE_ORDER if n in names]


def test_reviewer_none_fails_closed():
    bundle = _full_proof(reviewer_approved=None)
    assert bundle.may_open_pr is False
    assert bundle.blocking == []  # nothing failed; the reviewer simply did not answer


def test_reviewer_false_fails_closed():
    assert _full_proof(reviewer_approved=False).may_open_pr is False


def test_unavailable_validator_blocks():
    bundle = _full_proof(
        validators=[
            _ok("diff_in_scope"),
            _ok("no_cheating"),
            ValidatorResult("rescan_clean", "unavailable", "semgrep not installed"),
        ]
    )
    assert bundle.may_open_pr is False
    assert [v.name for v in bundle.blocking] == ["rescan_clean"]


def test_no_suite_blocks_even_with_everything_else_green():
    bundle = _full_proof(tests=_TestsValidation(result="NO_SUITE"))
    assert bundle.may_open_pr is False
    assert [v.outcome for v in bundle.blocking] == ["unavailable"]


def test_fewer_tests_blocks_even_though_the_suite_was_green():
    bundle = _full_proof(
        tests=_TestsValidation(
            result="PASS",
            base_executed=20,
            base_passed=20,
            patched_executed=17,
            patched_passed=17,
        )
    )
    assert bundle.may_open_pr is False
    assert "cheating-patch flag" in bundle.blocking[0].detail


def test_partial_proof_can_never_open_a_pr():
    """D4/D17: no exploit harness means no proof, so no PR - structurally."""
    bundle = build_bundle(
        finding_id="semgrep:xss:includes/x.php:3",
        funnel="partial_proof",
        tests=PASSING_TESTS,
        validators=[_ok("diff_in_scope"), _ok("no_cheating"), _ok("rescan_clean")],
        poc=NO_POC,
        reviewer_approved=True,
    )
    assert bundle.poc == "NO_POC"
    assert bundle.may_open_pr is False
    assert [v.name for v in bundle.blocking] == ["poc_blocked"]


def test_full_proof_without_a_poc_is_a_labelling_error():
    with pytest.raises(ValueError, match="full_proof requires a PoC"):
        build_bundle(
            finding_id="f", funnel="full_proof", tests=PASSING_TESTS, poc=NO_POC
        )


def test_partial_proof_with_a_poc_is_a_labelling_error():
    with pytest.raises(ValueError, match="partial_proof carries no PoC"):
        build_bundle(
            finding_id="f", funnel="partial_proof", tests=PASSING_TESTS, poc=BLOCKED_POC
        )


def test_missing_poc_outcome_is_unavailable_not_absent():
    bundle = build_bundle(
        finding_id="f", funnel="partial_proof", tests=PASSING_TESTS, poc=None
    )
    poc_row = next(v for v in bundle.all_validators if v.name == "poc_blocked")
    assert poc_row.outcome == "unavailable"


def test_duplicate_validator_names_are_rejected():
    with pytest.raises(ValueError, match="duplicate validator names"):
        build_bundle(
            finding_id="f",
            funnel="partial_proof",
            tests=PASSING_TESTS,
            validators=[_ok("rescan_clean"), _ok("rescan_clean")],
            poc=NO_POC,
        )


def test_caller_supplied_tests_green_is_rejected():
    with pytest.raises(ValueError, match="tests_green"):
        build_bundle(
            finding_id="f",
            funnel="partial_proof",
            tests=PASSING_TESTS,
            validators=[_ok("tests_green")],
            poc=NO_POC,
        )


def test_to_dict_carries_the_grade_and_the_gate():
    d = _full_proof().to_dict()
    assert d["may_open_pr"] is True
    assert d["grade"]["pass"] == 5
    assert d["blocking"] == []


# --------------------------------------------------------------------------- #
# Wiring into the policy engine
# --------------------------------------------------------------------------- #

def _fix_candidate_decision():
    verdict = Verdict(
        finding_id="semgrep:xss:includes/order.php:11",
        verdict="true_positive",
        confidence=0.93,
        cwe="CWE-79",
        evidence=[Evidence(file="includes/order.php", line=11, why="unescaped $_GET")],
        reachability="reachable_from_http",
        business_impact=BusinessImpact(),
        injection_observed=False,
        rationale="unescaped request value in an href",
    )
    return decide(verdict, BusinessImpact(), tau=0.7)


def test_a_passing_bundle_leaves_the_fix_decision_alone():
    decision = _fix_candidate_decision()
    assert decision.recommended_action == "fix_candidate"
    assert decide_after_proof(decision, _full_proof()) is decision


def test_a_blocked_bundle_downgrades_to_a_ticket():
    after = decide_after_proof(
        _fix_candidate_decision(), _full_proof(tests=_TestsValidation(result="NO_SUITE"))
    )
    assert after.recommended_action == "open_ticket"
    assert after.escalate_reason == "proof_failed"
    assert "tests_green=unavailable" in after.rationale


def test_a_missing_reviewer_verdict_downgrades_to_a_ticket():
    after = decide_after_proof(_fix_candidate_decision(), _full_proof(reviewer_approved=None))
    assert after.recommended_action == "open_ticket"
    assert "reviewer did not approve" in after.rationale


# --------------------------------------------------------------------------- #
# run_proof
# --------------------------------------------------------------------------- #

CLEAN_DIFF = """\
diff --git a/includes/order.php b/includes/order.php
--- a/includes/order.php
+++ b/includes/order.php
@@ -10,2 +10,2 @@
-        echo $_GET['back'];
+        echo esc_url($_GET['back']);
diff --git a/tests/OrderTest.php b/tests/OrderTest.php
new file mode 100644
--- /dev/null
+++ b/tests/OrderTest.php
@@ -0,0 +1,2 @@
+<?php
+class OrderTest { public function testEscaped() {} }
"""


class ScriptedRunner:
    """Dispatches on the executable name rather than call order, so the proof
    runner's internal ordering is not baked into the test."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, *, cwd, timeout_s=600.0, env=None):
        argv = tuple(str(a) for a in argv)
        self.calls.append(argv)
        for key, result in self.mapping.items():
            if key in argv[0] or key in " ".join(argv):
                return result(str(cwd)) if callable(result) else result
        return CommandResult(argv=argv, started=False, error="unscripted command")


def test_run_proof_grades_a_target_with_no_toolchain(tmp_path):
    """Nothing installed: every validator that could not run says so."""
    base, patched = tmp_path / "base", tmp_path / "patched"
    base.mkdir()
    patched.mkdir()

    bundle = run_proof(
        ProofRequest(
            finding_id="semgrep:xss:includes/order.php:11",
            funnel="partial_proof",
            base_tree=base,
            patched_tree=patched,
            diff_text=CLEAN_DIFF,
            finding_path="includes/order.php",
            rule_id="php.xss",
        ),
        runner=ScriptedRunner({}),
        which_fn=lambda _n: None,
    )
    outcomes = {v.name: v.outcome for v in bundle.all_validators}
    assert outcomes["diff_in_scope"] == "pass"
    assert outcomes["no_cheating"] == "pass"
    assert outcomes["rescan_clean"] == "unavailable"  # no semgrep ruleset configured
    assert outcomes["tests_green"] == "unavailable"  # no suite
    assert outcomes["poc_blocked"] == "skipped"  # partial-proof funnel
    assert bundle.may_open_pr is False
    assert bundle.grade()["unavailable"] == 2


def test_run_proof_wires_every_validator(tmp_path):
    base, patched = tmp_path / "base", tmp_path / "patched"
    (base / "tests").mkdir(parents=True)
    (patched / "tests").mkdir(parents=True)

    semgrep_out = CommandResult(
        argv=("semgrep",),
        returncode=0,
        stdout='{"errors": [], "paths": {"scanned": ["a.php"]}, "results": []}',
    )
    semgrep_base = CommandResult(
        argv=("semgrep",),
        returncode=1,
        stdout=(
            '{"errors": [], "paths": {"scanned": ["a.php"]}, "results": ['
            '{"check_id": "php.xss", "path": "includes/order.php",'
            ' "start": {"line": 11}, "end": {"line": 11},'
            ' "extra": {"message": "m", "severity": "WARNING", "lines": "x"}}]}'
        ),
    )
    semgrep_calls = [semgrep_base, semgrep_out]

    runner = ScriptedRunner(
        {
            "semgrep": lambda _cwd: semgrep_calls.pop(0),
            "pytest": CommandResult(
                argv=("pytest",), returncode=0, stdout="==== 9 passed in 1s ===="
            ),
            "poc": lambda cwd: CommandResult(
                argv=("python", "poc.py"), returncode=0 if cwd.endswith("base") else 1
            ),
        }
    )

    bundle = run_proof(
        ProofRequest(
            finding_id="semgrep:php.xss:includes/order.php:11",
            funnel="full_proof",
            base_tree=base,
            patched_tree=patched,
            diff_text=CLEAN_DIFF,
            finding_path="includes/order.php",
            rule_id="php.xss",
            semgrep_config="rules/xss.yaml",
            poc=PoCSpec(argv=("python", "poc.py"), bin_name="python"),
        ),
        reviewer_approved=True,
        runner=runner,
        which_fn=lambda _n: "/usr/bin/" + _n,
    )
    assert {v.name: v.outcome for v in bundle.all_validators} == {
        "diff_in_scope": "pass",
        "no_cheating": "pass",
        "rescan_clean": "pass",
        "tests_green": "pass",
        "poc_blocked": "pass",
    }
    assert bundle.may_open_pr is True
    assert bundle.poc == "BLOCKED"


def test_the_fixers_regression_gate_becomes_a_bundle_row(tmp_path):
    """`FixAttempt.regression_test` is a `ValidatorResult`, so it plugs straight
    into the bundle through `extra_validators` and blocks like any other stage."""
    from pramaan.fix.guards import RegressionTestGate, regression_test_validator

    base, patched = tmp_path / "base", tmp_path / "patched"
    base.mkdir()
    patched.mkdir()

    gate = RegressionTestGate()
    gate.evaluate(
        "diff --git a/includes/order.php b/includes/order.php\n"
        "--- a/includes/order.php\n+++ b/includes/order.php\n"
        "@@ -1,1 +1,1 @@\n-a\n+b\n"
    )
    bundle = run_proof(
        ProofRequest(
            finding_id="f",
            funnel="partial_proof",
            base_tree=base,
            patched_tree=patched,
            diff_text=CLEAN_DIFF,
            finding_path="includes/order.php",
            extra_validators=(regression_test_validator(gate),),
        ),
        runner=ScriptedRunner({}),
        which_fn=lambda _n: None,
    )
    row = next(v for v in bundle.all_validators if v.name == "regression_test")
    assert row.outcome == "fail"
    assert bundle.may_open_pr is False


def test_run_proof_never_sets_reviewer_approved_by_itself(tmp_path):
    base, patched = tmp_path / "base", tmp_path / "patched"
    base.mkdir()
    patched.mkdir()
    bundle = run_proof(
        ProofRequest(
            finding_id="f",
            funnel="partial_proof",
            base_tree=base,
            patched_tree=patched,
            diff_text=CLEAN_DIFF,
            finding_path="includes/order.php",
        ),
        runner=ScriptedRunner({}),
        which_fn=lambda _n: None,
    )
    assert bundle.reviewer_approved is None


# --------------------------------------------------------------------------- #
# The funnel
# --------------------------------------------------------------------------- #

def test_funnel_counts_survivors_stage_by_stage():
    bundles = [
        _full_proof(),
        _full_proof(
            validators=[
                ValidatorResult("diff_in_scope", "fail", "unrelated files"),
                _ok("no_cheating"),
                _ok("rescan_clean"),
            ]
        ),
        _full_proof(tests=_TestsValidation(result="NO_SUITE")),
        _full_proof(reviewer_approved=None),
    ]
    report = funnel_report(bundles)
    assert report.drafted == 4
    assert report.per_stage_pass["diff_in_scope"] == 3
    assert report.per_stage_pass["tests_green"] == 3
    assert report.cumulative["diff_in_scope"] == 3
    assert report.cumulative["tests_green"] == 2
    assert report.cumulative["poc_blocked"] == 2
    assert report.reviewer_approved == 3
    # Only the first bundle clears every stage *and* has a reviewer verdict: the
    # fourth passes every validator and is still blocked by `reviewer=None`.
    assert report.may_open_pr == 1
    assert report.survival_rate == 0.25
    assert report.per_stage_outcomes["tests_green"]["unavailable"] == 1


def test_funnel_refuses_to_blend_the_two_kinds():
    partial = build_bundle(
        finding_id="p", funnel="partial_proof", tests=PASSING_TESTS, poc=NO_POC
    )
    with pytest.raises(ValueError, match="refusing to blend funnels"):
        funnel_report([_full_proof(), partial])


def test_split_by_funnel_separates_them():
    partial = build_bundle(
        finding_id="p", funnel="partial_proof", tests=PASSING_TESTS, poc=NO_POC
    )
    split = split_by_funnel([_full_proof(), partial, _full_proof()])
    assert len(split["full_proof"]) == 2 and len(split["partial_proof"]) == 1
    assert funnel_report(split["partial_proof"]).may_open_pr == 0


def test_funnel_needs_a_denominator():
    with pytest.raises(ValueError, match="at least one bundle"):
        funnel_report([])
