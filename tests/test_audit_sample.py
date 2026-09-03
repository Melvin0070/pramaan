"""The 10% auto-close audit draw (TODO 2)."""

from __future__ import annotations

import pytest

from pramaan.evals.audit_sample import (
    AuditOutcome,
    AuditSample,
    draw,
    eligible_ids,
    record,
)
from pramaan.evals.stats import EvalError, InsufficientData
from pramaan.policy.engine import decide
from pramaan.schemas import BusinessImpact, Evidence, Verdict

FRAME = [f"semgrep:rule:src/File{i:03d}.php:{i}" for i in range(60)]
SEED = "pramaan-audit-2026-09"


def _verdict(label: str, confidence: float) -> Verdict:
    return Verdict(
        finding_id="semgrep:rule:src/Api.php:10",
        verdict=label,  # type: ignore[arg-type]
        confidence=confidence,
        cwe="CWE-89",
        evidence=[Evidence("src/Api.php", 10, "why")],
        reachability="internal_only",
        business_impact=BusinessImpact(),
        injection_observed=False,
        rationale="r",
    )


class TestEligibleFrame:
    def test_only_auto_closures_enter_the_frame(self):
        closed = decide(_verdict("false_positive", 0.97), BusinessImpact(), 0.9)
        ticketed = decide(_verdict("true_positive", 0.97), BusinessImpact(), 0.9)
        escalated = decide(_verdict("false_positive", 0.10), BusinessImpact(), 0.9)
        assert closed.recommended_action == "auto_close"
        frame = eligible_ids(
            [("A", closed), ("B", ticketed), ("C", escalated)]
        )
        assert frame == ("A",)

    def test_missing_finding_id_is_an_error(self):
        closed = decide(_verdict("false_positive", 0.97), BusinessImpact(), 0.9)
        with pytest.raises(EvalError):
            eligible_ids([closed])


class TestDraw:
    def test_is_deterministic_for_a_seed(self):
        assert draw(FRAME, seed=SEED).sample_ids == draw(FRAME, seed=SEED).sample_ids

    def test_is_independent_of_frame_order(self):
        assert (
            draw(FRAME, seed=SEED).sample_ids
            == draw(list(reversed(FRAME)), seed=SEED).sample_ids
        )

    def test_a_different_seed_draws_a_different_sample(self):
        assert draw(FRAME, seed=SEED).sample_ids != draw(FRAME, seed="other").sample_ids

    def test_size_is_ten_percent_rounded_up(self):
        assert draw(FRAME, seed=SEED).size == 6
        assert draw(FRAME[:11], seed=SEED).size == 2

    def test_min_size_floors_a_tiny_frame(self):
        sample = draw(FRAME[:3], seed=SEED)
        assert sample.size == 1
        assert sample.realised_fraction == pytest.approx(1 / 3)

    def test_sample_is_a_subset_of_the_frame(self):
        sample = draw(FRAME, seed=SEED)
        assert set(sample.sample_ids) <= set(FRAME)

    def test_verify_recomputes_the_draw(self):
        sample = draw(FRAME, seed=SEED)
        assert sample.verify(FRAME)
        assert not sample.verify(FRAME[:-1])

    def test_empty_frame_is_not_an_error(self):
        sample = draw([], seed=SEED)
        assert sample.size == 0 and sample.frame_size == 0
        assert "empty frame" in sample.unaudited_statement()

    def test_duplicate_ids_are_rejected(self):
        with pytest.raises(EvalError):
            draw(["A", "A", "B"], seed=SEED)

    def test_seed_is_mandatory(self):
        with pytest.raises(ValueError):
            draw(FRAME, seed="  ")

    def test_fraction_must_be_a_proportion(self):
        with pytest.raises(ValueError):
            draw(FRAME, seed=SEED, fraction=1.5)

    def test_to_dict_publishes_the_ids_and_the_seed(self):
        d = draw(FRAME, seed=SEED).to_dict()
        assert d["seed"] == SEED
        assert len(d["sample_ids"]) == d["sample_size"] == 6


class TestUnauditedPath:
    def test_statement_says_plainly_that_nobody_audited(self):
        text = draw(FRAME, seed=SEED).unaudited_statement()
        assert "NO AUDIT WAS PERFORMED" in text
        assert SEED in text
        assert "6 of 60" in text

    def test_an_audit_without_a_named_auditor_is_refused(self):
        sample = draw(FRAME, seed=SEED)
        with pytest.raises(EvalError) as excinfo:
            record(
                sample,
                [AuditOutcome(sample.sample_ids[0], True)],
                auditor="   ",
            )
        assert "unaudited_statement" in str(excinfo.value)

    def test_recording_nothing_is_refused(self):
        sample = draw(FRAME, seed=SEED)
        with pytest.raises(InsufficientData):
            record(sample, [], auditor="melvin")


class TestRecord:
    def test_counts_errors_and_reports_an_interval(self):
        sample = draw(FRAME, seed=SEED)
        outcomes = [
            AuditOutcome(fid, i != 0, note="wrong call" if i == 0 else "")
            for i, fid in enumerate(sample.sample_ids)
        ]
        result = record(sample, outcomes, auditor="melvin", min_n=1)
        assert result.n_audited == 6
        assert result.n_errors == 1
        assert result.error_rate.point == pytest.approx(1 / 6)
        assert result.error_rate.low is not None
        assert result.errors[0].note == "wrong call"

    def test_zero_errors_reports_the_rule_of_three_bound(self):
        sample = draw(FRAME, seed=SEED)
        result = record(
            sample,
            [AuditOutcome(fid, True) for fid in sample.sample_ids],
            auditor="melvin",
            min_n=1,
        )
        assert result.n_errors == 0
        assert result.error_rate.point == 0.0
        assert result.zero_error_upper_bound == pytest.approx(0.3930, abs=1e-3)
        assert "95% upper bound" in result.render()

    def test_projection_to_the_frame_is_a_range_not_a_point(self):
        sample = draw(FRAME, seed=SEED)
        outcomes = [
            AuditOutcome(fid, i != 0) for i, fid in enumerate(sample.sample_ids)
        ]
        result = record(sample, outcomes, auditor="melvin", min_n=1)
        low, high = result.projected_frame_errors
        assert low < (1 / 6) * 60 < high
        assert any("finite-population correction" in n for n in result.notes)

    def test_partial_audits_are_reported_not_hidden(self):
        sample = draw(FRAME, seed=SEED)
        result = record(
            sample,
            [AuditOutcome(fid, True) for fid in sample.sample_ids[:3]],
            auditor="melvin",
            min_n=1,
        )
        assert result.n_audited == 3
        assert len(result.unaudited_ids) == 3
        assert any("were not\n" in n or "not reviewed" in n for n in result.notes)

    def test_outcomes_outside_the_sample_are_rejected(self):
        sample = draw(FRAME, seed=SEED)
        with pytest.raises(EvalError):
            record(sample, [AuditOutcome("not-in-sample", True)], auditor="m")

    def test_double_auditing_one_finding_is_rejected(self):
        sample = draw(FRAME, seed=SEED)
        fid = sample.sample_ids[0]
        with pytest.raises(EvalError):
            record(
                sample,
                [AuditOutcome(fid, True), AuditOutcome(fid, False)],
                auditor="m",
            )

    def test_small_audits_are_flagged_as_counts_only(self):
        sample = draw(FRAME[:20], seed=SEED)
        result = record(
            sample,
            [AuditOutcome(fid, True) for fid in sample.sample_ids],
            auditor="melvin",
        )
        assert not result.error_rate.reportable
        assert any("report the counts, not the rate" in n for n in result.notes)

    def test_to_dict_is_serialisable(self):
        sample = draw(FRAME, seed=SEED)
        d = record(
            sample,
            [AuditOutcome(fid, True) for fid in sample.sample_ids],
            auditor="melvin",
            min_n=1,
        ).to_dict()
        assert d["auditor"] == "melvin"
        assert d["sample"]["seed"] == SEED


class TestSampleType:
    def test_sample_is_frozen(self):
        sample = draw(FRAME, seed=SEED)
        with pytest.raises(Exception):
            sample.sample_ids = ()  # type: ignore[misc]
        assert isinstance(sample, AuditSample)
