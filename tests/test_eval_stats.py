"""Small-sample statistics and the labelled-row contract."""

from __future__ import annotations

import pytest
from evals_fixtures import CORPUS, OTHER_CORPUS, make_attempt

from pramaan.evals.labels import (
    LabelledVerdict,
    canonical_order,
    check_scoring_unit,
    from_attempts,
    one_corpus,
    one_row_per_finding,
    repeated_findings,
    split_by_corpus,
)
from pramaan.evals.stats import (
    BlendedCorpusError,
    InsufficientData,
    Rate,
    RepeatedRunsError,
    bootstrap_ci,
    mean,
    median,
    quantile,
    stdev,
    wilson_interval,
    zero_events_upper_bound,
)


class TestWilson:
    def test_zero_successes_has_a_non_degenerate_upper_bound(self):
        low, high = wilson_interval(0, 10)
        assert low == 0.0
        assert high == pytest.approx(0.2775, abs=1e-3)

    def test_all_successes_has_a_non_degenerate_lower_bound(self):
        low, high = wilson_interval(10, 10)
        assert high == pytest.approx(1.0)
        assert low == pytest.approx(0.7225, abs=1e-3)

    def test_interval_narrows_as_n_grows(self):
        small = wilson_interval(5, 10)
        large = wilson_interval(500, 1000)
        assert (large[1] - large[0]) < (small[1] - small[0])

    def test_refuses_an_empty_denominator(self):
        with pytest.raises(InsufficientData):
            wilson_interval(0, 0)

    def test_rejects_impossible_counts(self):
        with pytest.raises(ValueError):
            wilson_interval(11, 10)


class TestRate:
    def test_empty_denominator_is_unknown_not_zero(self):
        r = Rate(0, 0, label="asr")
        assert r.point is None
        assert r.interval is None
        assert "nothing to report" in r.render()

    def test_small_n_is_not_reportable_and_says_so(self):
        r = Rate(1, 3, label="miss rate")
        assert r.point == pytest.approx(1 / 3)
        assert not r.reportable
        assert "n too small to report" in r.render()
        with pytest.raises(InsufficientData):
            r.require_point()

    def test_reportable_rate_hands_over_its_point(self):
        r = Rate(9, 10, label="pass^5")
        assert r.reportable
        assert r.require_point() == pytest.approx(0.9)
        assert "95% CI" in r.render()

    def test_rejects_inconsistent_counts(self):
        with pytest.raises(ValueError):
            Rate(4, 3)
        with pytest.raises(ValueError):
            Rate(-1, 3)

    def test_to_dict_carries_the_denominator(self):
        d = Rate(2, 20, label="x").to_dict()
        assert d["successes"] == 2 and d["n"] == 20
        assert d["ci95_low"] is not None and d["ci95_high"] is not None


class TestRuleOfThree:
    def test_zero_in_ten_is_not_zero_percent(self):
        assert zero_events_upper_bound(10) == pytest.approx(0.2589, abs=1e-3)

    def test_bound_shrinks_with_more_trials(self):
        assert zero_events_upper_bound(100) < zero_events_upper_bound(10)

    def test_needs_at_least_one_trial(self):
        with pytest.raises(InsufficientData):
            zero_events_upper_bound(0)


class TestDescriptives:
    def test_quantile_matches_linear_interpolation(self):
        xs = [1.0, 2.0, 3.0, 4.0]
        assert quantile(xs, 0.0) == 1.0
        assert quantile(xs, 1.0) == 4.0
        assert quantile(xs, 0.5) == pytest.approx(2.5)
        assert quantile(xs, 0.25) == pytest.approx(1.75)

    def test_single_observation_has_zero_spread(self):
        assert stdev([3.0]) == 0.0

    def test_empty_inputs_raise_one_error_type(self):
        for fn in (mean, median, stdev):
            with pytest.raises(InsufficientData):
                fn([])
        with pytest.raises(InsufficientData):
            quantile([], 0.5)

    def test_mean_and_median_disagree_on_a_skewed_sample(self):
        xs = [1.0, 1.0, 1.0, 97.0]
        assert median(xs) == 1.0
        assert mean(xs) == pytest.approx(25.0)


class TestBootstrap:
    def test_same_seed_same_interval(self):
        values = [float(i % 7) for i in range(60)]
        a = bootstrap_ci(values, lambda s: sum(s) / len(s), seed="z", resamples=200)
        b = bootstrap_ci(values, lambda s: sum(s) / len(s), seed="z", resamples=200)
        assert a == b

    def test_different_seed_different_interval(self):
        values = [float(i % 7) for i in range(60)]
        a = bootstrap_ci(values, lambda s: sum(s) / len(s), seed="z", resamples=200)
        b = bootstrap_ci(values, lambda s: sum(s) / len(s), seed="y", resamples=200)
        assert a != b

    def test_interval_brackets_the_sample_mean(self):
        values = [float(i) for i in range(100)]
        low, high = bootstrap_ci(
            values, lambda s: sum(s) / len(s), seed="z", resamples=400
        )
        assert low < mean(values) < high

    def test_empty_sample_raises(self):
        with pytest.raises(InsufficientData):
            bootstrap_ci([], lambda s: 0.0, seed="z", resamples=10)

    def test_all_degenerate_resamples_raise_rather_than_fabricate(self):
        def always_degenerate(sample):
            raise InsufficientData("nope")

        with pytest.raises(InsufficientData):
            bootstrap_ci([1.0, 2.0], always_degenerate, seed="z", resamples=10)


class TestLabelledVerdict:
    def test_requires_a_named_corpus(self):
        with pytest.raises(ValueError):
            LabelledVerdict("F1", "  ", "false_positive", 0.9, "false_positive")

    def test_rejects_unknown_labels(self):
        with pytest.raises(ValueError):
            LabelledVerdict("F1", CORPUS, "maybe", 0.9, "false_positive")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            LabelledVerdict("F1", CORPUS, "false_positive", 0.9, "needs_human")  # type: ignore[arg-type]

    def test_rejects_out_of_range_confidence(self):
        with pytest.raises(ValueError):
            LabelledVerdict("F1", CORPUS, "false_positive", 1.4, "false_positive")

    def test_needs_human_is_absent_not_wrong(self):
        row = LabelledVerdict("F1", CORPUS, "needs_human", 0.5, "true_positive")
        assert not row.is_decidable
        assert not row.correct
        assert not row.says_false_positive

    def test_unparsed_is_absent_not_wrong(self):
        row = LabelledVerdict(
            "F1", CORPUS, "unparsed", 0.0, "true_positive", status="schema_invalid"
        )
        assert not row.is_decidable
        assert not row.correct

    def test_valid_row_scores_correctness(self):
        row = LabelledVerdict("F1", CORPUS, "false_positive", 0.9, "false_positive")
        assert row.is_decidable and row.correct and row.says_false_positive


class TestCorpusGuard:
    def test_one_corpus_accepts_a_single_name(self):
        rows = [LabelledVerdict("F1", CORPUS, "false_positive", 0.9, "false_positive")]
        assert one_corpus(rows) == CORPUS

    def test_one_corpus_refuses_a_blend(self):
        rows = [
            LabelledVerdict("F1", CORPUS, "false_positive", 0.9, "false_positive"),
            LabelledVerdict(
                "F2", OTHER_CORPUS, "false_positive", 0.9, "false_positive"
            ),
        ]
        with pytest.raises(BlendedCorpusError):
            one_corpus(rows)

    def test_split_by_corpus_is_sorted_and_complete(self):
        rows = [
            LabelledVerdict("F1", OTHER_CORPUS, "false_positive", 0.9, "false_positive"),
            LabelledVerdict("F2", CORPUS, "false_positive", 0.9, "false_positive"),
        ]
        out = split_by_corpus(rows)
        assert list(out) == sorted([CORPUS, OTHER_CORPUS])
        assert sum(len(v) for v in out.values()) == 2

    def test_empty_input_raises(self):
        with pytest.raises(InsufficientData):
            one_corpus([])


class TestCanonicalOrder:
    def test_is_independent_of_input_order(self):
        rows = [
            LabelledVerdict("B", CORPUS, "false_positive", 0.5, "false_positive"),
            LabelledVerdict("A", CORPUS, "true_positive", 0.9, "true_positive"),
        ]
        assert canonical_order(rows) == canonical_order(list(reversed(rows)))

    def test_orders_by_corpus_then_id(self):
        rows = [
            LabelledVerdict("Z", CORPUS, "false_positive", 0.5, "false_positive"),
            LabelledVerdict("A", OTHER_CORPUS, "true_positive", 0.9, "true_positive"),
        ]
        assert [r.finding_id for r in canonical_order(rows)] == ["A", "Z"]


class TestScoringUnit:
    @staticmethod
    def _runs(n_findings: int = 4, k: int = 5):
        return [
            LabelledVerdict(
                f"F{f}",
                CORPUS,
                "false_positive",
                0.9,
                "false_positive",
                run_index=run,
            )
            for f in range(n_findings)
            for run in range(k)
        ]

    def test_repeated_findings_are_counted(self):
        assert repeated_findings(self._runs(3, 5)) == {"F0": 5, "F1": 5, "F2": 5}

    def test_one_row_per_finding_picks_the_lowest_run_index(self):
        rows = one_row_per_finding(self._runs(3, 5))
        assert [r.finding_id for r in rows] == ["F0", "F1", "F2"]
        assert all(r.run_index == 0 for r in rows)

    def test_one_row_per_finding_can_name_the_run(self):
        rows = one_row_per_finding(self._runs(3, 5), run_index=3)
        assert all(r.run_index == 3 for r in rows)
        assert len(rows) == 3

    def test_selecting_a_run_that_does_not_exist_raises(self):
        with pytest.raises(InsufficientData):
            one_row_per_finding(self._runs(3, 5), run_index=9)

    def test_guard_refuses_a_pass_k_table_by_default(self):
        with pytest.raises(RepeatedRunsError) as excinfo:
            check_scoring_unit(
                self._runs(), what="test", allow_repeated_runs=False
            )
        assert "one_row_per_finding" in str(excinfo.value)

    def test_guard_waived_returns_a_note_rather_than_silence(self):
        notes = check_scoring_unit(
            self._runs(), what="test", allow_repeated_runs=True
        )
        assert notes and "narrower than the evidence" in notes[0]

    def test_guard_is_silent_when_the_unit_is_already_the_finding(self):
        rows = one_row_per_finding(self._runs())
        assert check_scoring_unit(rows, what="test", allow_repeated_runs=False) == ()


class TestFromAttempts:
    def test_builds_rows_and_skips_unlabelled_findings(self):
        attempts = [
            make_attempt(finding_id="F1", verdict="false_positive", confidence=0.8),
            make_attempt(finding_id="F2", verdict="true_positive"),
        ]
        rows = from_attempts(attempts, {"F1": "false_positive"})
        assert [r.finding_id for r in rows] == ["F1"]
        assert rows[0].confidence == pytest.approx(0.8)

    def test_failed_attempts_survive_as_unparsed_rows(self):
        attempts = [
            make_attempt(finding_id="F1", status="schema_invalid", verdict=None),
        ]
        rows = from_attempts(attempts, {"F1": "true_positive"})
        assert rows[0].model_verdict == "unparsed"
        assert rows[0].status == "schema_invalid"
        assert not rows[0].is_decidable

    def test_missing_label_can_be_made_fatal(self):
        attempts = [make_attempt(finding_id="F1")]
        with pytest.raises(InsufficientData):
            from_attempts(attempts, {}, on_missing_label="error")

    def test_attempt_without_a_corpus_refuses_to_default(self):
        attempt = make_attempt(finding_id="F1")
        stripped = type(attempt)(
            **{**attempt.to_dict(), "metadata": {}}
        )
        with pytest.raises(BlendedCorpusError):
            from_attempts([stripped], {"F1": "true_positive"})

    def test_explicit_corpus_of_overrides_metadata(self):
        attempts = [make_attempt(finding_id="F1", corpus=CORPUS)]
        rows = from_attempts(
            attempts, {"F1": "true_positive"}, corpus_of=lambda a: OTHER_CORPUS
        )
        assert rows[0].corpus == OTHER_CORPUS
