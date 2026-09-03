"""FP-class precision/recall/F1 and the miss rate under an asymmetric cost."""

from __future__ import annotations

import pytest
from evals_fixtures import CORPUS, OTHER_CORPUS

from pramaan.evals.labels import LabelledVerdict, one_row_per_finding
from pramaan.evals.metrics import (
    MISS_WEIGHT,
    confusion,
    fp_class_metrics,
    fp_class_metrics_per_corpus,
)
from pramaan.evals.stats import (
    BlendedCorpusError,
    InsufficientData,
    RepeatedRunsError,
)


def _rows(
    *,
    correct_close: int = 10,
    misses: int = 2,
    needless: int = 5,
    correct_escalation: int = 8,
    miss_confidence: float = 0.9,
    corpus: str = CORPUS,
) -> list[LabelledVerdict]:
    rows: list[LabelledVerdict] = []
    i = 0

    def add(model: str, truth: str, confidence: float) -> None:
        nonlocal i
        rows.append(
            LabelledVerdict(f"F{i:03d}", corpus, model, confidence, truth)  # type: ignore[arg-type]
        )
        i += 1

    for _ in range(correct_close):
        add("false_positive", "false_positive", 0.9)
    for _ in range(misses):
        add("false_positive", "true_positive", miss_confidence)
    for _ in range(needless):
        add("true_positive", "false_positive", 0.8)
    for _ in range(correct_escalation):
        add("true_positive", "true_positive", 0.95)
    return rows


class TestConfusion:
    def test_cells_are_named_by_what_they_cost(self):
        m = confusion(_rows())
        assert m.correct_auto_close == 10
        assert m.miss == 2
        assert m.needless_review == 5
        assert m.correct_escalation == 8
        assert m.n == 25
        assert m.n_real_defects == 10
        assert m.n_false_positives == 15

    def test_needs_human_is_not_a_miss(self):
        rows = _rows(misses=0) + [
            LabelledVerdict("NH", CORPUS, "needs_human", 0.4, "true_positive")
        ]
        m = confusion(rows)
        assert m.miss == 0
        assert m.undecidable_on_real == 1
        assert m.correct_escalation == 9

    def test_unparsed_is_not_a_miss(self):
        rows = _rows(misses=0) + [
            LabelledVerdict(
                "U", CORPUS, "unparsed", 0.0, "true_positive", status="schema_invalid"
            )
        ]
        m = confusion(rows)
        assert m.miss == 0
        assert m.undecidable_on_real == 1

    def test_tau_withholds_low_confidence_auto_closes(self):
        rows = _rows(miss_confidence=0.5)
        ungated = confusion(rows)
        gated = confusion(rows, tau=0.7)
        assert ungated.miss == 2
        assert gated.miss == 0
        assert gated.below_tau_on_real == 2
        assert gated.correct_escalation == 10

    def test_rejects_a_tau_outside_the_unit_interval(self):
        with pytest.raises(ValueError):
            confusion(_rows(), tau=1.5)


class TestFpClassMetrics:
    def test_precision_recall_f1(self):
        r = fp_class_metrics(_rows())
        assert r.precision.point == pytest.approx(10 / 12)
        assert r.recall.point == pytest.approx(10 / 15)
        assert r.f1 == pytest.approx(0.7407, abs=1e-4)

    def test_miss_rate_is_over_real_defects_only(self):
        r = fp_class_metrics(_rows())
        assert r.miss_rate.successes == 2 and r.miss_rate.n == 10
        assert r.miss_rate.point == pytest.approx(0.2)
        assert r.needless_review_rate.point == pytest.approx(5 / 15)

    def test_asymmetric_cost_weights_a_miss_four_to_one(self):
        r = fp_class_metrics(_rows())
        assert MISS_WEIGHT == 4.0
        assert r.cost.from_misses == pytest.approx(8.0)
        assert r.cost.from_reviews == pytest.approx(5.0)
        assert r.cost.total == pytest.approx(13.0)
        assert r.cost.per_finding == pytest.approx(13 / 25)
        assert r.cost.miss_share == pytest.approx(8 / 13)

    def test_baselines_make_the_harness_falsifiable(self):
        r = fp_class_metrics(_rows())
        assert r.cost.review_everything == pytest.approx(15.0)
        assert r.cost.close_everything == pytest.approx(40.0)
        assert r.cost.vs_review_everything == pytest.approx(13 / 15)

    def test_a_harness_worse_than_reviewing_everything_says_so(self):
        r = fp_class_metrics(_rows(correct_close=1, misses=8, needless=1))
        assert r.cost.vs_review_everything > 1.0
        assert any("not earning its place" in n for n in r.notes)

    def test_gating_at_tau_changes_the_reported_matrix(self):
        rows = _rows(miss_confidence=0.5)
        ungated = fp_class_metrics(rows)
        gated = fp_class_metrics(rows, tau=0.7)
        assert ungated.miss_rate.successes == 2
        assert gated.miss_rate.successes == 0
        assert gated.tau == 0.7
        assert any("the gate withheld" in n for n in gated.notes)
        assert "tau=0.700" in gated.render()

    def test_small_denominators_are_flagged_not_divided(self):
        rows = _rows(correct_close=2, misses=1, needless=1, correct_escalation=1)
        r = fp_class_metrics(rows)
        assert not r.miss_rate.reportable
        assert any("too few to compare against the 2% CI gate" in n for n in r.notes)
        with pytest.raises(InsufficientData):
            r.miss_rate.require_point()

    def test_undecidable_rows_are_reported(self):
        rows = _rows() + [
            LabelledVerdict("NH", CORPUS, "needs_human", 0.4, "true_positive")
        ]
        r = fp_class_metrics(rows)
        assert any("needs_human or unparsed" in n for n in r.notes)

    def test_refuses_to_blend_corpora(self):
        rows = _rows() + _rows(corpus=OTHER_CORPUS)
        with pytest.raises(BlendedCorpusError):
            fp_class_metrics(rows)

    def test_per_corpus_reports_both_separately(self):
        rows = _rows() + _rows(corpus=OTHER_CORPUS, misses=6)
        out = fp_class_metrics_per_corpus(rows)
        assert set(out) == {CORPUS, OTHER_CORPUS}
        assert out[CORPUS].miss_rate.successes == 2
        assert out[OTHER_CORPUS].miss_rate.successes == 6

    def test_f1_is_undefined_rather_than_zero_when_nothing_is_predicted(self):
        rows = [
            LabelledVerdict(f"T{i}", CORPUS, "true_positive", 0.9, "true_positive")
            for i in range(5)
        ]
        r = fp_class_metrics(rows)
        assert r.precision.point is None
        assert r.f1 is None
        assert "undefined" in r.render()

    def test_five_runs_of_one_finding_are_not_five_findings(self):
        """The miss rate is gated at 2%; a fivefold denominator sails under it."""
        rows = [
            LabelledVerdict(
                f"F{i}", CORPUS, "false_positive", 0.9, "false_positive",
                run_index=run,
            )
            for i in range(10)
            for run in range(5)
        ]
        with pytest.raises(RepeatedRunsError):
            fp_class_metrics(rows)
        waived = fp_class_metrics(rows, allow_repeated_runs=True)
        assert waived.matrix.n == 50
        assert any("narrower than the evidence" in n for n in waived.notes)
        reduced = fp_class_metrics(one_row_per_finding(rows))
        assert reduced.matrix.n == 10
        assert reduced.precision.width > waived.precision.width

    def test_rejects_empty_input(self):
        with pytest.raises(InsufficientData):
            fp_class_metrics([])

    def test_rejects_a_non_positive_miss_weight(self):
        with pytest.raises(ValueError):
            fp_class_metrics(_rows(), miss_weight=0)

    def test_to_dict_round_trips_the_numbers(self):
        d = fp_class_metrics(_rows()).to_dict()
        assert d["confusion"]["miss"] == 2
        assert d["cost"]["miss_weight"] == 4.0
        assert d["miss_rate"]["n"] == 10
