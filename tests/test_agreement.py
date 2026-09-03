"""Intra-rater agreement, the wash-out, and the statistic that is not kappa (D18)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pramaan.evals import agreement as agreement_mod
from pramaan.evals.agreement import (
    DEGENERATE_PREVALENCE,
    IntraRaterAgreement,
    ModelHumanAgreement,
    Rating,
    WashoutViolation,
    intra_rater_kappa,
    model_vs_human_agreement,
)
from pramaan.evals.stats import EvalError, InsufficientData

PASS_ONE_AT = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)


def _pass(labels: dict[str, str], *, days: int = 14, session: str = "p1"):
    at = PASS_ONE_AT + timedelta(days=days)
    return [
        Rating(item_id=k, label=v, rated_at=at, corpus="php-121", session=session)
        for k, v in labels.items()
    ]


def _two_by_two(a: int, b: int, c: int, d: int):
    """yes/yes=a, yes/no=b, no/yes=c, no/no=d."""
    first: dict[str, str] = {}
    second: dict[str, str] = {}
    i = 0
    for count, (one, two) in (
        (a, ("tp", "tp")),
        (b, ("tp", "fp")),
        (c, ("fp", "tp")),
        (d, ("fp", "fp")),
    ):
        for _ in range(count):
            first[f"I{i:03d}"] = one
            second[f"I{i:03d}"] = two
            i += 1
    return _pass(first, days=0), _pass(second, days=14, session="p2")


class TestIntraRaterKappa:
    def test_matches_the_textbook_value(self):
        one, two = _two_by_two(40, 10, 10, 40)
        result = intra_rater_kappa(one, two, bootstrap=0)
        assert result.intra_rater_observed_agreement.point == pytest.approx(0.8)
        assert result.intra_rater_expected_agreement == pytest.approx(0.5)
        assert result.intra_rater_kappa == pytest.approx(0.6)

    def test_perfect_self_consistency_is_one(self):
        one, two = _two_by_two(50, 0, 0, 50)
        assert intra_rater_kappa(one, two, bootstrap=0).intra_rater_kappa == 1.0

    def test_records_which_items_were_relabelled(self):
        one, two = _two_by_two(40, 10, 10, 40)
        result = intra_rater_kappa(one, two, bootstrap=0)
        assert len(result.intra_rater_flips) == 20
        assert all(a != b for _, a, b in result.intra_rater_flips)

    def test_washout_under_seven_days_raises(self):
        one = _pass({"A": "tp", "B": "fp"}, days=0)
        two = _pass({"A": "tp", "B": "fp"}, days=3, session="p2")
        with pytest.raises(WashoutViolation):
            intra_rater_kappa(one, two)

    def test_washout_violation_can_be_recorded_instead_of_raised(self):
        one = _pass({f"I{i}": "tp" if i % 2 else "fp" for i in range(30)}, days=0)
        two = _pass(
            {f"I{i}": "tp" if i % 2 else "fp" for i in range(30)},
            days=3,
            session="p2",
        )
        result = intra_rater_kappa(one, two, strict=False, bootstrap=0)
        assert not result.intra_rater_washout_satisfied
        assert len(result.intra_rater_washout_violations) == 30
        assert any("not publishable" in n for n in result.notes)

    def test_exactly_seven_days_satisfies_the_washout(self):
        one = _pass({f"I{i}": "tp" if i % 2 else "fp" for i in range(30)}, days=0)
        two = _pass(
            {f"I{i}": "tp" if i % 2 else "fp" for i in range(30)},
            days=7,
            session="p2",
        )
        result = intra_rater_kappa(one, two, bootstrap=0)
        assert result.intra_rater_washout_satisfied
        assert result.intra_rater_washout_days_min == pytest.approx(7.0)

    def test_degenerate_marginals_give_none_not_zero(self):
        one, two = _two_by_two(0, 0, 0, 60)
        result = intra_rater_kappa(one, two, bootstrap=0)
        assert result.intra_rater_kappa is None
        assert result.intra_rater_degenerate
        assert "undefined" in result.render()

    def test_high_prevalence_is_flagged_as_uninterpretable(self):
        """The reason weighted kappa on severity was dropped: at 94% one class
        the coefficient collapses whatever the agreement is."""
        one, two = _two_by_two(2, 1, 1, 96)
        result = intra_rater_kappa(one, two, bootstrap=0)
        assert result.intra_rater_prevalence >= DEGENERATE_PREVALENCE
        assert result.intra_rater_degenerate
        assert result.intra_rater_observed_agreement.point == pytest.approx(0.98)
        assert any("weighted kappa" in n for n in result.notes)

    def test_bootstrap_interval_is_seeded(self):
        one, two = _two_by_two(40, 10, 10, 40)
        a = intra_rater_kappa(one, two, bootstrap=200, seed="s")
        b = intra_rater_kappa(one, two, bootstrap=200, seed="s")
        assert a.intra_rater_kappa_ci95 == b.intra_rater_kappa_ci95
        assert a.intra_rater_kappa_ci95 is not None
        low, high = a.intra_rater_kappa_ci95
        assert low < 0.6 < high

    def test_naive_timestamps_are_rejected(self):
        with pytest.raises(ValueError):
            Rating("A", "tp", datetime(2026, 5, 1, 10, 0))

    def test_duplicate_label_in_one_pass_is_an_error(self):
        at = PASS_ONE_AT
        one = [Rating("A", "tp", at), Rating("A", "fp", at)]
        two = _pass({"A": "tp"}, days=14)
        with pytest.raises(EvalError):
            intra_rater_kappa(one, two)

    def test_no_overlap_raises(self):
        one = _pass({"A": "tp"}, days=0)
        two = _pass({"B": "tp"}, days=14)
        with pytest.raises(InsufficientData):
            intra_rater_kappa(one, two)

    def test_items_in_only_one_pass_are_dropped_and_reported(self):
        one, two = _two_by_two(20, 5, 5, 20)
        one = one + _pass({"EXTRA": "tp"}, days=0)
        result = intra_rater_kappa(one, two, bootstrap=0)
        assert result.intra_rater_n == 50
        assert any("only one pass" in n for n in result.notes)

    def test_small_n_is_flagged(self):
        one, two = _two_by_two(4, 1, 1, 4)
        result = intra_rater_kappa(one, two, bootstrap=0, min_n=20)
        assert any("compared against a fixed threshold" in n for n in result.notes)


class TestNamingDiscipline:
    def test_every_measurement_field_is_named_intra_rater(self):
        contextual = {"corpus", "notes"}
        for name in IntraRaterAgreement.__dataclass_fields__:
            if name in contextual:
                continue
            assert name.startswith("intra_rater_"), (
                f"{name!r} would be read as inter-rater reliability"
            )

    def test_serialised_output_names_the_statistic(self):
        one, two = _two_by_two(40, 10, 10, 40)
        d = intra_rater_kappa(one, two, bootstrap=0).to_dict()
        assert d["statistic"] == "intra_rater_cohens_kappa"
        assert "not inter-rater" in d["interpretation"]

    def test_the_module_exposes_no_weighted_kappa(self):
        """Dropped as degenerate at 94% one CWE; a future refactor must not
        quietly reintroduce it."""
        assert not hasattr(agreement_mod, "weighted_kappa")
        assert not any(
            "weighted" in name for name in agreement_mod.__all__
        )

    def test_model_human_result_has_no_kappa_anywhere(self):
        for name in ModelHumanAgreement.__dataclass_fields__:
            assert "kappa" not in name
        one = _pass({"A": "tp", "B": "fp"}, days=0)
        two = _pass({"A": "tp", "B": "fp"}, days=0, session="h")
        d = model_vs_human_agreement(one, two, min_n=1).to_dict()
        assert not any("kappa" in key for key in d)
        assert "not kappa" in d["interpretation"]


class TestModelVsHuman:
    def test_reports_raw_agreement_with_an_interval(self):
        human = _pass({f"I{i}": "tp" if i < 30 else "fp" for i in range(60)})
        model = _pass(
            {f"I{i}": ("tp" if i < 25 else "fp") for i in range(60)}, session="m"
        )
        result = model_vs_human_agreement(model, human)
        assert result.n == 60
        assert result.raw_agreement.successes == 55
        assert result.raw_agreement.low is not None

    def test_needs_human_is_excluded_from_both_sides(self):
        human = _pass({f"I{i}": "tp" for i in range(10)})
        labels = {f"I{i}": "tp" for i in range(8)}
        labels["I8"] = "needs_human"
        labels["I9"] = "unparsed"
        model = _pass(labels, session="m")
        result = model_vs_human_agreement(model, human, min_n=1)
        assert result.n == 8
        assert result.excluded_undecidable == 2
        assert result.raw_agreement.point == 1.0
        assert "outside this measurement" in result.notes[0]

    def test_per_class_agreement_is_broken_out(self):
        human = _pass({f"I{i}": "tp" if i < 10 else "fp" for i in range(20)})
        model = _pass(
            {f"I{i}": "fp" for i in range(20)}, session="m"
        )
        result = model_vs_human_agreement(model, human, min_n=1)
        assert result.per_class["tp"].point == 0.0
        assert result.per_class["fp"].point == 1.0

    def test_all_undecidable_raises(self):
        human = _pass({f"I{i}": "tp" for i in range(5)})
        model = _pass({f"I{i}": "needs_human" for i in range(5)}, session="m")
        with pytest.raises(InsufficientData):
            model_vs_human_agreement(model, human)

    def test_render_states_it_is_not_chance_corrected(self):
        human = _pass({f"I{i}": "tp" if i % 2 else "fp" for i in range(20)})
        model = _pass(
            {f"I{i}": "tp" if i % 2 else "fp" for i in range(20)}, session="m"
        )
        text = model_vs_human_agreement(model, human).render()
        assert "not chance-corrected" in text
        assert "never reported as kappa" in text
