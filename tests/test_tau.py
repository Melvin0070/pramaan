"""Tau derivation, fold isolation, reliability and ECE (D3).

The centre of gravity of this file is `TestFoldIsolation`. Everything else here
checks arithmetic; those tests check the one property whose failure would make
every published calibration number wrong in the flattering direction, and they
are built so that they cannot pass vacuously.
"""

from __future__ import annotations

import pytest
from evals_fixtures import CORPUS, OTHER_CORPUS, poison, tau_corpus

from pramaan.calibration import tau as tau_mod
from pramaan.calibration.tau import (
    NEVER_ACHIEVED,
    _fit_threshold,
    derive,
    derive_per_corpus,
    expected_calibration_error,
    grouping_keys,
    kfold_indices,
    reliability_diagram,
)
from pramaan.evals.labels import LabelledVerdict
from pramaan.evals.stats import (
    BlendedCorpusError,
    InsufficientData,
    RepeatedRunsError,
)

SEED = "test-seed"


def _heldout(rows, *, repeat: int = 0, fold: int = 0, k: int = 5, repeats: int = 4):
    """The finding ids held out of one fold, rebuilt from the public API."""
    keys = grouping_keys(rows)
    splits = kfold_indices(keys, k=k, repeats=repeats, seed=SEED)
    return {keys[i] for i in splits[repeat][fold][1]}


# --------------------------------------------------------------------------- #
# Fold construction
# --------------------------------------------------------------------------- #

class TestKFoldIndices:
    def test_each_repeat_is_a_partition(self):
        keys = [f"k{i}" for i in range(37)]
        for repeat in kfold_indices(keys, k=5, repeats=4, seed=SEED):
            seen: list[int] = []
            for train, test in repeat:
                assert set(train).isdisjoint(test)
                assert set(train) | set(test) == set(range(37))
                seen.extend(test)
            # every index tested exactly once per repeat
            assert sorted(seen) == list(range(37))

    def test_fold_sizes_differ_by_at_most_one(self):
        keys = [f"k{i}" for i in range(37)]
        for repeat in kfold_indices(keys, k=5, repeats=3, seed=SEED):
            sizes = sorted(len(test) for _, test in repeat)
            assert sizes[-1] - sizes[0] <= 1
            assert sum(sizes) == 37

    def test_repeats_are_different_permutations(self):
        keys = [f"k{i}" for i in range(50)]
        repeats = kfold_indices(keys, k=5, repeats=5, seed=SEED)
        first_folds = {repeat[0][1] for repeat in repeats}
        assert len(first_folds) > 1, "repeats collapsed onto one permutation"

    def test_seed_is_the_whole_permutation(self):
        keys = [f"k{i}" for i in range(50)]
        a = kfold_indices(keys, k=5, repeats=2, seed="a")
        b = kfold_indices(keys, k=5, repeats=2, seed="b")
        assert a == kfold_indices(keys, k=5, repeats=2, seed="a")
        assert a != b

    def test_refuses_more_folds_than_rows(self):
        with pytest.raises(InsufficientData):
            kfold_indices(["a", "b"], k=5, repeats=1, seed=SEED)

    def test_rejects_degenerate_k(self):
        with pytest.raises(ValueError):
            kfold_indices(["a", "b", "c"], k=1, repeats=1, seed=SEED)


# --------------------------------------------------------------------------- #
# Fold isolation — the headline risk
# --------------------------------------------------------------------------- #

class TestFoldIsolation:
    """Tau fitted for a fold must not have seen that fold's labels.

    Three independent angles, because a single angle here would be easy to
    satisfy accidentally:

      1. structural — instrument the fitter and check what it was handed;
      2. behavioural — corrupt one fold's labels and show its tau does not move;
      3. non-vacuity — show the same corruption *does* move every other fold's
         tau, and does move a fit over the whole corpus.

    Test 2 alone would pass against an implementation that ignored the data
    entirely. Test 3 is what makes test 2 mean something.
    """

    def test_fitter_never_receives_a_heldout_row(self, monkeypatch):
        rows = tau_corpus()
        keys = grouping_keys(rows)
        expected = kfold_indices(keys, k=5, repeats=3, seed=SEED)

        seen: list[set[str]] = []
        real = tau_mod._fit_threshold

        def spy(train, **kwargs):
            seen.append({row.finding_id for row in train})
            return real(train, **kwargs)

        monkeypatch.setattr(tau_mod, "_fit_threshold", spy)
        derive(rows, k=5, repeats=3, seed=SEED)

        flat = [fold for repeat in expected for fold in repeat]
        assert len(seen) == len(flat) == 15
        for train_ids, (train_idx, test_idx) in zip(seen, flat):
            heldout = {keys[i] for i in test_idx}
            assert train_ids.isdisjoint(heldout), (
                "the fitter was handed a held-out row"
            )
            assert train_ids == {keys[i] for i in train_idx}

    def test_repeated_runs_of_one_finding_never_straddle_a_fold(self, monkeypatch):
        """Grouped splitting. Five verdicts on the same defect are near-copies;
        putting four in training and one in test is not cross-validation."""
        rows = []
        for f in range(20):
            for run in range(5):
                rows.append(
                    LabelledVerdict(
                        finding_id=f"G{f:02d}",
                        corpus=CORPUS,
                        model_verdict="false_positive",
                        confidence=round(0.30 + f * 0.03, 4),
                        true_label="false_positive" if f % 4 else "true_positive",
                        run_index=run,
                    )
                )
        keys = grouping_keys(rows)
        assert len(keys) == 20

        seen: list[set[str]] = []
        real = tau_mod._fit_threshold

        def spy(train, **kwargs):
            seen.append({row.finding_id for row in train})
            return real(train, **kwargs)

        monkeypatch.setattr(tau_mod, "_fit_threshold", spy)
        result = derive(rows, k=5, repeats=2, seed=SEED, allow_repeated_runs=True)
        assert any("scored at row level" in n for n in result.notes)

        flat = [
            fold for repeat in kfold_indices(keys, k=5, repeats=2, seed=SEED)
            for fold in repeat
        ]
        for train_ids, (_, test_idx) in zip(seen, flat):
            heldout = {keys[i] for i in test_idx}
            assert train_ids.isdisjoint(heldout)
            assert len(train_ids) == 16

    def test_corrupting_a_folds_labels_does_not_move_its_tau(self):
        rows = tau_corpus()
        heldout_ids = _heldout(rows)

        clean = derive(rows, k=5, repeats=4, seed=SEED)
        poisoned = derive(poison(rows, heldout_ids), k=5, repeats=4, seed=SEED)

        target_clean = next(
            f for f in clean.folds if f.repeat == 0 and f.fold == 0
        )
        target_poisoned = next(
            f for f in poisoned.folds if f.repeat == 0 and f.fold == 0
        )
        assert target_clean.tau == target_poisoned.tau
        assert target_clean.achieved == target_poisoned.achieved
        assert target_clean.train_support == target_poisoned.train_support

    def test_the_same_corruption_moves_every_other_fold(self):
        """Non-vacuity. If this fails, the test above proves nothing."""
        rows = tau_corpus()
        heldout_ids = _heldout(rows)

        clean = derive(rows, k=5, repeats=4, seed=SEED)
        poisoned = derive(poison(rows, heldout_ids), k=5, repeats=4, seed=SEED)

        moved = [
            (c.repeat, c.fold)
            for c, p in zip(clean.folds, poisoned.folds)
            if c.tau != p.tau
        ]
        assert (0, 0) not in moved
        # Those rows are training data for every other fold, so every other fold
        # must react. Anything less means the poison was too weak to detect
        # leakage with.
        assert len(moved) == len(clean.folds) - 1

    def test_positive_control_the_poison_is_potent(self):
        """Fitting on the whole corpus, poisoned rows included, must change the
        answer — otherwise 'the fold's tau did not move' is uninformative."""
        rows = tau_corpus()
        heldout_ids = _heldout(rows)

        clean_fit = _fit_threshold(rows, target_precision=0.95, min_support=5)
        poisoned_fit = _fit_threshold(
            poison(rows, heldout_ids), target_precision=0.95, min_support=5
        )
        assert clean_fit.achieved
        # Not merely "different": the poisoned fit must be different by a wide
        # margin, so that a leak of even part of the held-out fold would be
        # visible in the fold tau rather than lost in rounding.
        assert abs(poisoned_fit.tau - clean_fit.tau) >= 0.2

    def test_heldout_precision_is_scored_on_unseen_rows(self):
        """A generalisation gap must be visible. Scoring on the training rows
        would make every fold clear the target by construction."""
        result = derive(tau_corpus(), k=5, repeats=10, seed=SEED)
        train = [f.train_precision for f in result.folds if f.train_precision]
        heldout = [
            f.heldout_precision for f in result.folds if f.heldout_precision
        ]
        assert all(p >= result.target_precision for p in train)
        assert sum(heldout) / len(heldout) < sum(train) / len(train)
        assert min(heldout) < result.target_precision, (
            "no fold under-performed out of sample; tau is being scored on the "
            "rows it was fitted on"
        )


# --------------------------------------------------------------------------- #
# Threshold fitting
# --------------------------------------------------------------------------- #

class TestFitThreshold:
    def test_min_support_blocks_a_single_lucky_row(self):
        rows = [
            LabelledVerdict("A", CORPUS, "false_positive", 0.99, "false_positive"),
            *[
                LabelledVerdict(
                    f"B{i}", CORPUS, "false_positive", 0.5, "true_positive"
                )
                for i in range(10)
            ],
        ]
        fit = _fit_threshold(rows, target_precision=0.95, min_support=5)
        assert not fit.achieved
        assert fit.tau == NEVER_ACHIEVED

    def test_threshold_must_hold_continuously_above_itself(self):
        """A single clean bucket low down does not open the gate for the mess
        above it."""
        rows = [
            # 0.90-0.99: mostly wrong
            *[
                LabelledVerdict(
                    f"H{i}",
                    CORPUS,
                    "false_positive",
                    0.90 + i * 0.01,
                    "true_positive" if i % 2 else "false_positive",
                )
                for i in range(10)
            ],
            # 0.50-0.59: all genuinely false positives
            *[
                LabelledVerdict(
                    f"L{i}", CORPUS, "false_positive", 0.50 + i * 0.01, "false_positive"
                )
                for i in range(10)
            ],
        ]
        fit = _fit_threshold(rows, target_precision=0.95, min_support=5)
        # Precision at 0.50 pooled is 15/20 = 0.75, so no threshold qualifies.
        assert not fit.achieved

    def test_no_false_positive_verdicts_fails_closed(self):
        rows = [
            LabelledVerdict(f"T{i}", CORPUS, "true_positive", 0.9, "true_positive")
            for i in range(10)
        ]
        fit = _fit_threshold(rows, target_precision=0.95, min_support=5)
        assert fit.tau == NEVER_ACHIEVED and not fit.achieved

    def test_finds_the_knee_in_a_separable_corpus(self):
        fit = _fit_threshold(tau_corpus(), target_precision=0.95, min_support=5)
        assert fit.achieved
        assert 0.45 <= fit.tau <= 0.65


# --------------------------------------------------------------------------- #
# derive
# --------------------------------------------------------------------------- #

class TestDerive:
    def test_reports_a_spread_and_never_a_bare_tau(self):
        result = derive(tau_corpus(), k=5, repeats=10, seed=SEED)
        assert not hasattr(result, "tau"), (
            "TauResult grew a point estimate; D3 forbids publishing one"
        )
        assert len(result.folds) == 50
        assert result.spread.n == 50
        assert result.spread.minimum <= result.spread.median <= result.spread.maximum
        assert result.spread.iqr >= 0.0
        assert "median" in result.spread.render()

    def test_recommended_tau_is_conservative(self):
        result = derive(tau_corpus(), k=5, repeats=10, seed=SEED)
        assert result.recommended_tau() >= result.spread.median

    def test_recommended_tau_refuses_when_folds_did_not_achieve_target(self):
        rows = tau_corpus()
        wrecked = poison(rows, _heldout(rows))
        result = derive(wrecked, k=5, repeats=4, seed=SEED)
        assert result.achieved_fraction < 0.9
        with pytest.raises(InsufficientData):
            result.recommended_tau()
        assert result.to_dict()["recommended_tau_p75"] is None
        assert "UNAVAILABLE" in result.render()

    def test_is_deterministic_and_order_independent(self):
        rows = tau_corpus()
        shuffled = list(reversed(rows))
        a = derive(rows, k=5, repeats=3, seed=SEED)
        b = derive(shuffled, k=5, repeats=3, seed=SEED)
        assert [f.tau for f in a.folds] == [f.tau for f in b.folds]

    def test_refuses_to_blend_corpora(self):
        rows = tau_corpus() + tau_corpus(corpus=OTHER_CORPUS)
        with pytest.raises(BlendedCorpusError):
            derive(rows, k=5, repeats=2, seed=SEED)

    def test_per_corpus_returns_one_result_each(self):
        rows = tau_corpus() + tau_corpus(corpus=OTHER_CORPUS)
        out = derive_per_corpus(rows, k=5, repeats=2, seed=SEED)
        assert set(out) == {CORPUS, OTHER_CORPUS}

    def test_flags_an_underpowered_corpus(self):
        rows = tau_corpus(n_fp=16, n_tp=4)
        result = derive(rows, k=5, repeats=2, seed=SEED)
        assert result.underpowered
        assert any("underpowered" in n for n in result.notes)

    def test_held_out_denominator_is_one_repeats_worth(self):
        """Ten repeats must not multiply the sample size by ten."""
        rows = tau_corpus()
        one = derive(rows, k=5, repeats=1, seed=SEED)
        ten = derive(rows, k=5, repeats=10, seed=SEED)
        assert ten.heldout_precision.n <= one.heldout_precision.n * 2
        assert "do not enlarge n" in ten.heldout_precision.note

    def test_a_pass_k_table_needs_an_explicit_opt_in(self):
        rows = [
            LabelledVerdict(
                f"F{i:02d}",
                CORPUS,
                "false_positive",
                round(0.30 + i * 0.02, 4),
                "false_positive" if i % 4 else "true_positive",
                run_index=run,
            )
            for i in range(20)
            for run in range(5)
        ]
        with pytest.raises(RepeatedRunsError):
            derive(rows, k=5, repeats=2, seed=SEED)

    def test_rejects_empty_input(self):
        with pytest.raises(InsufficientData):
            derive([], k=5, repeats=2, seed=SEED)


# --------------------------------------------------------------------------- #
# Reliability and ECE
# --------------------------------------------------------------------------- #

def _calibrated(per_bin: int = 20, corpus: str = CORPUS) -> list[LabelledVerdict]:
    """Perfectly calibrated: in the bin centred on p, exactly p of the rows are
    right."""
    rows: list[LabelledVerdict] = []
    for b in range(10):
        centre = round(b / 10 + 0.05, 3)
        correct = round(centre * per_bin)
        for i in range(per_bin):
            rows.append(
                LabelledVerdict(
                    finding_id=f"C{b}-{i}",
                    corpus=corpus,
                    model_verdict="false_positive",
                    confidence=centre,
                    true_label="false_positive" if i < correct else "true_positive",
                )
            )
    return rows


class TestReliability:
    def test_perfect_calibration_scores_near_zero_ece(self):
        assert expected_calibration_error(_calibrated()) < 0.01

    def test_systematic_overconfidence_is_caught(self):
        rows = [
            LabelledVerdict(
                f"O{i}",
                CORPUS,
                "false_positive",
                0.95,
                "false_positive" if i < 50 else "true_positive",
            )
            for i in range(100)
        ]
        diagram = reliability_diagram(rows)
        assert diagram.ece == pytest.approx(0.45, abs=0.01)
        assert diagram.bins[9].gap == pytest.approx(0.45, abs=0.01)

    def test_bins_carry_counts_and_intervals(self):
        diagram = reliability_diagram(_calibrated(per_bin=20))
        occupied = [b for b in diagram.bins if b.n]
        assert len(occupied) == 10
        for b in occupied:
            assert b.n == 20
            assert b.accuracy.low is not None and b.accuracy.high is not None

    def test_small_bins_are_flagged_and_excluded_from_mce(self):
        rows = _calibrated(per_bin=20)
        # one extra, lonely bin member at a wildly miscalibrated confidence
        rows = [r for r in rows if r.confidence != 0.05]
        rows.append(
            LabelledVerdict("lonely", CORPUS, "false_positive", 0.05, "false_positive")
        )
        diagram = reliability_diagram(rows, min_bin_n=5)
        assert 0 in diagram.underpowered_bins
        assert diagram.mce < 0.9  # the lonely bin's gap of ~0.95 is ignored
        assert any("underpowered" in n or "fewer than" in n for n in diagram.notes)

    def test_unparsed_and_needs_human_rows_are_excluded_but_counted(self):
        rows = _calibrated(per_bin=10)
        rows.append(
            LabelledVerdict(
                "U1", CORPUS, "unparsed", 0.0, "true_positive", status="schema_invalid"
            )
        )
        rows.append(
            LabelledVerdict("U2", CORPUS, "needs_human", 0.4, "true_positive")
        )
        diagram = reliability_diagram(rows)
        assert diagram.n_excluded == 2
        assert diagram.excluded_by_status["schema_invalid"] == 1
        assert diagram.excluded_by_status["needs_human"] == 1
        assert diagram.n_scored == 100

    def test_bootstrap_interval_is_seeded_and_reproducible(self):
        rows = _calibrated(per_bin=20)
        a = reliability_diagram(rows, bootstrap=200, seed="s1")
        b = reliability_diagram(rows, bootstrap=200, seed="s1")
        c = reliability_diagram(rows, bootstrap=200, seed="s2")
        assert a.ece_ci == b.ece_ci
        assert a.ece_ci != c.ece_ci
        assert a.ece_ci is not None
        assert 0.0 <= a.ece_ci[0] <= a.ece_ci[1]
        assert a.ece <= a.ece_ci[1]

    def test_upward_bias_of_the_ece_bootstrap_is_declared(self):
        """Near-perfect calibration puts the whole bootstrap distribution above
        the plug-in ECE, because ECE sums absolute deviations and cannot go
        below zero. That looks like a bug in a report, so the result says it."""
        diagram = reliability_diagram(_calibrated(per_bin=20), bootstrap=200)
        assert diagram.ece_ci is not None
        assert diagram.ece_ci[0] > diagram.ece
        assert any("upward-" in n for n in diagram.notes)

    def test_missing_interval_is_announced_not_hidden(self):
        diagram = reliability_diagram(_calibrated(per_bin=20), bootstrap=0)
        assert diagram.ece_ci is None
        assert "do not publish this bare" in diagram.render()

    def test_refuses_to_blend_corpora(self):
        rows = _calibrated(per_bin=5) + _calibrated(per_bin=5, corpus=OTHER_CORPUS)
        with pytest.raises(BlendedCorpusError):
            reliability_diagram(rows)

    def test_all_undecidable_raises_rather_than_dividing_by_zero(self):
        rows = [
            LabelledVerdict(
                f"U{i}",
                CORPUS,
                "unparsed",
                0.0,
                "true_positive",
                status="schema_invalid",
            )
            for i in range(5)
        ]
        with pytest.raises(InsufficientData):
            reliability_diagram(rows)
        with pytest.raises(InsufficientData):
            expected_calibration_error(rows)

    def test_confidence_of_one_lands_in_the_top_bin(self):
        rows = [
            LabelledVerdict(f"T{i}", CORPUS, "false_positive", 1.0, "false_positive")
            for i in range(10)
        ]
        diagram = reliability_diagram(rows)
        assert diagram.bins[9].n == 10
        assert diagram.ece == pytest.approx(0.0)
