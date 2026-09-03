"""Tiered orchestration: the CI replay reads the cache, the nightly run cannot."""

from __future__ import annotations

import pytest
from evals_fixtures import CORPUS, k_attempts, make_attempt

from pramaan.evals.injection import CONTROL_ARM, HARDENED_ARM, run_paired
from pramaan.evals.labels import LabelledVerdict
from pramaan.evals.metrics import fp_class_metrics
from pramaan.evals.runner import (
    CorpusReport,
    EpochLeakError,
    StaleEpochError,
    ci_suite,
    evaluate_gates,
    nightly_suite,
    stratified_subset,
)
from pramaan.evals.stats import EvalError, InsufficientData
from pramaan.store.verdict_cache import CachedVerdictStore
from test_injection import make_run_trial  # reuse the paired-run fake

CI_EPOCH = "epoch-ci-1"


def suite_corpus(
    *, n_findings: int = 40, run_epoch: str = CI_EPOCH, corpus: str = CORPUS
):
    attempts = []
    labels: dict[str, str] = {}
    for i in range(n_findings):
        finding_id = f"F{i:03d}"
        confidence = round(0.20 + i * (0.79 / (n_findings - 1)), 4)
        if i % 5 == 0:
            model, truth = "true_positive", "true_positive"
        else:
            model = "false_positive"
            truth = (
                "false_positive"
                if (confidence >= 0.60 or i % 3)
                else "true_positive"
            )
        labels[finding_id] = truth
        attempts.extend(
            k_attempts(
                finding_id,
                [model] * 5,
                confidence=confidence,
                run_epoch=run_epoch,
                corpus=corpus,
            )
        )
    return attempts, labels


class ReadTrap:
    """An `AttemptSink` that explodes on any read of a cached attempt.

    The nightly pass^k must not replay the cache (D19). Rather than counting
    calls after the fact, this makes a read impossible: the only survivable
    operations are `put` and `epochs`.
    """

    def __init__(self, store: CachedVerdictStore) -> None:
        self._store = store
        self.puts: list[tuple[str, object]] = []

    def put(self, fingerprint: str, attempt):
        self.puts.append((fingerprint, attempt))
        return self._store.put(fingerprint, attempt)

    def epochs(self) -> list[str]:
        return self._store.epochs()

    def get(self, *args, **kwargs):
        raise AssertionError("the nightly run read a cached attempt")

    def has(self, *args, **kwargs):
        raise AssertionError("the nightly run probed the cache")

    def attempts_for_fingerprint(self, *args, **kwargs):
        raise AssertionError("the nightly run read cached attempts")

    def all(self, *args, **kwargs):
        raise AssertionError("the nightly run enumerated the cache")


def fresh_runner(labels_source, *, epoch_override: str | None = None):
    """Produces k attempts stamped with whatever epoch it is given."""

    def runner(*, fingerprint: str, run_epoch: str, k: int):
        finding_id = fingerprint.removeprefix("fp-")
        return [
            make_attempt(
                finding_id=finding_id,
                fingerprint=fingerprint,
                run_index=i,
                verdict="false_positive",
                confidence=0.8,
                run_epoch=epoch_override or run_epoch,
            )
            for i in range(k)
        ]

    return runner


class TestStratifiedSubset:
    def test_is_deterministic(self):
        keys = [f"k{i:03d}" for i in range(100)]
        a = stratified_subset(keys, stratum_of=lambda k: k[-1], seed="s")
        b = stratified_subset(keys, stratum_of=lambda k: k[-1], seed="s")
        assert a == b

    def test_a_different_seed_picks_a_different_subset(self):
        keys = [f"k{i:03d}" for i in range(100)]
        a = stratified_subset(keys, stratum_of=lambda k: k[-1], seed="s")
        b = stratified_subset(keys, stratum_of=lambda k: k[-1], seed="t")
        assert a != b

    def test_every_stratum_is_represented(self):
        keys = [f"k{i:03d}" for i in range(100)]
        chosen = stratified_subset(
            keys, stratum_of=lambda k: k[-1], seed="s", fraction=0.1
        )
        assert {k[-1] for k in chosen} == {str(d) for d in range(10)}

    def test_a_thin_stratum_survives_a_small_fraction(self):
        keys = ["rare-1", *[f"common-{i}" for i in range(100)]]
        chosen = stratified_subset(
            keys,
            stratum_of=lambda k: k.split("-")[0],
            seed="s",
            fraction=0.05,
        )
        assert "rare-1" in chosen

    def test_empty_input_is_empty_output(self):
        assert stratified_subset([], stratum_of=lambda k: "x", seed="s") == ()

    def test_rejects_a_nonsense_fraction(self):
        with pytest.raises(ValueError):
            stratified_subset(["a"], stratum_of=lambda k: "x", seed="s", fraction=0)


class TestCiSuite:
    def test_reads_the_cache_and_scores_a_subset(self):
        """Positive control for the read path: without this, the nightly
        read-trap test could pass simply because nothing ever reads."""
        attempts, labels = suite_corpus()
        with CachedVerdictStore() as store:
            for attempt in attempts:
                store.put(attempt.fingerprint, attempt)
            assert store.count() == 200
            result = ci_suite(
                (c.attempt for c in store.all()), labels, fraction=0.5
            )
        assert result.tier == "ci"
        assert result.run_epoch is None
        assert 0 < result.n_attempts < 200
        assert CORPUS in result.corpora
        assert result.gates

    def test_subset_is_stable_across_runs(self):
        attempts, labels = suite_corpus()
        a = ci_suite(attempts, labels, fraction=0.5)
        b = ci_suite(attempts, labels, fraction=0.5)
        assert a.subset_keys == b.subset_keys

    def test_all_k_runs_of_a_chosen_finding_come_along(self):
        attempts, labels = suite_corpus()
        result = ci_suite(attempts, labels, fraction=0.5)
        consistency = result.corpora[CORPUS].consistency
        assert consistency is not None
        assert not consistency.incomplete_groups
        assert all(g.n_attempts == 5 for g in consistency.groups)

    def test_scores_findings_not_attempts(self):
        """Every finding contributes five cached attempts; the precision and
        miss-rate denominators must count findings."""
        attempts, labels = suite_corpus()
        result = ci_suite(attempts, labels, fraction=0.5)
        report = result.corpora[CORPUS]
        assert report.n_rows == len(result.subset_keys)
        assert result.n_attempts == report.n_rows * 5
        assert report.metrics is not None
        assert report.metrics.matrix.n == report.n_rows

    def test_says_out_loud_that_it_is_a_replay(self):
        attempts, labels = suite_corpus()
        result = ci_suite(attempts, labels, fraction=0.5)
        assert any("replay of recorded verdicts" in n for n in result.notes)
        assert any("do not publish the CI figure" in n for n in result.notes)

    def test_gates_are_blocking_in_ci(self):
        attempts, labels = suite_corpus()
        result = ci_suite(attempts, labels, fraction=0.5)
        assert all(g.blocking for g in result.gates)

    def test_empty_input_raises(self):
        with pytest.raises(InsufficientData):
            ci_suite([], {})

    def test_unlabelled_attempts_raise_rather_than_score_nothing(self):
        attempts, _ = suite_corpus()
        with pytest.raises(InsufficientData):
            ci_suite(attempts, {})

    def test_renders_and_serialises(self):
        attempts, labels = suite_corpus()
        result = ci_suite(attempts, labels, fraction=0.5)
        assert "Kasauti suite" in result.render()
        assert result.to_dict()["tier"] == "ci"


class TestNightlyBypassesTheCache:
    def test_never_reads_a_cached_attempt(self):
        attempts, labels = suite_corpus()
        with CachedVerdictStore() as store:
            for attempt in attempts:
                store.put(attempt.fingerprint, attempt)
            trap = ReadTrap(store)
            result = nightly_suite(
                trap,
                [f"fp-F{i:03d}" for i in range(40)],
                fresh_runner(labels),
                labels,
                k=5,
            )
        assert result.tier == "nightly"
        assert result.run_epoch is not None
        assert result.run_epoch != CI_EPOCH
        assert len(trap.puts) == 200

    def test_persists_fresh_attempts_under_the_new_epoch(self):
        attempts, labels = suite_corpus()
        with CachedVerdictStore() as store:
            for attempt in attempts:
                store.put(attempt.fingerprint, attempt)
            trap = ReadTrap(store)
            result = nightly_suite(
                trap,
                [f"fp-F{i:03d}" for i in range(10)],
                fresh_runner(labels),
                labels,
                k=5,
            )
            assert sorted(store.epochs()) == sorted([CI_EPOCH, result.run_epoch])
            assert store.count() == 200 + 50

    def test_reusing_an_existing_epoch_is_refused(self):
        attempts, labels = suite_corpus()
        with CachedVerdictStore() as store:
            for attempt in attempts:
                store.put(attempt.fingerprint, attempt)
            with pytest.raises(StaleEpochError):
                nightly_suite(
                    ReadTrap(store),
                    ["fp-F000"],
                    fresh_runner(labels),
                    labels,
                    k=5,
                    run_epoch=CI_EPOCH,
                )

    def test_a_cached_attempt_slipping_through_is_caught(self):
        """If anything in the chain answers from cache, the attempt arrives
        stamped with the old epoch and the run stops."""
        attempts, labels = suite_corpus()
        with CachedVerdictStore() as store:
            for attempt in attempts:
                store.put(attempt.fingerprint, attempt)
            with pytest.raises(EpochLeakError) as excinfo:
                nightly_suite(
                    ReadTrap(store),
                    ["fp-F000"],
                    fresh_runner(labels, epoch_override=CI_EPOCH),
                    labels,
                    k=5,
                    run_epoch="epoch-nightly-1",
                )
        assert "reached the nightly pass^k" in str(excinfo.value)

    def test_a_short_run_is_a_harness_bug_not_a_lower_score(self):
        _, labels = suite_corpus()

        def short(*, fingerprint, run_epoch, k):
            return fresh_runner(labels)(
                fingerprint=fingerprint, run_epoch=run_epoch, k=k - 1
            )

        with CachedVerdictStore() as store:
            with pytest.raises(EvalError):
                nightly_suite(ReadTrap(store), ["fp-F000"], short, labels, k=5)

    def test_an_attempt_for_the_wrong_defect_is_refused(self):
        _, labels = suite_corpus()

        def wrong(*, fingerprint, run_epoch, k):
            return [
                make_attempt(
                    finding_id="F999",
                    fingerprint="fp-F999",
                    run_index=i,
                    run_epoch=run_epoch,
                )
                for i in range(k)
            ]

        with CachedVerdictStore() as store:
            with pytest.raises(EvalError):
                nightly_suite(ReadTrap(store), ["fp-F000"], wrong, labels, k=5)

    def test_no_findings_raises(self):
        _, labels = suite_corpus()
        with CachedVerdictStore() as store:
            with pytest.raises(InsufficientData):
                nightly_suite(ReadTrap(store), [], fresh_runner(labels), labels)

    def test_nightly_gates_are_reported_not_blocking(self):
        attempts, labels = suite_corpus()
        with CachedVerdictStore() as store:
            result = nightly_suite(
                ReadTrap(store),
                [f"fp-F{i:03d}" for i in range(40)],
                fresh_runner(labels),
                labels,
                k=5,
                reliability_bootstrap=0,
            )
        assert result.gates
        assert not any(g.blocking for g in result.gates)
        assert not result.blocked


class TestGates:
    def test_kappa_is_not_a_gate(self):
        """D18 removed it. A future edit must not slip it back in."""
        attempts, labels = suite_corpus()
        result = ci_suite(attempts, labels, fraction=0.5)
        assert result.gates
        assert not any("kappa" in g.name.lower() for g in result.gates)

    def test_an_unreadable_gate_blocks_rather_than_passes(self):
        # Six confident false positives and a single real defect: the miss rate
        # would be over n=1, which is not a rate.
        rows = [
            LabelledVerdict(f"F{i}", CORPUS, "false_positive", 0.9, "false_positive")
            for i in range(6)
        ]
        rows.append(
            LabelledVerdict("R", CORPUS, "true_positive", 0.9, "true_positive")
        )
        report = CorpusReport(corpus=CORPUS, n_rows=7, metrics=fp_class_metrics(rows))
        gates = evaluate_gates({CORPUS: report}, tier="ci")
        miss = next(g for g in gates if g.name == "miss_rate")
        assert miss.status == "inconclusive"
        assert miss.blocks
        assert "INCONCLUSIVE" in miss.render()

    def test_thresholds_can_be_overridden(self):
        attempts, labels = suite_corpus()
        strict = ci_suite(attempts, labels, fraction=0.5, thresholds={"ece": 0.0})
        ece = next(g for g in strict.gates if g.name == "ece")
        assert ece.threshold == 0.0

    def test_injection_gates_skip_channels_that_cannot_be_attacked(self):
        paired = run_paired(make_run_trial(control_wins=None, hardened_wins=set()))
        gates = evaluate_gates({}, tier="nightly", injection=paired)
        names = {g.name for g in gates}
        assert "hardened_injection_asr[code_comment]" in names
        assert "hardened_injection_asr[repo_claude_md]" not in names, (
            "a gate that cannot fail is self-congratulation, not a gate"
        )

    def test_injection_gate_fails_when_a_payload_lands(self):
        paired = run_paired(
            make_run_trial(control_wins=None, hardened_wins={"PI-CC-01"})
        )
        gates = evaluate_gates({}, tier="ci", injection=paired)
        gate = next(
            g for g in gates if g.name == "hardened_injection_asr[code_comment]"
        )
        assert gate.status == "fail"
        assert gate.blocks

    def test_arms_are_distinct_configurations(self):
        assert CONTROL_ARM.name != HARDENED_ARM.name
        assert CONTROL_ARM.unions_path_tags is False
        assert HARDENED_ARM.unions_path_tags is True
