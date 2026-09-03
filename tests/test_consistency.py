"""pass^k over cached attempts, with `schema_invalid` as a non-match (D10)."""

from __future__ import annotations

import pytest
from evals_fixtures import CORPUS, OTHER_CORPUS, k_attempts, make_attempt

from pramaan.evals.consistency import (
    InconsistentGroup,
    attempt_corpus,
    group_sizes,
    pass_at_k,
    pass_at_k_by_corpus,
    schema_failure_rate,
)
from pramaan.evals.stats import EvalError, InsufficientData


def _five(finding_id: str, verdict: str = "true_positive", **kw):
    return k_attempts(finding_id, [verdict] * 5, **kw)


class TestPassAtK:
    def test_all_five_agreeing_is_a_match(self):
        result = pass_at_k(_five("F1"), k=5, min_n=1)
        assert result.pass_k.successes == 1 and result.pass_k.n == 1
        assert result.groups[0].matched

    def test_one_disagreement_fails_the_group(self):
        attempts = k_attempts(
            "F1",
            ["true_positive", "true_positive", "false_positive", "true_positive",
             "true_positive"],
        )
        result = pass_at_k(attempts, k=5, min_n=1)
        assert result.pass_k.successes == 0
        assert result.failure_reasons["disagreement"] == 1

    def test_schema_invalid_counts_as_a_non_match(self):
        """D10, and the single most tempting thing to get wrong here."""
        attempts = k_attempts(
            "F1",
            ["true_positive"] * 4 + [None],
            statuses=["valid"] * 4 + ["schema_invalid"],
        )
        result = pass_at_k(attempts, k=5, min_n=1)
        assert result.pass_k.successes == 0
        assert result.failure_reasons["schema_invalid"] == 1
        assert "schema_invalid" in result.groups[0].reason

    @pytest.mark.parametrize(
        "status", ["schema_invalid", "truncated", "budget_abort", "refused"]
    )
    def test_every_failure_status_is_a_non_match(self, status):
        attempts = k_attempts(
            "F1",
            ["true_positive"] * 4 + [None],
            statuses=["valid"] * 4 + [status],
        )
        result = pass_at_k(attempts, k=5, min_n=1)
        assert result.pass_k.successes == 0
        assert result.failure_reasons[status] == 1

    def test_schema_failure_rate_is_published_alongside(self):
        attempts = _five("F1") + k_attempts(
            "F2",
            ["true_positive"] * 4 + [None],
            statuses=["valid"] * 4 + ["schema_invalid"],
        )
        result = pass_at_k(attempts, k=5, min_n=1)
        assert result.schema_failure.successes == 1
        assert result.schema_failure.n == 10
        assert result.invalid_attempt.successes == 1
        assert result.status_counts["schema_invalid"] == 1
        assert result.status_counts["valid"] == 9

    def test_short_group_raises_under_strict(self):
        attempts = k_attempts("F1", ["true_positive"] * 3)
        with pytest.raises(InconsistentGroup):
            pass_at_k(attempts, k=5)

    def test_short_group_is_a_non_match_not_an_exclusion(self):
        attempts = _five("F1") + k_attempts("F2", ["true_positive"] * 3)
        result = pass_at_k(attempts, k=5, strict=False, min_n=1)
        assert result.pass_k.n == 2, "the short group must stay in the denominator"
        assert result.pass_k.successes == 1
        assert len(result.incomplete_groups) == 1
        assert any("counted as non-matches" in n for n in result.notes)

    def test_duplicate_run_index_is_an_error(self):
        attempts = _five("F1")
        attempts.append(make_attempt(finding_id="F1", run_index=0))
        with pytest.raises(InconsistentGroup):
            pass_at_k(attempts, k=6)

    def test_epochs_never_merge_into_one_group(self):
        """D19: the CI epoch and a nightly epoch are separate measurements."""
        attempts = _five("F1", run_epoch="epoch-ci") + _five(
            "F1", run_epoch="epoch-nightly"
        )
        result = pass_at_k(attempts, k=5, min_n=1)
        assert result.pass_k.n == 2
        assert any("run_epochs" in n for n in result.notes)

    def test_stricter_key_fields_ask_a_harder_question(self):
        attempts = _five("F1")
        loose = pass_at_k(attempts, k=5, key_fields=("verdict",), min_n=1)
        tight = pass_at_k(
            attempts, k=5, key_fields=("verdict", "cwe", "confidence"), min_n=1
        )
        assert loose.pass_k.successes == tight.pass_k.successes == 1
        assert tight.key_fields == ("verdict", "cwe", "confidence")

    def test_rate_carries_an_interval_and_a_small_n_warning(self):
        result = pass_at_k(_five("F1"), k=5, min_n=5)
        assert not result.pass_k.reportable
        assert "n too small" in result.render()

    def test_empty_input_raises(self):
        with pytest.raises(InsufficientData):
            pass_at_k([], k=5)

    def test_rejects_empty_key_fields(self):
        with pytest.raises(ValueError):
            pass_at_k(_five("F1"), k=5, key_fields=())

    def test_to_dict_is_serialisable(self):
        d = pass_at_k(_five("F1"), k=5, min_n=1).to_dict()
        assert d["pass_k"]["n"] == 1
        assert d["schema_failure_rate"]["n"] == 5


class TestPerCorpus:
    def test_never_returns_one_pooled_number(self):
        attempts = _five("F1", corpus=CORPUS) + _five("F2", corpus=OTHER_CORPUS)
        out = pass_at_k_by_corpus(attempts, k=5, min_n=1)
        assert set(out) == {CORPUS, OTHER_CORPUS}
        assert all(r.pass_k.n == 1 for r in out.values())

    def test_attempt_without_a_corpus_refuses_to_pool(self):
        attempt = make_attempt(finding_id="F1")
        stripped = type(attempt)(**{**attempt.to_dict(), "metadata": {}})
        with pytest.raises(EvalError):
            attempt_corpus(stripped)
        assert attempt_corpus(stripped, default="x") == "x"


class TestSchemaFailureRate:
    def test_counts_only_schema_invalid(self):
        attempts = k_attempts(
            "F1",
            [None, None, "true_positive", "true_positive", "true_positive"],
            statuses=["schema_invalid", "truncated", "valid", "valid", "valid"],
        )
        rate = schema_failure_rate(attempts, min_n=1)
        assert rate.successes == 1 and rate.n == 5


class TestGroupSizes:
    def test_reports_short_groups_before_a_strict_run(self):
        attempts = _five("F1") + k_attempts("F2", ["true_positive"] * 2)
        sizes = sorted(group_sizes(attempts).values())
        assert sizes == [2, 5]
