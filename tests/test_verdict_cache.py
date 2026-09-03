"""Tests for the content-addressed verdict cache (D13, D19)."""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone

import pytest

from pramaan.schemas import ALL_ATTEMPT_STATUSES, Attempt
from pramaan.store.verdict_cache import (
    KEY_FIELDS,
    CacheError,
    CacheKey,
    CachedVerdictStore,
    component_hash,
    compute_prompt_hash,
    load_jsonl,
    new_run_epoch,
)

FP = "a" * 32

VERDICT = {
    "finding_id": "semgrep:sqli:src/Api.php:42",
    "verdict": "true_positive",
    "confidence": 0.91,
    "cwe": "CWE-89",
    "evidence": [{"file": "src/Api.php", "line": 42, "why": "unparameterised query"}],
    "reachability": "reachable_from_http",
    "business_impact": {
        "payment_path": True,
        "auth_or_session": False,
        "pci_scope_hint": False,
        "kyc_or_settlement": False,
    },
    "injection_observed": False,
    "rationale": "user input reaches the query builder unescaped",
}


def attempt(
    *,
    status: str = "valid",
    run_index: int = 0,
    run_epoch: str = "epoch-ci-1",
    model: str = "claude-opus-5",
    effort: str = "high",
    context_config: str = "ctx50_callers",
    prompt_hash: str = "p" * 32,
    fingerprint: str = FP,
    verdict: dict | None = None,
    **overrides: object,
) -> Attempt:
    fields: dict[str, object] = {
        "finding_id": "semgrep:sqli:src/Api.php:42",
        "fingerprint": fingerprint,
        "run_index": run_index,
        "status": status,
        "verdict": VERDICT if (verdict is None and status == "valid") else verdict,
        "raw_text": '{"verdict": "true_positive"}',
        "model": model,
        "effort": effort,
        "context_config": context_config,
        "prompt_hash": prompt_hash,
        "run_epoch": run_epoch,
        "cost_usd": 0.017,
        "duration_s": 4.2,
        "num_turns": 3,
        "system_fingerprint": "fp_20260901",
        "error": None,
        "metadata": {},
    }
    fields.update(overrides)
    return Attempt(**fields)  # type: ignore[arg-type]


def key_of(a: Attempt, fingerprint: str = FP) -> CacheKey:
    return CacheKey.for_attempt(fingerprint, a)


@pytest.fixture
def cache():
    store = CachedVerdictStore()
    yield store
    store.close()


# -- Round-trip -----------------------------------------------------------


def test_put_then_get_is_a_hit(cache):
    a = attempt()
    cache.put(FP, a)
    assert cache.get(key_of(a)) == a
    assert cache.has(key_of(a))
    assert cache.count() == 1


def test_get_on_empty_cache_is_a_miss(cache):
    assert cache.get(key_of(attempt())) is None
    assert cache.has(key_of(attempt())) is False


def test_re_putting_the_same_key_replaces_rather_than_duplicates(cache):
    truncated = attempt(status="truncated", verdict=None)
    cache.put(FP, truncated)
    finished = attempt(status="valid")
    cache.put(FP, finished)
    assert cache.count() == 1
    got = cache.get(key_of(finished))
    assert got is not None and got.status == "valid"


def test_persists_across_reopen(tmp_path):
    path = tmp_path / "nested" / "verdicts.sqlite"
    a = attempt()
    with CachedVerdictStore(path) as c:
        c.put(FP, a)
    with CachedVerdictStore(path) as c:
        assert c.get(key_of(a)) == a


# -- D19: run-epoch isolation --------------------------------------------


def test_a_fresh_epoch_misses_every_cached_row(cache):
    cached = attempt(run_epoch="epoch-ci-1")
    cache.put(FP, cached)

    nightly_epoch = new_run_epoch()
    nightly_key = CacheKey(
        fingerprint=FP,
        model=cached.model,
        effort=cached.effort,
        context_config=cached.context_config,
        prompt_hash=cached.prompt_hash,
        run_index=cached.run_index,
        run_epoch=nightly_epoch,
    )
    # Everything but the epoch is identical. This must not be coerced to a hit.
    assert cache.get(nightly_key) is None


def test_whole_nightly_pass_k_misses_the_whole_ci_epoch(cache):
    k = 5
    for i in range(k):
        cache.put(FP, attempt(run_index=i, run_epoch="epoch-ci-1"))
    assert cache.count() == k

    nightly = new_run_epoch()
    misses = [
        cache.get(
            CacheKey(FP, "claude-opus-5", "high", "ctx50_callers", "p" * 32, i, nightly)
        )
        for i in range(k)
    ]
    assert misses == [None] * k


def test_epochs_coexist_rather_than_overwrite(cache):
    a = attempt(run_epoch="epoch-ci-1")
    b = attempt(run_epoch="epoch-nightly-2")
    cache.put(FP, a)
    cache.put(FP, b)
    assert cache.count() == 2
    assert cache.get(key_of(a)) is not None
    assert cache.get(key_of(b)) is not None
    assert cache.epochs() == ["epoch-ci-1", "epoch-nightly-2"]


def test_get_has_no_escape_hatch_that_relaxes_the_epoch():
    """Guards the exact regression: an `ignore_epoch=`-shaped parameter."""
    params = list(inspect.signature(CachedVerdictStore.get).parameters)
    assert params == ["self", "key"]


def test_lookup_binds_every_key_field_into_the_sql(cache):
    """Observes the statement SQLite actually ran, not the module source.

    A source grep is not enough: `if name != "run_epoch"` still mentions the
    field while dropping it from the WHERE clause.
    """
    a = attempt(run_epoch="epoch-ci-1")
    cache.put(FP, a)
    seen: list[str] = []
    cache._conn.set_trace_callback(seen.append)
    cache.get(key_of(a))
    cache._conn.set_trace_callback(None)

    sql = " ".join(seen)
    for value in (FP, a.model, a.effort, a.context_config, a.prompt_hash, a.run_epoch):
        assert value in sql, f"{value!r} never reached the lookup"


def test_narrowing_by_epoch_never_widens(cache):
    cache.put(FP, attempt(run_epoch="epoch-ci-1"))
    cache.put(FP, attempt(run_epoch="epoch-nightly-2"))
    assert len(cache.attempts_for_fingerprint(FP)) == 2
    narrowed = cache.attempts_for_fingerprint(FP, run_epoch="epoch-nightly-2")
    assert [c.key.run_epoch for c in narrowed] == ["epoch-nightly-2"]


def test_blank_epoch_is_rejected(cache):
    with pytest.raises(ValueError, match="run_epoch"):
        CacheKey(FP, "m", "e", "c", "p", 0, "")
    with pytest.raises(ValueError, match="run_epoch"):
        cache.put(FP, attempt(run_epoch="   "))


def test_new_run_epoch_is_unique_and_takes_the_clock_as_a_parameter():
    fixed = datetime(2026, 9, 3, 2, 0, 0, tzinfo=timezone.utc)
    a, b = new_run_epoch(fixed), new_run_epoch(fixed)
    assert a.startswith("20260903T020000Z-")
    assert a != b  # two nightly runs in the same second still isolate


# -- Every key field discriminates ---------------------------------------


@pytest.mark.parametrize(
    "field,other",
    [
        ("fingerprint", "b" * 32),
        ("model", "claude-sonnet-4-5"),
        ("effort", "low"),
        ("context_config", "ctx200_callers"),
        ("prompt_hash", "q" * 32),
        ("run_index", 1),
        ("run_epoch", "epoch-nightly-2"),
    ],
)
def test_changing_any_single_key_field_is_a_miss(cache, field, other):
    a = attempt()
    cache.put(FP, a)
    base = key_of(a).as_dict()
    assert base[field] != other
    assert cache.get(CacheKey.from_dict({**base, field: other})) is None
    # ...and the original is still a hit, so the miss is discrimination, not loss.
    assert cache.get(key_of(a)) is not None


def test_key_fields_are_exactly_the_contract_tuple():
    assert KEY_FIELDS == (
        "fingerprint",
        "model",
        "effort",
        "context_config",
        "prompt_hash",
        "run_index",
        "run_epoch",
    )
    assert [f.name for f in CacheKey.__dataclass_fields__.values()] == list(KEY_FIELDS)


@pytest.mark.parametrize("field", ["fingerprint", "model", "effort", "context_config"])
def test_blank_key_fields_are_rejected(field):
    base = {
        "fingerprint": FP,
        "model": "m",
        "effort": "e",
        "context_config": "c",
        "prompt_hash": "p",
        "run_index": 0,
        "run_epoch": "x",
    }
    with pytest.raises(ValueError, match=field):
        CacheKey.from_dict({**base, field: ""})


def test_negative_run_index_is_rejected():
    with pytest.raises(ValueError, match="run_index"):
        CacheKey(FP, "m", "e", "c", "p", -1, "x")


# -- Failure statuses are data, not errors --------------------------------


@pytest.mark.parametrize("status", ALL_ATTEMPT_STATUSES)
def test_all_five_statuses_round_trip(cache, status):
    a = attempt(
        status=status,
        verdict=VERDICT if status == "valid" else None,
        raw_text="{truncated" if status != "valid" else json.dumps(VERDICT),
        error=None if status == "valid" else f"{status} at turn 25",
    )
    cache.put(FP, a)
    got = cache.get(key_of(a))
    assert got == a
    assert got.status == status
    assert got.is_valid is (status == "valid")


def test_schema_invalid_attempt_keeps_its_raw_text(cache):
    a = attempt(
        status="schema_invalid",
        verdict=None,
        raw_text='{"verdict": "probably_bad"}',
        error="confidence missing",
    )
    cache.put(FP, a)
    got = cache.get(key_of(a))
    assert got is not None
    assert got.verdict is None
    assert got.raw_text == '{"verdict": "probably_bad"}'
    assert got.error == "confidence missing"


def test_budget_abort_counts_toward_pass_at_k_denominator(cache):
    cache.put(FP, attempt(run_index=0, status="valid"))
    cache.put(FP, attempt(run_index=1, status="budget_abort", verdict=None))
    cache.put(FP, attempt(run_index=2, status="schema_invalid", verdict=None))
    stored = cache.attempts_for_fingerprint(FP)
    assert len(stored) == 3
    assert sum(1 for c in stored if c.attempt.is_valid) == 1


def test_status_counts_cover_all_five(cache):
    for i, status in enumerate(ALL_ATTEMPT_STATUSES):
        cache.put(FP, attempt(run_index=i, status=status, verdict=None))
    counts = cache.status_counts()
    assert set(counts) == set(ALL_ATTEMPT_STATUSES)
    assert sum(counts.values()) == 5


def test_unknown_status_is_rejected(cache):
    with pytest.raises(ValueError, match="unknown attempt status"):
        cache.put(FP, attempt(status="probably_fine"))


def test_system_fingerprint_survives_so_drift_stays_visible(cache):
    a = attempt(system_fingerprint="fp_20261001_drifted")
    cache.put(FP, a)
    got = cache.get(key_of(a))
    assert got is not None and got.system_fingerprint == "fp_20261001_drifted"


def test_corrupt_row_raises_rather_than_reporting_a_miss(cache):
    a = attempt()
    cache.put(FP, a)
    cache._conn.execute("UPDATE attempts SET attempt = ?", ("{not json",))
    cache._conn.commit()
    with pytest.raises(CacheError, match="corrupt cached attempt"):
        cache.get(key_of(a))


# -- Skill-scoped invalidation -------------------------------------------


def _prompt(**components: str) -> tuple[str, dict[str, str]]:
    comps = {name: component_hash(text) for name, text in components.items()}
    return compute_prompt_hash(comps), comps


def test_prompt_hash_is_order_independent_and_content_sensitive():
    a = compute_prompt_hash({"system": "1", "skill:cwe-89": "2"})
    b = compute_prompt_hash({"skill:cwe-89": "2", "system": "1"})
    c = compute_prompt_hash({"system": "1", "skill:cwe-89": "3"})
    d = compute_prompt_hash({"system": "1", "skill:cwe-79": "2"})
    assert a == b
    assert a != c != d and a != d
    with pytest.raises(ValueError):
        compute_prompt_hash({})


def test_editing_one_skill_invalidates_only_its_rows(cache):
    sqli_hash, sqli_components = _prompt(
        system="triage rubric v1", **{"skill:cwe-89": "sqli guidance v1"}
    )
    xss_hash, xss_components = _prompt(
        system="triage rubric v1", **{"skill:cwe-79": "xss guidance v1"}
    )
    assert sqli_hash != xss_hash

    cache.put(FP, attempt(prompt_hash=sqli_hash), components=sqli_components)
    cache.put("b" * 32, attempt(prompt_hash=xss_hash, fingerprint="b" * 32), components=xss_components)
    assert cache.count() == 2

    dropped = cache.invalidate_component("skill:cwe-89")
    assert dropped == 1
    assert cache.count() == 1
    survivor = cache.attempts_for_fingerprint("b" * 32)
    assert [c.key.prompt_hash for c in survivor] == [xss_hash]


def test_a_shared_component_edit_invalidates_both(cache):
    sqli_hash, sqli_components = _prompt(
        system="rubric v1", **{"skill:cwe-89": "sqli v1"}
    )
    xss_hash, xss_components = _prompt(system="rubric v1", **{"skill:cwe-79": "xss v1"})
    cache.put(FP, attempt(prompt_hash=sqli_hash), components=sqli_components)
    cache.put("b" * 32, attempt(prompt_hash=xss_hash, fingerprint="b" * 32), components=xss_components)

    assert cache.invalidate_component("system") == 2
    assert cache.count() == 0


def test_unchanged_skill_content_is_not_invalidated(cache):
    unchanged = component_hash("sqli guidance v1")
    old = component_hash("sqli guidance v0")

    fresh_hash, fresh = _prompt(system="rubric", **{"skill:cwe-89": "sqli guidance v1"})
    stale_components = {"system": component_hash("rubric"), "skill:cwe-89": old}
    stale_hash = compute_prompt_hash(stale_components)

    cache.put(FP, attempt(prompt_hash=fresh_hash), components=fresh)
    cache.put(FP, attempt(run_index=1, prompt_hash=stale_hash), components=stale_components)
    assert cache.count() == 2

    dropped = cache.invalidate_component("skill:cwe-89", current_hash=unchanged)
    assert dropped == 1
    remaining = cache.attempts_for_fingerprint(FP)
    assert [c.key.prompt_hash for c in remaining] == [fresh_hash]


def test_invalidating_an_unknown_component_is_a_no_op(cache):
    prompt_hash, components = _prompt(system="rubric", **{"skill:cwe-89": "v1"})
    cache.put(FP, attempt(prompt_hash=prompt_hash), components=components)
    assert cache.invalidate_component("skill:cwe-611") == 0
    assert cache.count() == 1


def test_mislabelled_components_are_rejected(cache):
    _, components = _prompt(system="rubric", **{"skill:cwe-89": "v1"})
    with pytest.raises(ValueError, match="prompt_hash"):
        cache.put(FP, attempt(prompt_hash="z" * 32), components=components)
    assert cache.count() == 0


def test_unregistered_prompt_hashes_are_surfaced_not_swallowed(cache):
    registered, components = _prompt(system="rubric", **{"skill:cwe-89": "v1"})
    cache.put(FP, attempt(prompt_hash=registered), components=components)
    cache.put(FP, attempt(run_index=1, prompt_hash="u" * 32))

    assert cache.unregistered_prompt_hashes() == ["u" * 32]
    # An unregistered row is out of reach of skill-scoped eviction by design;
    # `unregistered_prompt_hashes` is what makes that visible.
    cache.invalidate_component("skill:cwe-89")
    assert [c.key.prompt_hash for c in cache.all()] == ["u" * 32]


def test_register_prompt_ahead_of_time_enables_invalidation(cache):
    components = {"system": component_hash("rubric"), "skill:cwe-89": component_hash("v1")}
    prompt_hash = cache.register_prompt(components)
    cache.put(FP, attempt(prompt_hash=prompt_hash))
    assert cache.unregistered_prompt_hashes() == []
    assert cache.invalidate_component("skill:cwe-89") == 1


# -- Published verdict table ---------------------------------------------


def test_export_carries_the_key_and_every_status(tmp_path, cache):
    for i, status in enumerate(ALL_ATTEMPT_STATUSES):
        cache.put(
            FP,
            attempt(run_index=i, status=status, verdict=VERDICT if status == "valid" else None),
        )
    out = tmp_path / "verdicts.jsonl"
    assert cache.export_jsonl(out) == 5

    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 5
    for record in records:
        # `Attempt` carries no fingerprint, so the table must supply it or tau
        # cannot be re-derived from the published file alone.
        for field in KEY_FIELDS:
            assert field in record
        assert "attempt" in record
    assert {r["attempt"]["status"] for r in records} == set(ALL_ATTEMPT_STATUSES)


def test_export_is_deterministic(tmp_path, cache):
    cache.put("c" * 32, attempt(run_index=1, fingerprint="c" * 32))
    cache.put(FP, attempt(run_index=1))
    cache.put(FP, attempt(run_index=0))
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    cache.export_jsonl(first)
    cache.export_jsonl(second)
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")

    order = [
        (r.key.fingerprint, r.key.run_index) for r in load_jsonl(first)
    ]
    assert order == [(FP, 0), (FP, 1), ("c" * 32, 1)]


def test_tau_can_be_rederived_from_the_published_table_with_no_api_key(tmp_path, cache):
    originals = [attempt(run_index=i, status=s, verdict=VERDICT if s == "valid" else None)
                 for i, s in enumerate(ALL_ATTEMPT_STATUSES)]
    for a in originals:
        cache.put(FP, a)
    out = tmp_path / "verdicts.jsonl"
    cache.export_jsonl(out)

    # No database, no network: just the file.
    replayed = list(load_jsonl(out))
    assert [r.attempt for r in replayed] == originals
    assert all(r.key.fingerprint == FP for r in replayed)

    rebuilt = CachedVerdictStore()
    assert rebuilt.import_jsonl(out) == 5
    for a in originals:
        assert rebuilt.get(key_of(a)) == a
    rebuilt.close()


def test_export_of_an_empty_cache_is_an_empty_file(tmp_path, cache):
    out = tmp_path / "empty.jsonl"
    assert cache.export_jsonl(out) == 0
    assert out.read_text(encoding="utf-8") == ""
    assert list(load_jsonl(out)) == []


def test_malformed_published_table_raises(tmp_path):
    out = tmp_path / "verdicts.jsonl"
    out.write_text('{"fingerprint": "a"\n', encoding="utf-8")
    with pytest.raises(CacheError, match=":1:"):
        list(load_jsonl(out))


def test_published_record_missing_a_key_field_raises(tmp_path):
    out = tmp_path / "verdicts.jsonl"
    out.write_text(json.dumps({"attempt": attempt().to_dict()}) + "\n", encoding="utf-8")
    with pytest.raises(CacheError, match="missing key field"):
        list(load_jsonl(out))
