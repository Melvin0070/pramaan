"""Tests for the finding store (D6)."""

from __future__ import annotations

import json

import pytest

from pramaan.schemas import Finding, make_finding_id, make_fingerprint
from pramaan.store.defectdojo_adapter import (
    DefectDojoAdapter,
    engagement_name,
    product_name,
    scan_type_for,
    to_defectdojo_finding,
)
from pramaan.store.finding_store import (
    FindingStore,
    JsonlFindingStore,
    SqliteFindingStore,
    StoreError,
    copy_findings,
)


def make(
    *,
    rule_id: str = "php.lang.security.sqli",
    path: str = "src/Api.php",
    line_start: int = 42,
    repo: str = "razorpay-php",
    tool: str = "semgrep",
    snippet: str | None = "$db->query($sql);",
    severity: str = "high",
    **overrides: object,
) -> Finding:
    fields: dict[str, object] = {
        "finding_id": make_finding_id(tool, rule_id, repo, path, line_start),
        "fingerprint": make_fingerprint(tool, rule_id, repo, path, snippet),
        "tool": tool,
        "rule_id": rule_id,
        "message": "Possible SQL injection",
        "severity_reported": severity,
        "repo": repo,
        "path": path,
        "line_start": line_start,
        "line_end": line_start,
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "commit_sha": "deadbeef",
        "snippet": snippet,
        "metadata": {"dup_count": 0},
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


@pytest.fixture(params=["sqlite", "jsonl"])
def store(request: pytest.FixtureRequest, tmp_path):
    if request.param == "sqlite":
        s = SqliteFindingStore(tmp_path / "findings.sqlite")
    else:
        s = JsonlFindingStore(tmp_path / "corpus.jsonl")
    yield s
    s.close()


# -- Protocol conformance -------------------------------------------------


def test_all_backends_satisfy_the_protocol(tmp_path):
    backends = [
        SqliteFindingStore(":memory:"),
        JsonlFindingStore(tmp_path / "c.jsonl"),
        DefectDojoAdapter("https://dojo.example", repo="razorpay-php"),
    ]
    for backend in backends:
        assert isinstance(backend, FindingStore), type(backend).__name__


# -- Round-trip -----------------------------------------------------------


def test_roundtrip_preserves_every_field(store):
    finding = make()
    store.upsert(finding)
    assert store.get(finding.finding_id) == finding


def test_roundtrip_preserves_optional_nulls_and_metadata(store):
    finding = make(cwe=None, owasp=None, commit_sha=None, snippet=None,
                   metadata={"dup_count": 3, "note": "héllo ünicode"})
    store.upsert(finding)
    got = store.get(finding.finding_id)
    assert got is not None
    assert got.cwe is None and got.snippet is None
    assert got.metadata == {"dup_count": 3, "note": "héllo ünicode"}


def test_get_missing_returns_none(store):
    assert store.get("semgrep:nope:src/x.php:1") is None


def test_count_and_all_agree(store):
    findings = [make(line_start=n, path=f"src/A{n}.php") for n in range(5)]
    for f in findings:
        store.upsert(f)
    assert store.count() == 5
    assert list(store.all()) == findings


def test_upsert_is_idempotent_by_finding_id(store):
    finding = make()
    store.upsert(finding)
    store.upsert(finding)
    assert store.count() == 1


def test_upsert_updates_in_place_and_keeps_position(store):
    first = make(path="src/A.php", line_start=1)
    second = make(path="src/B.php", line_start=2)
    store.upsert(first)
    store.upsert(second)

    revised = make(path="src/A.php", line_start=1, message="revised", severity="critical")
    assert revised.finding_id == first.finding_id
    store.upsert(revised)

    assert store.count() == 2
    got = store.get(first.finding_id)
    assert got is not None and got.severity_reported == "critical"
    # Position is stable: an update must not reshuffle the corpus.
    assert [f.finding_id for f in store.all()] == [first.finding_id, second.finding_id]


def test_by_fingerprint_groups_the_same_defect(store):
    # Same tool/rule/repo/path/snippet, different line: one fingerprint, two ids.
    a = make(line_start=10)
    b = make(line_start=99)
    other = make(path="src/Other.php")
    assert a.fingerprint == b.fingerprint != other.fingerprint
    for f in (a, b, other):
        store.upsert(f)

    grouped = store.by_fingerprint(a.fingerprint)
    assert [f.finding_id for f in grouped] == [a.finding_id, b.finding_id]
    assert store.by_fingerprint("nosuchfingerprint") == []


# -- Fail-closed validation ----------------------------------------------


def test_invalid_severity_is_rejected_at_the_boundary(store):
    bad = make(severity="showstopper")
    with pytest.raises(StoreError, match="FINDING_SCHEMA"):
        store.upsert(bad)
    assert store.count() == 0


def test_a_bad_finding_mid_batch_leaves_the_store_unchanged(store):
    # A half-imported corpus is worse than a failed import: every count in the
    # trust report would be quietly wrong.
    batch = [make(path="src/A.php"), make(path="src/B.php", severity="oops"),
             make(path="src/C.php")]
    with pytest.raises(StoreError):
        store.upsert_many(batch)
    assert store.count() == 0


def test_validation_can_be_disabled_explicitly(tmp_path):
    s = SqliteFindingStore(tmp_path / "f.sqlite", validate=False)
    s.upsert(make(severity="showstopper"))
    assert s.count() == 1
    s.close()


# -- Durability -----------------------------------------------------------


def test_sqlite_persists_across_reopen(tmp_path):
    path = tmp_path / "nested" / "findings.sqlite"
    with SqliteFindingStore(path) as s:
        s.upsert(make())
    with SqliteFindingStore(path) as s:
        assert s.count() == 1


def test_sqlite_memory_store_works():
    s = SqliteFindingStore()
    s.upsert(make())
    assert s.count() == 1
    s.close()


def test_jsonl_persists_across_reopen(tmp_path):
    path = tmp_path / "corpus.jsonl"
    JsonlFindingStore(path).upsert(make())
    assert JsonlFindingStore(path).count() == 1


def test_jsonl_file_is_one_json_object_per_line(tmp_path):
    path = tmp_path / "corpus.jsonl"
    s = JsonlFindingStore(path)
    s.upsert(make(path="src/A.php"))
    s.upsert(make(path="src/B.php"))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["path"] for line in lines] == ["src/A.php", "src/B.php"]


def test_jsonl_log_replays_last_write_wins_and_compacts(tmp_path):
    path = tmp_path / "corpus.jsonl"
    s = JsonlFindingStore(path)
    s.upsert(make(message="first"))
    s.upsert(make(message="second"))
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2

    reopened = JsonlFindingStore(path)
    assert reopened.count() == 1
    only = next(reopened.all())
    assert only.message == "second"

    reopened.compact()
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1
    assert JsonlFindingStore(path).count() == 1


# -- A shrinking corpus must be loud -------------------------------------


def test_malformed_line_raises_and_names_the_line(tmp_path):
    path = tmp_path / "corpus.jsonl"
    s = JsonlFindingStore(path)
    s.upsert(make(path="src/A.php"))
    s.upsert(make(path="src/B.php"))
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"finding_id": "truncated"\n')

    with pytest.raises(StoreError) as exc:
        JsonlFindingStore(path)
    assert ":3:" in str(exc.value)


def test_non_object_line_raises(tmp_path):
    path = tmp_path / "corpus.jsonl"
    path.write_text('["not", "a", "finding"]\n', encoding="utf-8")
    with pytest.raises(StoreError, match="expected a JSON object"):
        JsonlFindingStore(path)


def test_line_missing_required_fields_raises(tmp_path):
    path = tmp_path / "corpus.jsonl"
    path.write_text('{"finding_id": "x"}\n', encoding="utf-8")
    with pytest.raises(StoreError):
        JsonlFindingStore(path)


def test_corrupt_sqlite_blob_raises_rather_than_returning_none(tmp_path):
    path = tmp_path / "f.sqlite"
    s = SqliteFindingStore(path)
    finding = make()
    s.upsert(finding)
    s._conn.execute("UPDATE findings SET data = ?", ("{not json",))
    s._conn.commit()
    with pytest.raises(StoreError, match="corrupt row"):
        s.get(finding.finding_id)
    s.close()


def test_blank_lines_are_tolerated(tmp_path):
    path = tmp_path / "corpus.jsonl"
    JsonlFindingStore(path).upsert(make())
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n\n")
    assert JsonlFindingStore(path).count() == 1


# -- Corpus <-> system of record -----------------------------------------


def test_corpus_moves_between_backends_losslessly(tmp_path):
    corpus = JsonlFindingStore(tmp_path / "corpus.jsonl")
    originals = [make(path=f"src/A{n}.php", line_start=n) for n in range(4)]
    corpus.upsert_many(originals)

    record = SqliteFindingStore(tmp_path / "f.sqlite")
    assert copy_findings(corpus, record) == 4
    assert list(record.all()) == originals

    exported = tmp_path / "roundtrip.jsonl"
    assert record.export_jsonl(exported) == 4
    assert list(JsonlFindingStore(exported).all()) == originals
    record.close()


def test_sqlite_fingerprints_are_deduped_in_insertion_order(tmp_path):
    s = SqliteFindingStore(tmp_path / "f.sqlite")
    s.upsert_many([make(line_start=1), make(line_start=2), make(path="src/Z.php")])
    assert len(s.fingerprints()) == 2
    s.close()


# -- DefectDojo stub (D6) -------------------------------------------------


def test_bhadra_naming_product_is_repo_engagement_is_tool():
    assert product_name("razorpay/razorpay-php") == "razorpay-php"
    assert product_name("https://github.com/razorpay/razorpay-php.git") == "razorpay-php"
    assert product_name("razorpay-woocommerce") == "razorpay-woocommerce"
    assert engagement_name("semgrep") == "pramaan_Semgrep_Scan"
    assert engagement_name("govulncheck") == "pramaan_Govulncheck_Scan"


def test_adapter_exposes_bhadra_names_without_network():
    adapter = DefectDojoAdapter(
        "https://dojo.example/api/v2/", repo="razorpay/razorpay-php", tool="semgrep"
    )
    assert adapter.product == "razorpay-php"
    assert adapter.engagement == "pramaan_Semgrep_Scan"
    assert adapter.scan_type == "Semgrep JSON Report"
    payload = adapter.import_scan_payload(commit_sha="cafe")
    assert payload["product_name"] == "razorpay-php"
    assert payload["engagement_name"] == "pramaan_Semgrep_Scan"
    assert payload["commit_hash"] == "cafe"


def test_unknown_tool_has_no_scan_type_rather_than_a_wrong_one():
    # A wrong scan_type parses to zero findings and reports success.
    with pytest.raises(ValueError, match="no DefectDojo scan_type"):
        scan_type_for("nmap")


def test_finding_maps_onto_defectdojo_identity_fields():
    finding = make()
    payload = to_defectdojo_finding(finding)
    assert payload["hash_code"] == finding.fingerprint
    assert payload["unique_id_from_tool"] == finding.finding_id
    assert payload["severity"] == "High"
    assert payload["cwe"] == 89
    assert payload["verified"] is False


def test_missing_cwe_maps_to_zero_not_a_crash():
    assert to_defectdojo_finding(make(cwe=None))["cwe"] == 0
    assert to_defectdojo_finding(make(cwe="unknown"))["cwe"] == 0


@pytest.mark.parametrize(
    "call",
    [
        lambda a: a.upsert(make()),
        lambda a: a.upsert_many([make()]),
        lambda a: a.get("x"),
        lambda a: a.by_fingerprint("x"),
        lambda a: list(a.all()),
        lambda a: a.count(),
    ],
)
def test_every_protocol_method_is_an_explicit_stub(call):
    adapter = DefectDojoAdapter("https://dojo.example", repo="razorpay-php")
    with pytest.raises(NotImplementedError, match="week-2 stub"):
        call(adapter)
