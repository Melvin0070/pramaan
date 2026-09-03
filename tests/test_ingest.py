"""Tests for pramaan.ingest: Semgrep SARIF/JSON parsing and fingerprint dedup.

CONTRACTS.md (Lane C) is explicit that malformed input must raise
`IngestError` rather than silently returning a partial list, so most of
these are failure-mode tests built around minimal, deliberately-broken
payloads. The two fixtures under tests/fixtures/ carry the realistic
happy-path shapes (both a SARIF 2.1.0 log and Semgrep's native --json
output, each with more than one rule/severity/metadata shape) so those
are exercised once each in full rather than re-typed inline everywhere.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from pramaan.ingest.dedup import assign_occurrences, dedup
from pramaan.ingest.errors import IngestError
from pramaan.ingest.semgrep import parse_json, parse_sarif
from pramaan.schemas.finding import Finding, make_finding_id

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


# ---------------------------------------------------------------------------
# Minimal payload builders for the malformed-input tests. Each returns a
# fresh dict (deep-copied) representing the *smallest* valid document, so
# a test can delete/replace exactly the field it wants to prove is required.


def _minimal_sarif() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [
                            {
                                "id": "php.lang.security.injection.tainted-sql-string",
                                "defaultConfiguration": {"level": "error"},
                                "properties": {
                                    "cwe": ["CWE-89: Improper Neutralization..."],
                                    "owasp": ["A03:2021 - Injection"],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "php.lang.security.injection.tainted-sql-string",
                        "message": {"text": "Tainted SQL string."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/models/User.php"},
                                    "region": {"startLine": 42, "endLine": 44},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _minimal_json_result() -> dict[str, Any]:
    return {
        "check_id": "php.lang.security.injection.tainted-sql-string",
        "path": "app/models/User.php",
        "start": {"line": 42, "col": 1},
        "end": {"line": 44, "col": 10},
        "extra": {
            "message": "Tainted SQL string.",
            "severity": "ERROR",
            "metadata": {"cwe": ["CWE-89: Improper Neutralization..."]},
        },
    }


def _minimal_json() -> dict[str, Any]:
    return {"results": [_minimal_json_result()]}


def dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc)


# ---------------------------------------------------------------------------
# SARIF happy path


class TestParseSarifHappyPath:
    def setup_method(self) -> None:
        self.findings = parse_sarif(_load_fixture("semgrep_sarif_sample.json"))

    def test_returns_one_finding_per_result(self) -> None:
        assert len(self.findings) == 2
        assert all(isinstance(f, Finding) for f in self.findings)

    def test_rule_id_survives_intact_into_finding_id(self) -> None:
        sqli = self.findings[0]
        assert sqli.rule_id == "php.lang.security.injection.tainted-sql-string"
        assert sqli.finding_id == (
            "semgrep:php.lang.security.injection.tainted-sql-string:"
            "razorpay-php:app/models/User.php:42"
        )

    def test_location_and_message(self) -> None:
        sqli = self.findings[0]
        assert sqli.path == "app/models/User.php"
        assert sqli.line_start == 42
        assert sqli.line_end == 44
        assert "Tainted SQL string" in sqli.message
        assert sqli.snippet == "$query = \"SELECT * FROM users WHERE id = \" . $_GET['id'];"

    def test_severity_mapped_from_rule_default_configuration(self) -> None:
        # Neither result in the fixture carries its own `level`; both must
        # fall back to the rule's `defaultConfiguration.level`.
        sqli, xss = self.findings
        assert sqli.severity_reported == "high"  # SARIF "error"
        assert xss.severity_reported == "medium"  # SARIF "warning"
        assert sqli.metadata["raw_severity"] == "error"
        assert xss.metadata["raw_severity"] == "warning"

    def test_cwe_owasp_from_direct_rule_properties(self) -> None:
        sqli = self.findings[0]
        assert sqli.cwe == "CWE-89"
        assert sqli.owasp == "A03:2021"

    def test_cwe_owasp_fallback_to_tags_when_no_direct_properties(self) -> None:
        # The xss rule only carries `properties.tags`, not `properties.cwe`
        # / `properties.owasp` directly (php.lang.security.audit.xss...).
        xss = self.findings[1]
        assert xss.cwe == "CWE-79"  # from "external/cwe/cwe-079", zero-padding stripped
        assert xss.owasp == "A03:2021"  # from "OWASP-A03:2021 - Injection"

    def test_repo_and_commit_from_version_control_provenance(self) -> None:
        sqli = self.findings[0]
        # Bare name, not the clone URL: `repo` is a fingerprint term and the corpus
        # records bare names, so the two ingest paths must agree or the cache misses.
        assert sqli.repo == "razorpay-php"
        assert sqli.commit_sha == "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"

    def test_tool_is_semgrep(self) -> None:
        assert all(f.tool == "semgrep" for f in self.findings)

    def test_fingerprint_is_stable_hex_digest(self) -> None:
        sqli = self.findings[0]
        assert len(sqli.fingerprint) == 32
        int(sqli.fingerprint, 16)  # raises ValueError if not hex


def test_parse_sarif_repo_override_takes_priority_over_provenance() -> None:
    findings = parse_sarif(
        _load_fixture("semgrep_sarif_sample.json"), repo="razorpay/razorpay-php-fork"
    )
    assert all(f.repo == "razorpay/razorpay-php-fork" for f in findings)


def test_parse_sarif_result_level_overrides_rule_default() -> None:
    doc = _minimal_sarif()
    doc["runs"][0]["results"][0]["level"] = "warning"
    findings = parse_sarif(dump(doc))
    assert findings[0].severity_reported == "medium"  # not "high" from the rule default
    assert findings[0].metadata["raw_severity"] == "warning"


def test_parse_sarif_strips_file_uri_scheme() -> None:
    doc = _minimal_sarif()
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    loc["artifactLocation"]["uri"] = "file://app/models/User.php"
    findings = parse_sarif(dump(doc))
    assert findings[0].path == "app/models/User.php"


def test_parse_sarif_end_line_defaults_to_start_line() -> None:
    doc = _minimal_sarif()
    del doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["endLine"]
    findings = parse_sarif(dump(doc))
    assert findings[0].line_end == findings[0].line_start == 42


# ---------------------------------------------------------------------------
# SARIF: zero results is valid, not an error


def test_parse_sarif_zero_results_returns_empty_list() -> None:
    doc = _minimal_sarif()
    doc["runs"][0]["results"] = []
    assert parse_sarif(dump(doc)) == []


def test_parse_sarif_missing_results_key_treated_as_zero_results() -> None:
    doc = _minimal_sarif()
    del doc["runs"][0]["results"]
    assert parse_sarif(dump(doc)) == []


# ---------------------------------------------------------------------------
# SARIF: malformed input fails closed


def test_parse_sarif_truncated_json_raises() -> None:
    with pytest.raises(IngestError, match="invalid JSON"):
        parse_sarif('{"version": "2.1.0", "runs": [')


def test_parse_sarif_empty_string_raises() -> None:
    with pytest.raises(IngestError, match="invalid JSON"):
        parse_sarif("")


def test_parse_sarif_top_level_not_object_raises() -> None:
    with pytest.raises(IngestError, match="JSON object"):
        parse_sarif("[1, 2, 3]")


def test_parse_sarif_missing_runs_raises() -> None:
    with pytest.raises(IngestError, match="runs"):
        parse_sarif(json.dumps({"version": "2.1.0"}))


def test_parse_sarif_empty_runs_raises() -> None:
    with pytest.raises(IngestError, match="runs"):
        parse_sarif(json.dumps({"version": "2.1.0", "runs": []}))


def test_parse_sarif_runs_not_a_list_raises() -> None:
    with pytest.raises(IngestError, match="runs"):
        parse_sarif(json.dumps({"version": "2.1.0", "runs": "oops"}))


def test_parse_sarif_result_with_no_locations_raises() -> None:
    doc = _minimal_sarif()
    del doc["runs"][0]["results"][0]["locations"]
    with pytest.raises(IngestError, match="locations"):
        parse_sarif(dump(doc))


def test_parse_sarif_result_with_empty_locations_raises() -> None:
    doc = _minimal_sarif()
    doc["runs"][0]["results"][0]["locations"] = []
    with pytest.raises(IngestError, match="locations"):
        parse_sarif(dump(doc))


def test_parse_sarif_result_with_no_region_raises() -> None:
    doc = _minimal_sarif()
    del doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    with pytest.raises(IngestError, match="startLine"):
        parse_sarif(dump(doc))


def test_parse_sarif_result_with_no_rule_id_raises() -> None:
    doc = _minimal_sarif()
    del doc["runs"][0]["results"][0]["ruleId"]
    with pytest.raises(IngestError, match="ruleId"):
        parse_sarif(dump(doc))


def test_parse_sarif_result_with_no_message_raises() -> None:
    doc = _minimal_sarif()
    del doc["runs"][0]["results"][0]["message"]
    with pytest.raises(IngestError, match="message"):
        parse_sarif(dump(doc))


def test_parse_sarif_unresolvable_severity_raises() -> None:
    doc = _minimal_sarif()
    # Rule is missing entirely from tool.driver.rules, and the result has
    # no `level` of its own: severity cannot be resolved at all.
    doc["runs"][0]["tool"]["driver"]["rules"] = []
    with pytest.raises(IngestError, match="severity"):
        parse_sarif(dump(doc))


def test_parse_sarif_unrecognised_level_raises() -> None:
    doc = _minimal_sarif()
    doc["runs"][0]["results"][0]["level"] = "catastrophic"
    with pytest.raises(IngestError, match="catastrophic"):
        parse_sarif(dump(doc))


def test_parse_sarif_non_object_run_raises() -> None:
    with pytest.raises(IngestError, match="runs\\[0\\]"):
        parse_sarif(json.dumps({"runs": ["not-an-object"]}))


def test_parse_sarif_non_object_result_raises() -> None:
    doc = _minimal_sarif()
    doc["runs"][0]["results"] = ["not-an-object"]
    with pytest.raises(IngestError, match="results\\[0\\]"):
        parse_sarif(dump(doc))


# ---------------------------------------------------------------------------
# Semgrep JSON happy path


class TestParseJsonHappyPath:
    def setup_method(self) -> None:
        self.findings = parse_json(_load_fixture("semgrep_json_sample.json"))

    def test_returns_one_finding_per_result(self) -> None:
        assert len(self.findings) == 3

    def test_rule_id_survives_intact_into_finding_id(self) -> None:
        sqli = self.findings[0]
        assert sqli.rule_id == "php.lang.security.injection.tainted-sql-string"
        assert sqli.finding_id == (
            "semgrep:php.lang.security.injection.tainted-sql-string:"
            "unknown:app/models/User.php:42"
        )

    def test_severity_mapping(self) -> None:
        sqli, xss, secret = self.findings
        assert sqli.severity_reported == "high"  # ERROR
        assert xss.severity_reported == "medium"  # WARNING
        assert secret.severity_reported == "info"  # INFO

    def test_cwe_from_list_metadata(self) -> None:
        sqli = self.findings[0]
        assert sqli.cwe == "CWE-89"
        assert sqli.owasp == "A03:2021"

    def test_cwe_from_bare_string_metadata(self) -> None:
        xss = self.findings[1]
        assert xss.cwe == "CWE-79"
        assert xss.owasp == "A03:2021"

    def test_missing_metadata_yields_none_cwe_and_owasp(self) -> None:
        secret = self.findings[2]
        assert secret.cwe is None
        assert secret.owasp is None

    def test_snippet_from_lines_field(self) -> None:
        sqli = self.findings[0]
        assert sqli.snippet == "$query = \"SELECT * FROM users WHERE id = \" . $_GET['id'];"

    def test_snippet_none_when_lines_absent(self) -> None:
        secret = self.findings[2]
        assert secret.snippet is None

    def test_commit_sha_always_none_for_json_format(self) -> None:
        # Semgrep's native --json output carries no VCS provenance at all.
        assert all(f.commit_sha is None for f in self.findings)

    def test_repo_defaults_to_unknown_sentinel(self) -> None:
        assert all(f.repo == "unknown" for f in self.findings)


def test_parse_json_repo_override() -> None:
    findings = parse_json(
        _load_fixture("semgrep_json_sample.json"), repo="razorpay/razorpay-php"
    )
    assert all(f.repo == "razorpay/razorpay-php" for f in findings)


# ---------------------------------------------------------------------------
# Semgrep JSON: zero results is valid, not an error


def test_parse_json_zero_results_returns_empty_list() -> None:
    assert parse_json(json.dumps({"results": []})) == []


# ---------------------------------------------------------------------------
# Semgrep JSON: malformed input fails closed


def test_parse_json_truncated_json_raises() -> None:
    with pytest.raises(IngestError, match="invalid JSON"):
        parse_json('{"results": [')


def test_parse_json_empty_string_raises() -> None:
    with pytest.raises(IngestError, match="invalid JSON"):
        parse_json("")


def test_parse_json_top_level_not_object_raises() -> None:
    with pytest.raises(IngestError, match="JSON object"):
        parse_json("[1, 2, 3]")


def test_parse_json_missing_results_key_raises() -> None:
    with pytest.raises(IngestError, match="results"):
        parse_json(json.dumps({"version": "1.45.0"}))


def test_parse_json_results_not_a_list_raises() -> None:
    with pytest.raises(IngestError, match="results"):
        parse_json(json.dumps({"results": "oops"}))


def test_parse_json_result_with_no_path_raises() -> None:
    doc = _minimal_json()
    del doc["results"][0]["path"]
    with pytest.raises(IngestError, match="path"):
        parse_json(dump(doc))


def test_parse_json_result_with_no_start_line_raises() -> None:
    doc = _minimal_json()
    del doc["results"][0]["start"]
    with pytest.raises(IngestError, match="start.line"):
        parse_json(dump(doc))


def test_parse_json_result_with_no_end_line_raises() -> None:
    doc = _minimal_json()
    del doc["results"][0]["end"]
    with pytest.raises(IngestError, match="end.line"):
        parse_json(dump(doc))


def test_parse_json_result_with_no_check_id_raises() -> None:
    doc = _minimal_json()
    del doc["results"][0]["check_id"]
    with pytest.raises(IngestError, match="check_id"):
        parse_json(dump(doc))


def test_parse_json_result_with_no_extra_raises() -> None:
    doc = _minimal_json()
    del doc["results"][0]["extra"]
    with pytest.raises(IngestError, match="extra"):
        parse_json(dump(doc))


def test_parse_json_result_with_no_message_raises() -> None:
    doc = _minimal_json()
    del doc["results"][0]["extra"]["message"]
    with pytest.raises(IngestError, match="extra.message"):
        parse_json(dump(doc))


def test_parse_json_result_with_no_severity_raises() -> None:
    doc = _minimal_json()
    del doc["results"][0]["extra"]["severity"]
    with pytest.raises(IngestError, match="extra.severity"):
        parse_json(dump(doc))


def test_parse_json_unrecognised_severity_raises() -> None:
    doc = _minimal_json()
    doc["results"][0]["extra"]["severity"] = "CATASTROPHIC"
    with pytest.raises(IngestError, match="CATASTROPHIC"):
        parse_json(dump(doc))


def test_parse_json_non_object_result_raises() -> None:
    doc = {"results": ["not-an-object"]}
    with pytest.raises(IngestError, match="results\\[0\\]"):
        parse_json(dump(doc))


def test_parse_json_negative_line_raises() -> None:
    doc = _minimal_json()
    doc["results"][0]["start"]["line"] = -1
    with pytest.raises(IngestError, match="start.line"):
        parse_json(dump(doc))


# ---------------------------------------------------------------------------
# dedup()


def _finding(
    *,
    fingerprint: str = "fp-a",
    line_start: int = 10,
    rule_id: str = "php.lang.security.injection.tainted-sql-string",
    path: str = "app/models/User.php",
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        finding_id=f"semgrep:{rule_id}:{path}:{line_start}",
        fingerprint=fingerprint,
        tool="semgrep",
        rule_id=rule_id,
        message="Tainted SQL string.",
        severity_reported="high",
        repo="razorpay/razorpay-php",
        path=path,
        line_start=line_start,
        line_end=line_start + 1,
        metadata=metadata or {},
    )


def test_dedup_empty_list() -> None:
    assert dedup([]) == []


def test_dedup_no_collisions_returns_all_unchanged() -> None:
    findings = [_finding(fingerprint="fp-a"), _finding(fingerprint="fp-b")]
    result = dedup(findings)
    assert result == findings
    assert all("dup_count" not in f.metadata for f in result)


def test_dedup_collision_keeps_earliest_line_start() -> None:
    later = _finding(fingerprint="fp-a", line_start=99)
    earlier = _finding(fingerprint="fp-a", line_start=10)
    result = dedup([later, earlier])
    assert len(result) == 1
    assert result[0].line_start == 10
    assert result[0].finding_id == earlier.finding_id


def test_dedup_records_dup_count_on_collision() -> None:
    group = [_finding(fingerprint="fp-a", line_start=n) for n in (30, 10, 20)]
    result = dedup(group)
    assert len(result) == 1
    assert result[0].metadata["dup_count"] == 3


def test_dedup_preserves_existing_metadata_on_survivor() -> None:
    survivor = _finding(fingerprint="fp-a", line_start=10, metadata={"raw_severity": "error"})
    other = _finding(fingerprint="fp-a", line_start=20, metadata={"raw_severity": "error"})
    result = dedup([other, survivor])
    assert result[0].metadata["raw_severity"] == "error"
    assert result[0].metadata["dup_count"] == 2


def test_dedup_mixed_groups() -> None:
    unique = _finding(fingerprint="fp-solo", line_start=5)
    dup_1 = _finding(fingerprint="fp-dup", line_start=50)
    dup_2 = _finding(fingerprint="fp-dup", line_start=15)
    result = dedup([unique, dup_1, dup_2])
    assert len(result) == 2
    by_fp = {f.fingerprint: f for f in result}
    assert "dup_count" not in by_fp["fp-solo"].metadata
    assert by_fp["fp-dup"].line_start == 15
    assert by_fp["fp-dup"].metadata["dup_count"] == 2


def test_dedup_does_not_mutate_input_findings() -> None:
    original = _finding(fingerprint="fp-a", line_start=10)
    other = _finding(fingerprint="fp-a", line_start=20)
    before = copy.deepcopy(original.metadata)
    dedup([original, other])
    assert original.metadata == before


def test_dedup_ties_on_line_start_are_deterministic() -> None:
    first = _finding(fingerprint="fp-a", line_start=10, path="app/a.php")
    second = _finding(fingerprint="fp-a", line_start=10, path="app/a.php")
    result = dedup([first, second])
    assert len(result) == 1
    assert result[0].metadata["dup_count"] == 2


# ---------------------------------------------------------------------------
# End-to-end: parse then dedup


def test_parse_sarif_then_dedup_is_a_no_op_when_fingerprints_differ() -> None:
    findings = parse_sarif(_load_fixture("semgrep_sarif_sample.json"))
    result = dedup(findings)
    assert len(result) == len(findings) == 2


def test_parse_sarif_never_returns_partial_list_on_later_bad_result() -> None:
    # The whole point of failing closed: one malformed result among several
    # good ones must not silently ship the good ones as if that were the
    # complete set.
    doc = _minimal_sarif()
    good = doc["runs"][0]["results"][0]
    bad = copy.deepcopy(good)
    del bad["locations"]
    doc["runs"][0]["results"] = [good, bad]
    with pytest.raises(IngestError, match="locations"):
        parse_sarif(dump(doc))


def test_parse_json_never_returns_partial_list_on_later_bad_result() -> None:
    doc = _minimal_json()
    good = doc["results"][0]
    bad = copy.deepcopy(good)
    del bad["path"]
    doc["results"] = [good, bad]
    with pytest.raises(IngestError, match="path"):
        parse_json(dump(doc))


class TestOccurrenceIndexing:
    """A fingerprint that ignores line numbers can over-collapse.

    These three properties are in tension, and getting any of them wrong is silent:
    the corpus would simply contain fewer findings than the scanner reported, and
    nothing would say so.
    """

    @staticmethod
    def _finding(line: int, *, snippet: str = '<a href="<?= $x ?>">') -> Finding:
        return Finding(
            finding_id=f"semgrep:xss:repo:a.php:{line}",
            fingerprint="placeholder",
            tool="semgrep",
            rule_id="php.lang.security.audit.xss.var-in-href",
            message="Variable in href",
            severity_reported="medium",
            repo="repo",
            path="a.php",
            line_start=line,
            line_end=line,
            snippet=snippet,
        )

    def test_two_identical_lines_are_two_defects(self) -> None:
        # Fixing the first does not fix the second, so collapsing them would leave a
        # live vulnerability behind a green report.
        findings = assign_occurrences([self._finding(10), self._finding(40)])
        assert len({f.fingerprint for f in findings}) == 2
        assert len(dedup(findings)) == 2

    def test_the_same_line_reported_twice_still_collapses(self) -> None:
        # That is one defect the scanner mentioned twice, not two defects.
        findings = assign_occurrences([self._finding(10), self._finding(10)])
        assert len(dedup(findings)) == 1

    def test_a_line_shift_keeps_the_fingerprint_stable(self) -> None:
        # The verdict cache keys on fingerprint. If an unrelated edit above the defect
        # changed it, every cached verdict would miss and the calibration set would
        # silently start over.
        moved = assign_occurrences([self._finding(99)])[0]
        original = assign_occurrences([self._finding(10)])[0]
        assert moved.fingerprint == original.fingerprint

    def test_different_repos_vendoring_one_file_stay_distinct(self) -> None:
        # Two Razorpay payment-button plugins ship a byte-identical PHP file. This
        # produced six colliding finding_ids in the real corpus, and the store keys
        # on finding_id, so the collision was a silently dropped finding.
        a = make_finding_id("semgrep", "xss", "payment-button-siteorigin-plugin", "a.php", 10)
        b = make_finding_id("semgrep", "xss", "payment-button-visual-composer", "a.php", 10)
        assert a != b
