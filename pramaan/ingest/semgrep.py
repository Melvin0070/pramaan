"""Parse Semgrep output (SARIF 2.1.0 or Semgrep's own `--json` format) into
`Finding`s.

Semgrep is the only scanner in scope for Pramaan (PROJECT-BRAINSTORM.md
D2), but its own CLI, the GitHub Action and `semgrep ci` do not agree on
one output shape, and Razorpay's own engineering posts describe pulling
findings from the Semgrep API rather than a single fixed local format —
so both shapes are supported here.

Ingest fails closed (CONTRACTS.md ground rule 7): anything that stops us
from confidently building every `Finding` raises `IngestError` for the
whole call rather than returning the findings we did manage to parse.
Optional fields (`cwe`, `owasp`) are the one place we degrade gracefully
to `None` instead of raising, because the schema already models "unknown"
for those two, and refusing to ingest a real finding over an unparsable
CWE tag would be worse than ingesting it with that field blank.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from pramaan.ingest.errors import IngestError
from pramaan.ingest.dedup import assign_occurrences
from pramaan.schemas.finding import (
    Finding,
    Severity,
    make_fingerprint,
    make_finding_id,
)

TOOL = "semgrep"

# Semgrep's rule severity has exactly three levels. There is no first-party
# signal for "critical" or "low", so we don't invent one — CONTRACTS.md
# leaves the exact mapping to us ("map Semgrep severity onto the Severity
# literal"); this keeps Semgrep's middle level mapped to our middle level
# rather than spreading three values unevenly across five.
_JSON_SEVERITY: dict[str, Severity] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
}

# Semgrep's SARIF writer maps its three severities onto SARIF `level`
# (error/warning/note) one-for-one, so this mirrors _JSON_SEVERITY. `note`
# rather than SARIF's `none` is what Semgrep actually emits for INFO.
_SARIF_SEVERITY: dict[str, Severity] = {
    "error": "high",
    "warning": "medium",
    "note": "info",
}

# Matches both the human-readable metadata form ("CWE-79: Improper
# Neutralization...") and the registry tag form ("external/cwe/cwe-089");
# the capture group drops leading zeros so both spellings of the same CWE
# normalise to one string ("CWE-79") for fingerprinting and CWE-keyed
# lookups downstream (e.g. the fixer allowlist).
_CWE_RE = re.compile(r"cwe-0*(\d+)", re.IGNORECASE)
# Matches OWASP Top 10 tags like "A03:2021" or "A1:2017", however they're
# decorated ("A03:2021 - Injection", "OWASP-A03:2021").
_OWASP_RE = re.compile(r"\b([AC]\d{1,2}:\d{4})\b", re.IGNORECASE)


def parse_sarif(text: str, *, repo: str | None = None) -> list[Finding]:
    """Parse a SARIF 2.1.0 log produced by `semgrep --sarif`.

    `repo` overrides whatever (if anything) can be recovered from the
    log's own `versionControlProvenance`; Semgrep does not otherwise know
    what repo it ran against, so callers that know it should pass it.
    """
    doc = _load_json(text)
    if not isinstance(doc, dict):
        raise IngestError(
            f"SARIF input must be a JSON object, got {type(doc).__name__}"
        )

    runs = doc.get("runs")
    if not runs:
        raise IngestError("SARIF input has no 'runs': not a Semgrep SARIF log")
    if not isinstance(runs, list):
        raise IngestError(f"SARIF 'runs' must be a list, got {type(runs).__name__}")

    findings: list[Finding] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise IngestError(f"SARIF runs[{run_index}] must be an object")
        findings.extend(_parse_sarif_run(run, run_index, repo))
    # Distinguish repeated identical lines before anything downstream dedups.
    return assign_occurrences(findings)


def parse_json(text: str, *, repo: str | None = None) -> list[Finding]:
    """Parse Semgrep's native `--json` output.

    Unlike SARIF, this format carries no VCS provenance at all, so `repo`
    (when not passed) always falls back to the "unknown" sentinel.
    """
    doc = _load_json(text)
    if not isinstance(doc, dict):
        raise IngestError(
            f"Semgrep JSON input must be a JSON object, got {type(doc).__name__}"
        )

    results = doc.get("results")
    if results is None:
        raise IngestError(
            "Semgrep JSON input has no 'results': not Semgrep --json output"
        )
    if not isinstance(results, list):
        raise IngestError(
            f"Semgrep JSON 'results' must be a list, got {type(results).__name__}"
        )

    findings: list[Finding] = []
    for index, result in enumerate(results):
        where = f"results[{index}]"
        if not isinstance(result, dict):
            raise IngestError(f"{where} must be an object")
        findings.append(_finding_from_json_result(result, where, repo))
    # Distinguish repeated identical lines before anything downstream dedups.
    return assign_occurrences(findings)


# --------------------------------------------------------------------------
# SARIF


def _parse_sarif_run(
    run: dict[str, Any], run_index: int, repo: str | None
) -> list[Finding]:
    rules_by_id = _sarif_rules(run)
    run_repo = repo or _sarif_repo(run)
    run_commit = _sarif_commit(run)

    results = run.get("results")
    if results is None:
        # SARIF permits an absent `results` on a run that didn't execute;
        # Semgrep itself always writes `[]`, but treat them the same way
        # zero results is treated everywhere else: valid, not an error.
        return []
    if not isinstance(results, list):
        raise IngestError(f"SARIF runs[{run_index}].results must be a list")

    out: list[Finding] = []
    for result_index, result in enumerate(results):
        where = f"runs[{run_index}].results[{result_index}]"
        if not isinstance(result, dict):
            raise IngestError(f"SARIF {where} must be an object")
        out.append(
            _finding_from_sarif_result(result, rules_by_id, where, run_repo, run_commit)
        )
    return out


def _finding_from_sarif_result(
    result: dict[str, Any],
    rules_by_id: dict[str, dict[str, Any]],
    where: str,
    repo: str | None,
    commit_sha: str | None,
) -> Finding:
    rule_id = result.get("ruleId")
    if not isinstance(rule_id, str) or not rule_id:
        raise IngestError(f"SARIF {where} has no 'ruleId'")

    message_obj = result.get("message")
    message = message_obj.get("text") if isinstance(message_obj, dict) else None
    if not isinstance(message, str) or not message:
        raise IngestError(f"SARIF {where} ({rule_id}) has no 'message.text'")

    path, line_start, line_end, snippet = _sarif_location(result, where, rule_id)

    rule = rules_by_id.get(rule_id, {})
    raw_level = _sarif_raw_level(result, rule)
    severity = _sarif_severity(raw_level, where, rule_id)
    cwe, owasp = _sarif_metadata(rule)

    effective_repo = repo or "unknown"
    return Finding(
        finding_id=make_finding_id(TOOL, rule_id, effective_repo, path, line_start),
        fingerprint=make_fingerprint(TOOL, rule_id, effective_repo, path, snippet),
        tool=TOOL,
        rule_id=rule_id,
        message=message,
        severity_reported=severity,
        repo=effective_repo,
        path=path,
        line_start=line_start,
        line_end=line_end,
        cwe=cwe,
        owasp=owasp,
        commit_sha=commit_sha,
        snippet=snippet,
        metadata={"raw_severity": raw_level},
    )


def _sarif_location(
    result: dict[str, Any], where: str, rule_id: str
) -> tuple[str, int, int, str | None]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        raise IngestError(f"SARIF {where} ({rule_id}) has no 'locations'")

    first = locations[0]
    phys = first.get("physicalLocation") if isinstance(first, dict) else None
    if not isinstance(phys, dict):
        raise IngestError(
            f"SARIF {where} ({rule_id}) location has no 'physicalLocation'"
        )

    artifact = phys.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or not uri:
        raise IngestError(
            f"SARIF {where} ({rule_id}) has no 'physicalLocation.artifactLocation.uri'"
        )
    path = uri[len("file://") :] if uri.startswith("file://") else uri

    region = phys.get("region")
    line_start = region.get("startLine") if isinstance(region, dict) else None
    if not isinstance(line_start, int) or isinstance(line_start, bool) or line_start < 0:
        raise IngestError(f"SARIF {where} ({rule_id}) has no 'region.startLine'")

    # SARIF spec: endLine defaults to startLine when absent (single-line region).
    line_end = region.get("endLine", line_start)
    if not isinstance(line_end, int) or isinstance(line_end, bool) or line_end < 0:
        raise IngestError(f"SARIF {where} ({rule_id}) has a non-integer 'region.endLine'")

    snippet_obj = region.get("snippet")
    snippet = snippet_obj.get("text") if isinstance(snippet_obj, dict) else None
    snippet = snippet if isinstance(snippet, str) else None

    return path, line_start, line_end, snippet


def _sarif_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tool_obj = run.get("tool")
    driver = tool_obj.get("driver") if isinstance(tool_obj, dict) else None
    rules = driver.get("rules") if isinstance(driver, dict) else None
    if not isinstance(rules, list):
        return {}
    return {
        rule["id"]: rule
        for rule in rules
        if isinstance(rule, dict) and isinstance(rule.get("id"), str)
    }


def _sarif_raw_level(result: dict[str, Any], rule: dict[str, Any]) -> str | None:
    level = result.get("level")
    if isinstance(level, str) and level:
        return level
    config = rule.get("defaultConfiguration")
    level = config.get("level") if isinstance(config, dict) else None
    return level if isinstance(level, str) and level else None


def _sarif_severity(raw_level: str | None, where: str, rule_id: str) -> Severity:
    if raw_level is None:
        raise IngestError(
            f"SARIF {where} ({rule_id}) has no severity: no result 'level' and no "
            "rule 'defaultConfiguration.level' (rule missing from tool.driver.rules?)"
        )
    mapped = _SARIF_SEVERITY.get(raw_level)
    if mapped is None:
        raise IngestError(
            f"SARIF {where} ({rule_id}) has unrecognised level {raw_level!r}"
        )
    return mapped


def _sarif_metadata(rule: dict[str, Any]) -> tuple[str | None, str | None]:
    props = rule.get("properties")
    if not isinstance(props, dict):
        return None, None

    # Semgrep's SARIF rule `properties` carries the rule's metadata dict
    # more or less verbatim (same `cwe`/`owasp` shapes as --json's
    # extra.metadata), *and* a flattened `tags` list aimed at SARIF
    # consumers like GitHub code scanning. Try the direct keys first,
    # fall back to hunting through tags.
    cwe = _metadata_code(props.get("cwe"), _CWE_RE, lambda m: f"CWE-{m.group(1)}")
    owasp = _metadata_code(props.get("owasp"), _OWASP_RE, lambda m: m.group(1).upper())

    if cwe is None or owasp is None:
        tags = _as_str_list(props.get("tags"))
        if cwe is None:
            cwe = _first_match(_CWE_RE, tags, lambda m: f"CWE-{m.group(1)}")
        if owasp is None:
            owasp = _first_match(_OWASP_RE, tags, lambda m: m.group(1).upper())
    return cwe, owasp


def _sarif_repo(run: dict[str, Any]) -> str | None:
    """Bare repo name, not the clone URL.

    `repo` is an identity term in both `make_finding_id` and `make_fingerprint`, and
    the corpus records it as a bare name (`razorpay-opencart`). If provenance handed
    back `https://github.com/razorpay/razorpay-php.git` while the corpus said
    `razorpay-php`, the same defect would carry two different fingerprints depending
    on which path ingested it, and the verdict cache would never hit.
    """
    prov = _sarif_provenance(run)
    uri = prov.get("repositoryUri") if prov else None
    if not isinstance(uri, str) or not uri:
        return None
    name = uri.rstrip("/").rsplit("/", 1)[-1]
    return name[:-4] if name.endswith(".git") else name


def _sarif_commit(run: dict[str, Any]) -> str | None:
    prov = _sarif_provenance(run)
    rev = prov.get("revisionId") if prov else None
    return rev if isinstance(rev, str) and rev else None


def _sarif_provenance(run: dict[str, Any]) -> dict[str, Any] | None:
    vcs = run.get("versionControlProvenance")
    if isinstance(vcs, list) and vcs and isinstance(vcs[0], dict):
        return vcs[0]
    return None


# --------------------------------------------------------------------------
# Semgrep native JSON


def _finding_from_json_result(
    result: dict[str, Any], where: str, repo: str | None
) -> Finding:
    rule_id = result.get("check_id")
    if not isinstance(rule_id, str) or not rule_id:
        raise IngestError(f"{where} has no 'check_id'")

    path = result.get("path")
    if not isinstance(path, str) or not path:
        raise IngestError(f"{where} ({rule_id}) has no 'path'")

    start, end = result.get("start"), result.get("end")
    line_start = start.get("line") if isinstance(start, dict) else None
    line_end = end.get("line") if isinstance(end, dict) else None
    if not isinstance(line_start, int) or isinstance(line_start, bool) or line_start < 0:
        raise IngestError(f"{where} ({rule_id}) has no 'start.line'")
    if not isinstance(line_end, int) or isinstance(line_end, bool) or line_end < 0:
        raise IngestError(f"{where} ({rule_id}) has no 'end.line'")

    extra = result.get("extra")
    if not isinstance(extra, dict):
        raise IngestError(f"{where} ({rule_id}) has no 'extra'")

    message = extra.get("message")
    if not isinstance(message, str) or not message:
        raise IngestError(f"{where} ({rule_id}) has no 'extra.message'")

    raw_severity = extra.get("severity")
    if not isinstance(raw_severity, str) or not raw_severity:
        raise IngestError(f"{where} ({rule_id}) has no 'extra.severity'")
    severity = _JSON_SEVERITY.get(raw_severity.upper())
    if severity is None:
        raise IngestError(
            f"{where} ({rule_id}) has unrecognised Semgrep severity {raw_severity!r}"
        )

    lines = extra.get("lines")
    snippet = lines if isinstance(lines, str) else None

    metadata = extra.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    cwe = _metadata_code(metadata.get("cwe"), _CWE_RE, lambda m: f"CWE-{m.group(1)}")
    owasp = _metadata_code(metadata.get("owasp"), _OWASP_RE, lambda m: m.group(1).upper())

    effective_repo = repo or "unknown"
    return Finding(
        finding_id=make_finding_id(TOOL, rule_id, effective_repo, path, line_start),
        fingerprint=make_fingerprint(TOOL, rule_id, effective_repo, path, snippet),
        tool=TOOL,
        rule_id=rule_id,
        message=message,
        severity_reported=severity,
        repo=effective_repo,
        path=path,
        line_start=line_start,
        line_end=line_end,
        cwe=cwe,
        owasp=owasp,
        commit_sha=None,
        snippet=snippet,
        metadata={"raw_severity": raw_severity},
    )


# --------------------------------------------------------------------------
# Shared helpers


def _load_json(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise IngestError(f"invalid JSON: {e}") from e


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _first_match(
    pattern: re.Pattern[str], candidates: list[str], fmt: Callable[[re.Match[str]], str]
) -> str | None:
    """First candidate matching `pattern`, or None if none do.

    Used on tag soup (SARIF `properties.tags` mixes CWE, OWASP, category
    and technology tags) where a candidate that doesn't match the pattern
    is simply unrelated, not a differently-formatted answer — so there is
    no reasonable fallback value here, unlike `_metadata_code` below.
    """
    for candidate in candidates:
        m = pattern.search(candidate)
        if m:
            return fmt(m)
    return None


def _metadata_code(
    value: object, pattern: re.Pattern[str], fmt: Callable[[re.Match[str]], str]
) -> str | None:
    """Extract a normalised code from a dedicated metadata field.

    `extra.metadata.cwe` / `.owasp` (and their SARIF `properties` mirrors)
    are sometimes a list (`["CWE-79: Improper Neutralization..."]`),
    sometimes a bare string, and occasionally already just the code. Try
    the pattern first; if nothing matches, the field is still *known* to
    be about this classification (unlike tag soup), so fall back to its
    own text rather than discarding a value that's merely oddly formatted.
    """
    candidates = _as_str_list(value)
    if not candidates:
        return None
    for candidate in candidates:
        m = pattern.search(candidate)
        if m:
            return fmt(m)
    return candidates[0].strip() or None
