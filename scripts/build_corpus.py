"""Normalise raw Semgrep JSON (data/raw/*.json) into the frozen Finding corpus.

One-off corpus-build tool for the day-0 spike reproduction (see PROJECT-BRAINSTORM.md,
"Day-0 spike"). Deliberately lives outside `pramaan/ingest/`: that package is where a
sibling lane is building the real SARIF ingest pipeline, and this script's job ends the
day the corpus is frozen.

Usage: uv run --python 3.12 --with jsonschema python3 scripts/build_corpus.py
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # belt-and-braces: guarantee THIS worktree's pramaan wins

from pramaan.ingest.dedup import assign_occurrences
from pramaan.schemas.finding import (  # noqa: E402
    FINDING_SCHEMA,
    Finding,
    make_fingerprint,
    make_finding_id,
)

try:
    import jsonschema
except ImportError:  # pragma: no cover
    sys.exit("jsonschema not installed — run via: uv run --with jsonschema python3 scripts/build_corpus.py")

RAW_DIR = REPO_ROOT / "data" / "raw"
TARGETS_DIR = REPO_ROOT / "targets"
CORPUS_DIR = REPO_ROOT / "data" / "corpus"
FINDINGS_PATH = CORPUS_DIR / "findings.jsonl"
LABELS_PATH = CORPUS_DIR / "labels.csv"

# Semgrep's own scale tops out at ERROR — there is no native "critical" signal, and
# inventing one from impact+confidence would be a judgement call this script shouldn't
# make silently. ERROR findings in this ruleset set are the SQLi/cleartext-transport
# rules; WARNING is the XSS template rules. INFO is unused here but mapped for when a
# future ruleset produces it.
SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}

CWE_RE = re.compile(r"CWE-\d+")
SNIPPET_MAX_CHARS = 500


def commit_sha(repo: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(TARGETS_DIR / repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip() or None if result.returncode == 0 else None


def read_snippet(repo: str, rel_path: str, line_start: int, line_end: int) -> tuple[str | None, bool, int]:
    """Real source text, not Semgrep's own `extra.lines` — the CLI redacts that field to
    the literal string "requires login" for anonymous (non-`semgrep login`) scans of
    registry rules, which would otherwise poison every fingerprint in the corpus."""
    file_path = TARGETS_DIR / repo / rel_path
    try:
        lines = file_path.read_text(errors="replace").splitlines()
    except OSError:
        return None, False, 0
    lo, hi = max(line_start - 1, 0), min(line_end, len(lines))
    if lo >= hi:
        return None, False, 0
    text = "\n".join(lines[lo:hi]).strip()
    n_lines = hi - lo
    if len(text) > SNIPPET_MAX_CHARS:
        return text[:SNIPPET_MAX_CHARS] + " …[truncated]", True, n_lines
    return text, False, n_lines


def extract_cwe(metadata: dict[str, Any]) -> str | None:
    for entry in metadata.get("cwe", []) or []:
        m = CWE_RE.search(entry)
        if m:
            return m.group(0)
    return None


def extract_owasp(metadata: dict[str, Any]) -> str | None:
    entries = metadata.get("owasp", []) or []
    return "; ".join(entries) if entries else None


def build_findings() -> list[Finding]:
    raw_files = sorted(
        p for p in RAW_DIR.glob("*.json")
        if (TARGETS_DIR / p.stem).is_dir()  # excludes scratch files like _repo_list.json
    )
    if not raw_files:
        sys.exit(f"no raw Semgrep JSON found under {RAW_DIR} (matched against {TARGETS_DIR})")

    sha_cache: dict[str, str | None] = {}
    findings: list[Finding] = []
    finding_id_seen: dict[str, str] = {}  # finding_id -> repo, to detect cross-repo collisions
    id_collisions = 0

    for raw_file in raw_files:
        repo = raw_file.stem
        sha_cache.setdefault(repo, commit_sha(repo))
        data = json.loads(raw_file.read_text())
        if data.get("errors"):
            print(f"WARNING: {repo} reported {len(data['errors'])} Semgrep errors — see raw JSON", file=sys.stderr)

        for result in data.get("results", []):
            extra = result["extra"]
            metadata = extra.get("metadata", {})
            rel_path = result["path"]
            prefix = f"targets/{repo}/"
            if rel_path.startswith(prefix):
                rel_path = rel_path[len(prefix):]

            line_start = result["start"]["line"]
            line_end = result["end"]["line"]
            snippet, truncated, n_lines = read_snippet(repo, rel_path, line_start, line_end)
            rule_id = result["check_id"]

            fid = make_finding_id("semgrep", rule_id, repo, rel_path, line_start)
            # Kept as a live check rather than deleted: the collision this lane found
            # is fixed in the schema, and this is what would catch the next one.
            if fid in finding_id_seen and finding_id_seen[fid] != repo:
                id_collisions += 1
                print(
                    f"COLLISION: finding_id {fid} already emitted for repo "
                    f"{finding_id_seen[fid]!r}, now also matched in {repo!r}",
                    file=sys.stderr,
                )
            finding_id_seen[fid] = repo

            meta: dict[str, Any] = {
                "check_id": rule_id,
                "rule_short_name": rule_id.rsplit(".", 1)[-1],
                "semgrep_severity": extra.get("severity"),
                "confidence": metadata.get("confidence"),
                "impact": metadata.get("impact"),
                "likelihood": metadata.get("likelihood"),
                "vulnerability_class": metadata.get("vulnerability_class", []),
                "technology": metadata.get("technology", []),
                "references": (metadata.get("references") or [])[:3],
            }
            if truncated:
                meta["snippet_truncated"] = True
                meta["snippet_full_line_count"] = n_lines

            findings.append(Finding(
                finding_id=fid,
                fingerprint=make_fingerprint("semgrep", rule_id, repo, rel_path, snippet),
                tool="semgrep",
                rule_id=rule_id,
                message=extra["message"],
                severity_reported=SEVERITY_MAP.get(extra.get("severity"), "medium"),
                repo=repo,
                path=rel_path,
                line_start=line_start,
                line_end=line_end,
                cwe=extract_cwe(metadata),
                owasp=extract_owasp(metadata),
                commit_sha=sha_cache[repo],
                snippet=snippet,
                metadata=meta,
            ))

    print(f"raw findings (pre-dedup): {len(findings)}")
    print(f"finding_id collisions across repos: {id_collisions}")
    return findings


def dedup_by_fingerprint(findings: list[Finding]) -> list[Finding]:
    """Per docs/CONTRACTS.md Lane C: dedup by fingerprint, keep earliest line_start,
    record the collision count. fingerprint deliberately excludes line number, so this
    also catches near-identical repeated snippets within the same file/rule/repo."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.fingerprint].append(f)

    deduped: list[Finding] = []
    collisions = 0
    for group in groups.values():
        group.sort(key=lambda f: f.line_start)
        survivor = group[0]
        if len(group) > 1:
            collisions += 1
            survivor = Finding(**{**survivor.to_dict(), "metadata": {**survivor.metadata, "dup_count": len(group)}})
        deduped.append(survivor)

    print(f"fingerprint collisions (>1 finding sharing a fingerprint): {collisions}")
    print(f"findings after dedup: {len(deduped)}")
    return deduped


def validate(findings: list[Finding]) -> None:
    for f in findings:
        jsonschema.validate(f.to_dict(), FINDING_SCHEMA)


def write_corpus(findings: list[Finding]) -> None:
    findings = sorted(findings, key=lambda f: (f.repo, f.path, f.line_start))
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    with FINDINGS_PATH.open("w") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict()) + "\n")

    with LABELS_PATH.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["finding_id", "label", "confidence", "rater", "labelled_at", "notes"])
        for f in findings:
            # Deliberately blank past finding_id: a human labels this, not this script.
            # labelled_at is filled in by the rater at label time — its absence here IS
            # the evidence that labelling hasn't happened yet.
            writer.writerow([f.finding_id, "", "", "", "", ""])

    print(f"wrote {len(findings)} findings -> {FINDINGS_PATH.relative_to(REPO_ROOT)}")
    print(f"wrote {len(findings)} label rows -> {LABELS_PATH.relative_to(REPO_ROOT)}")


def print_summary(findings: list[Finding]) -> None:
    by_repo = Counter(f.repo for f in findings)
    by_rule = Counter(f.metadata["rule_short_name"] for f in findings)
    by_cwe = Counter(f.cwe or "NONE" for f in findings)
    by_sev = Counter(f.severity_reported for f in findings)

    print("\n--- by repo (nonzero) ---")
    for repo, n in by_repo.most_common():
        print(f"  {n:4d}  {repo}")
    print("\n--- by rule ---")
    for rule, n in by_rule.most_common():
        print(f"  {n:4d}  {rule}")
    print("\n--- by CWE ---")
    for cwe, n in by_cwe.most_common():
        print(f"  {n:4d}  {cwe}")
    print("\n--- by severity_reported ---")
    for sev, n in by_sev.most_common():
        print(f"  {n:4d}  {sev}")
    print(f"\nrepos with >=1 finding: {len(by_repo)}")
    print(f"distinct rules: {len(by_rule)}")
    print(f"TOTAL: {len(findings)}")


def main() -> None:
    findings = build_findings()
    # Index identical lines apart before dedup, otherwise two distinct defects on
    # byte-identical lines collapse into one and the second silently leaves the corpus.
    findings = assign_occurrences(findings)
    findings = dedup_by_fingerprint(findings)
    validate(findings)
    write_corpus(findings)
    print_summary(findings)


if __name__ == "__main__":
    main()
