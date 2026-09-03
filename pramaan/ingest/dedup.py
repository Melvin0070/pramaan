"""Fingerprint-based dedup of ingested findings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from pramaan.schemas.finding import Finding, make_fingerprint


def dedup(findings: list[Finding]) -> list[Finding]:
    """Group `findings` by `fingerprint`, keeping one record per group.

    `fingerprint` (see `make_fingerprint`) deliberately excludes the line
    number, so the same defect shifting down a few lines because of an
    unrelated edit above it collapses to one record instead of drifting
    into a second one. On a collision the record with the earliest
    `line_start` is kept — as good a proxy as any for "the original"
    without touching the clock or git history — and `metadata["dup_count"]`
    is set to the size of the collision group, i.e. how many raw results
    this one record now stands in for.

    Groups of size one are returned unchanged, with no `dup_count` added:
    that key means "a collision happened here," not "this finding was
    checked for collisions."
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[finding.fingerprint].append(finding)

    deduped: list[Finding] = []
    for group in groups.values():
        if len(group) == 1:
            deduped.append(group[0])
            continue
        canonical = min(group, key=lambda f: f.line_start)
        deduped.append(
            replace(canonical, metadata={**canonical.metadata, "dup_count": len(group)})
        )
    return deduped


def assign_occurrences(findings: list[Finding]) -> list[Finding]:
    """Re-derive fingerprints with a per-file occurrence index.

    Two byte-identical vulnerable lines in one file hash to the same fingerprint
    unless something tells them apart, and `dedup` would then fold a real second
    defect into the first. Indexing by line order within each
    (rule, repo, path, snippet) group keeps the index stable under edits elsewhere
    in the file, which is the property the verdict cache depends on.

    Run this before `dedup`, so what `dedup` collapses afterwards is genuinely
    repeated scanner output rather than two distinct findings.
    """
    groups: dict[tuple[str, str, str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        key = (
            finding.rule_id,
            finding.repo,
            finding.path,
            " ".join((finding.snippet or "").split()),
        )
        groups[key].append(finding)

    reindexed: dict[int, Finding] = {}
    for group in groups.values():
        # Index by distinct line, not by record: two results at the *same* line are
        # the scanner reporting one defect twice and must still collapse, while two
        # at different lines are two defects and must not.
        lines = sorted({f.line_start for f in group})
        order = {line: index for index, line in enumerate(lines)}
        for finding in group:
            occurrence = order[finding.line_start]
            reindexed[id(finding)] = replace(
                finding,
                fingerprint=make_fingerprint(
                    finding.tool,
                    finding.rule_id,
                    finding.repo,
                    finding.path,
                    finding.snippet,
                    occurrence,
                ),
            )
    # Preserve the caller's ordering; only the fingerprints changed.
    return [reindexed[id(f)] for f in findings]
