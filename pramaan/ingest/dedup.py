"""Fingerprint-based dedup of ingested findings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from pramaan.schemas.finding import Finding


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
