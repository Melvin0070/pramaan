"""Normalised finding schema — the ingest boundary.

One `Finding` is one scanner result after normalisation and dedup. Everything
downstream (triage, policy, fix, proof, report) keys off `finding_id`, and the
verdict cache keys off `fingerprint`.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    fingerprint: str
    tool: str
    rule_id: str
    message: str
    severity_reported: Severity
    repo: str
    path: str
    line_start: int
    line_end: int
    cwe: str | None = None
    owasp: str | None = None
    commit_sha: str | None = None
    snippet: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


def make_finding_id(
    tool: str, rule_id: str, repo: str, path: str, line_start: int
) -> str:
    """Human-readable, stable within a commit. Used for tickets and PR idempotency.

    `repo` is part of the identity because plugins vendor each other's files: two
    Razorpay payment-button plugins ship a byte-identical PHP file at the same path,
    which without the repo term produced six colliding ids in the real corpus. The
    store keys on `finding_id`, so a collision is a silently dropped finding.
    """
    return f"{tool}:{rule_id}:{repo}:{path}:{line_start}"


def make_fingerprint(
    tool: str,
    rule_id: str,
    repo: str,
    path: str,
    snippet: str | None,
    occurrence: int = 0,
) -> str:
    """DefectDojo-style dedup hash.

    Deliberately excludes the line number: the same defect shifting down by an
    unrelated edit above it must dedup to one finding, not two. Snippet is
    whitespace-normalised for the same reason.

    `occurrence` is what keeps that from over-collapsing. Two byte-identical
    vulnerable lines in one file are two defects, and folding them into one record
    means a fix lands on the first and the second silently survives -- the exact
    failure a suppression-detector is supposed to catch. Ingest assigns the index by
    line order within a file, so it is stable under edits elsewhere in the file while
    still telling the second occurrence apart from the first.
    """
    normalised = " ".join((snippet or "").split())
    payload = "|".join([tool, rule_id, repo, path, normalised, str(occurrence)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "finding_id", "fingerprint", "tool", "rule_id", "message",
        "severity_reported", "repo", "path", "line_start", "line_end",
    ],
    "properties": {
        "finding_id": {"type": "string", "minLength": 1},
        "fingerprint": {"type": "string", "minLength": 8},
        "tool": {"type": "string"},
        "rule_id": {"type": "string"},
        "message": {"type": "string"},
        "severity_reported": {"enum": ["critical", "high", "medium", "low", "info"]},
        "repo": {"type": "string"},
        "path": {"type": "string"},
        "line_start": {"type": "integer", "minimum": 0},
        "line_end": {"type": "integer", "minimum": 0},
        "cwe": {"type": ["string", "null"]},
        "owasp": {"type": ["string", "null"]},
        "commit_sha": {"type": ["string", "null"]},
        "snippet": {"type": ["string", "null"]},
        "metadata": {"type": "object"},
    },
}
