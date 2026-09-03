"""Verdict schema — model output is OBSERVATIONS ONLY (binding decision D8).

`ssvc_decision`, `severity` and `recommended_action` are deliberately absent.
They are computed by `pramaan.policy.engine`, a pure function, because a rubric
encoded in a prompt is a rubric an injected code comment can rewrite. The model
reports what it saw; the policy decides what happens.

The model's own opinion of the action MAY be logged separately as a divergence
metric, but it never reaches the actuator.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

VerdictLabel = Literal["true_positive", "false_positive", "needs_human"]
Reachability = Literal["reachable_from_http", "internal_only", "dead_code", "unknown"]


@dataclass(frozen=True, slots=True)
class Evidence:
    file: str
    line: int
    why: str


@dataclass(frozen=True, slots=True)
class BusinessImpact:
    """The model's *observations*. Unioned with the deterministic path tagger (D9)."""

    payment_path: bool = False
    auth_or_session: bool = False
    pci_scope_hint: bool = False
    kyc_or_settlement: bool = False

    def union(self, other: BusinessImpact) -> BusinessImpact:
        """D9: sensitivity is monotonic. A tag can be added, never removed."""
        return BusinessImpact(
            payment_path=self.payment_path or other.payment_path,
            auth_or_session=self.auth_or_session or other.auth_or_session,
            pci_scope_hint=self.pci_scope_hint or other.pci_scope_hint,
            kyc_or_settlement=self.kyc_or_settlement or other.kyc_or_settlement,
        )

    @property
    def any_sensitive(self) -> bool:
        return (
            self.payment_path
            or self.auth_or_session
            or self.pci_scope_hint
            or self.kyc_or_settlement
        )


@dataclass(frozen=True, slots=True)
class Verdict:
    finding_id: str
    verdict: VerdictLabel
    confidence: float
    cwe: str
    evidence: list[Evidence]
    reachability: Reachability
    business_impact: BusinessImpact
    injection_observed: bool
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Verdict:
        return cls(
            finding_id=d["finding_id"],
            verdict=d["verdict"],
            confidence=float(d["confidence"]),
            cwe=d["cwe"],
            evidence=[Evidence(**e) for e in d.get("evidence", [])],
            reachability=d["reachability"],
            business_impact=BusinessImpact(**d.get("business_impact", {})),
            injection_observed=bool(d["injection_observed"]),
            rationale=d["rationale"],
        )


VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "finding_id", "verdict", "confidence", "cwe", "evidence",
        "reachability", "business_impact", "injection_observed", "rationale",
    ],
    "properties": {
        "finding_id": {"type": "string", "minLength": 1},
        "verdict": {"enum": ["true_positive", "false_positive", "needs_human"]},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "cwe": {"type": "string"},
        "evidence": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["file", "line", "why"],
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 0},
                    "why": {"type": "string", "minLength": 1},
                },
            },
        },
        "reachability": {
            "enum": ["reachable_from_http", "internal_only", "dead_code", "unknown"]
        },
        "business_impact": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "payment_path", "auth_or_session", "pci_scope_hint", "kyc_or_settlement"
            ],
            "properties": {
                "payment_path": {"type": "boolean"},
                "auth_or_session": {"type": "boolean"},
                "pci_scope_hint": {"type": "boolean"},
                "kyc_or_settlement": {"type": "boolean"},
            },
        },
        "injection_observed": {"type": "boolean"},
        "rationale": {"type": "string", "minLength": 1},
    },
}
