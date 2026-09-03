"""Attempt-level status (binding decision D10).

Every call to the triage agent produces an Attempt, valid or not. A run that
returns unparseable JSON is a *recorded outcome*, not a retry-until-it-works.
`schema_invalid` counts as a NON-MATCH in pass^k — silently retrying it would
inflate the consistency number, which is the metric this project exists to make
trustworthy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

AttemptStatus = Literal[
    "valid",          # parsed and schema-validated
    "schema_invalid", # returned JSON that failed VERDICT_SCHEMA
    "truncated",      # hit max_turns / output cut off mid-object
    "budget_abort",   # max_budget_usd or task_budget exhausted
    "refused",        # model declined to answer
]

ALL_ATTEMPT_STATUSES: tuple[str, ...] = (
    "valid", "schema_invalid", "truncated", "budget_abort", "refused",
)


@dataclass(frozen=True, slots=True)
class Attempt:
    finding_id: str
    # The cache is keyed on fingerprint, not finding_id: a defect that shifts line
    # numbers is the same defect. Carried here so an Attempt can derive its own
    # cache key without the caller threading it separately.
    fingerprint: str
    run_index: int
    status: AttemptStatus
    verdict: dict[str, Any] | None
    raw_text: str | None
    model: str
    effort: str
    context_config: str
    prompt_hash: str
    run_epoch: str
    cost_usd: float = 0.0
    duration_s: float = 0.0
    num_turns: int = 0
    system_fingerprint: str | None = None  # D19: provider-side drift detector
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return self.status == "valid" and self.verdict is not None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Attempt:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})
