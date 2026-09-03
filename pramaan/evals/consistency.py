"""pass^k — does the harness give the same answer twice? (D10)

pass^k, not pass@k. pass@k asks whether *any* of k samples succeeded and is the
right metric when you can verify the answer and keep the good one. Triage cannot:
nobody re-runs a finding five times and picks the verdict they like. So the
question is whether all k runs agree, and a group scores 1 only if every one of
its k attempts is schema-valid and carries the identical verdict.

The rule that does the work here is D10: **a `schema_invalid` attempt is a
non-match.** It is tempting to treat unparseable output as a transport hiccup and
retry it away. That would be inflation, not measurement — the harness genuinely
failed to produce a verdict that time, and a consistency number that quietly
excludes its own failures is the number this project exists to distrust. The
same applies to `truncated`, `budget_abort` and `refused`. All five statuses are
counted, and the schema-failure rate is published beside pass^k rather than
buried.

Everything here reads cached `Attempt` rows. No network, no clock, no model.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pramaan.evals.stats import EvalError, InsufficientData, Rate
from pramaan.schemas import ALL_ATTEMPT_STATUSES, Attempt

__all__ = [
    "ConsistencyResult",
    "GroupKey",
    "GroupOutcome",
    "InconsistentGroup",
    "attempt_corpus",
    "group_sizes",
    "pass_at_k",
    "pass_at_k_by_corpus",
    "schema_failure_rate",
]

# The six cache-key dimensions that a pass^k group must hold constant. `run_index`
# is the one dimension that varies *within* a group — that is what makes the k
# runs k runs. `run_epoch` is inside the key, so a nightly epoch and a CI epoch
# never merge into one group of ten (D19).
GroupKey = tuple[str, str, str, str, str, str]

_GROUP_FIELDS: tuple[str, ...] = (
    "fingerprint",
    "model",
    "effort",
    "context_config",
    "prompt_hash",
    "run_epoch",
)


class InconsistentGroup(EvalError):
    """A pass^k group whose shape is wrong — the wrong number of runs, or two
    attempts claiming the same `run_index`."""


def _group_key(attempt: Attempt) -> GroupKey:
    return tuple(getattr(attempt, f) for f in _GROUP_FIELDS)  # type: ignore[return-value]


def attempt_corpus(attempt: Attempt, *, default: str | None = None) -> str:
    """Which corpus an attempt belongs to (D16).

    Raises when the attempt does not say and no default is given: an unlabelled
    attempt is exactly the row that would blend OWASP Benchmark into the real
    PHP numbers without anyone noticing.
    """
    corpus = (attempt.metadata or {}).get("corpus")
    if isinstance(corpus, str) and corpus.strip():
        return corpus
    if default is not None:
        return default
    raise EvalError(
        f"attempt {attempt.finding_id!r} carries no metadata['corpus']; "
        "D16 forbids scoring it into an unnamed pool"
    )


@dataclass(frozen=True, slots=True)
class GroupOutcome:
    """One finding's k runs."""

    key: GroupKey
    finding_id: str
    n_attempts: int
    matched: bool
    signatures: tuple[tuple[Any, ...], ...]
    statuses: tuple[str, ...]
    reason: str

    @property
    def fingerprint(self) -> str:
        return self.key[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": dict(zip(_GROUP_FIELDS, self.key)),
            "finding_id": self.finding_id,
            "n_attempts": self.n_attempts,
            "matched": self.matched,
            "statuses": list(self.statuses),
            "signatures": [list(s) for s in self.signatures],
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ConsistencyResult:
    corpus: str
    k: int
    key_fields: tuple[str, ...]
    pass_k: Rate
    groups: tuple[GroupOutcome, ...]
    status_counts: dict[str, int]
    schema_failure: Rate
    invalid_attempt: Rate
    incomplete_groups: tuple[GroupKey, ...]
    failure_reasons: dict[str, int]
    notes: tuple[str, ...] = ()

    @property
    def n_attempts(self) -> int:
        return sum(self.status_counts.values())

    def render(self) -> str:
        lines = [
            f"pass^{self.k} ({self.corpus}) over "
            f"{', '.join(self.key_fields)}",
            f"  {self.pass_k.render()}",
            f"  {self.schema_failure.render()}",
            f"  {self.invalid_attempt.render()}",
            "  statuses: "
            + ", ".join(f"{k}={v}" for k, v in sorted(self.status_counts.items())),
        ]
        if self.failure_reasons:
            lines.append(
                "  failures: "
                + ", ".join(
                    f"{k}={v}" for k, v in sorted(self.failure_reasons.items())
                )
            )
        if self.incomplete_groups:
            lines.append(
                f"  incomplete groups counted as non-matches: "
                f"{len(self.incomplete_groups)}"
            )
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "k": self.k,
            "key_fields": list(self.key_fields),
            "pass_k": self.pass_k.to_dict(),
            "schema_failure_rate": self.schema_failure.to_dict(),
            "invalid_attempt_rate": self.invalid_attempt.to_dict(),
            "status_counts": dict(self.status_counts),
            "failure_reasons": dict(self.failure_reasons),
            "n_groups": len(self.groups),
            "n_attempts": self.n_attempts,
            "incomplete_groups": [dict(zip(_GROUP_FIELDS, g)) for g in self.incomplete_groups],
            "notes": list(self.notes),
        }


def schema_failure_rate(attempts: Sequence[Attempt], *, min_n: int = 5) -> Rate:
    """Share of attempts that returned JSON failing `VERDICT_SCHEMA` (D10).

    Published in its own right. It is the honest denominator behind every
    consistency claim, and it is the number that moves when a model update
    changes structured-output behaviour.
    """
    invalid = sum(1 for a in attempts if a.status == "schema_invalid")
    return Rate(
        invalid,
        len(attempts),
        min_n=min_n,
        label="schema-failure rate",
    )


def pass_at_k(
    attempts: Iterable[Attempt],
    *,
    k: int = 5,
    key_fields: Sequence[str] = ("verdict",),
    strict: bool = True,
    corpus: str | None = None,
    min_n: int = 5,
) -> ConsistencyResult:
    """pass^k over cached attempts.

    A group is the k runs sharing every cache-key dimension but `run_index`. It
    matches only when all k attempts are `valid` **and** their verdicts agree on
    `key_fields`.

    Args:
        k: runs per finding.
        key_fields: which verdict fields must agree. Default is the label alone,
            which is what the CI gate is set against. Passing `("verdict","cwe")`
            asks the stricter question and will produce a lower number; say
            which one you published.
        strict: a group with the wrong number of attempts raises. With
            `strict=False` it is counted as a **non-match** and listed in
            `incomplete_groups` — failing closed, never dropped, because
            dropping short groups is how a half-finished nightly run reports
            100% consistency.
        corpus: label for the report. D16 blending is the caller's error; use
            `pass_at_k_by_corpus` over mixed input.

    Raises:
        InconsistentGroup: duplicate `run_index` within a group, or (under
            `strict`) a group whose size is not k.
        InsufficientData: no attempts at all.
    """
    rows = list(attempts)
    if not rows:
        raise InsufficientData("pass_at_k() needs attempts")
    if k < 1:
        raise ValueError(f"k must be >= 1, got {k}")
    fields = tuple(key_fields)
    if not fields:
        raise ValueError("key_fields must name at least one verdict field")

    grouped: dict[GroupKey, list[Attempt]] = {}
    for attempt in rows:
        grouped.setdefault(_group_key(attempt), []).append(attempt)

    outcomes: list[GroupOutcome] = []
    incomplete: list[GroupKey] = []
    reasons: dict[str, int] = {}

    for key in sorted(grouped):
        members = sorted(grouped[key], key=lambda a: a.run_index)
        indices = [a.run_index for a in members]
        if len(set(indices)) != len(indices):
            raise InconsistentGroup(
                f"duplicate run_index {indices} for fingerprint {key[0]!r}; "
                "two attempts are claiming to be the same run"
            )
        statuses = tuple(a.status for a in members)
        finding_id = members[0].finding_id

        if len(members) != k:
            if strict:
                raise InconsistentGroup(
                    f"fingerprint {key[0]!r} has {len(members)} attempts, "
                    f"expected k={k}; pass strict=False to count short groups "
                    "as non-matches instead"
                )
            incomplete.append(key)
            reasons["incomplete_group"] = reasons.get("incomplete_group", 0) + 1
            outcomes.append(
                GroupOutcome(
                    key=key,
                    finding_id=finding_id,
                    n_attempts=len(members),
                    matched=False,
                    signatures=(),
                    statuses=statuses,
                    reason=f"only {len(members)}/{k} attempts recorded",
                )
            )
            continue

        bad = [a for a in members if not a.is_valid]
        if bad:
            # D10, stated in code: a run that produced no schema-valid verdict
            # is a run that disagreed. There is no repair path here on purpose.
            worst = sorted({a.status for a in bad})
            for status in worst:
                reasons[status] = reasons.get(status, 0) + 1
            outcomes.append(
                GroupOutcome(
                    key=key,
                    finding_id=finding_id,
                    n_attempts=len(members),
                    matched=False,
                    signatures=(),
                    statuses=statuses,
                    reason=f"non-valid attempts: {', '.join(worst)}",
                )
            )
            continue

        signatures = tuple(
            tuple((a.verdict or {}).get(f) for f in fields) for a in members
        )
        matched = len(set(signatures)) == 1
        if not matched:
            reasons["disagreement"] = reasons.get("disagreement", 0) + 1
        outcomes.append(
            GroupOutcome(
                key=key,
                finding_id=finding_id,
                n_attempts=len(members),
                matched=matched,
                signatures=signatures,
                statuses=statuses,
                reason="all runs agree" if matched else "runs disagree",
            )
        )

    matched_n = sum(1 for o in outcomes if o.matched)
    status_counts = {s: 0 for s in ALL_ATTEMPT_STATUSES}
    for attempt in rows:
        status_counts[attempt.status] = status_counts.get(attempt.status, 0) + 1

    notes: list[str] = []
    if incomplete:
        notes.append(
            f"{len(incomplete)} groups had fewer than k={k} attempts and are "
            "counted as non-matches, not excluded"
        )
    if len(outcomes) < min_n:
        notes.append(
            f"only {len(outcomes)} findings in this pass^{k} measurement; the "
            "interval is wider than the CI gate it would be checked against"
        )
    epochs = {key[5] for key in grouped}
    if len(epochs) > 1:
        notes.append(
            f"{len(epochs)} distinct run_epochs present; groups are kept apart "
            "by epoch, so a cached CI run and a fresh nightly run are never "
            "merged into one group (D19)"
        )

    return ConsistencyResult(
        corpus=corpus or "unnamed",
        k=k,
        key_fields=fields,
        pass_k=Rate(matched_n, len(outcomes), min_n=min_n, label=f"pass^{k}"),
        groups=tuple(outcomes),
        status_counts=status_counts,
        schema_failure=schema_failure_rate(rows, min_n=min_n),
        invalid_attempt=Rate(
            sum(1 for a in rows if a.status != "valid"),
            len(rows),
            min_n=min_n,
            label="non-valid attempt rate",
        ),
        incomplete_groups=tuple(incomplete),
        failure_reasons=reasons,
        notes=tuple(notes),
    )


def pass_at_k_by_corpus(
    attempts: Iterable[Attempt],
    *,
    corpus_of: Callable[[Attempt], str] = attempt_corpus,
    **kwargs: Any,
) -> dict[str, ConsistencyResult]:
    """One `ConsistencyResult` per corpus (D16). Never one pooled number."""
    buckets: dict[str, list[Attempt]] = {}
    for attempt in attempts:
        buckets.setdefault(corpus_of(attempt), []).append(attempt)
    return {
        name: pass_at_k(rows, corpus=name, **kwargs)
        for name, rows in sorted(buckets.items())
    }


def group_sizes(attempts: Iterable[Attempt]) -> Mapping[GroupKey, int]:
    """Diagnostic: how many runs each group actually holds. Useful before
    calling `pass_at_k(strict=True)` on a run you did not supervise."""
    sizes: dict[GroupKey, int] = {}
    for attempt in attempts:
        key = _group_key(attempt)
        sizes[key] = sizes.get(key, 0) + 1
    return sizes
