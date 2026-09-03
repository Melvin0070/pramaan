"""The 10% auto-close audit draw (TODO 2).

The act-vs-escalate policy closes a false positive at or above tau without a
human ever reading it, and routes 10% of those closures to an audit queue. An
audit queue nobody audits is a control that exists on paper, which a security
reviewer spots immediately — so this module does two things and says so plainly:

  * draws the sample **reproducibly**, from a published seed, so a reader can
    recompute exactly which findings were supposed to be audited; and
  * makes "the sample was queued but not audited in this build" a first-class
    output rather than an omission. `unaudited_statement()` exists to be pasted
    into the report when no audit happened.

The draw is a SHA-256 ordering rather than `random.shuffle`, for the same reason
the k-fold permutation is: "seed=X" is only a verifiable claim if the reader can
rebuild the draw without running this code, in this language, at this Python
version. Sorting `sha256(seed|id)` is reproducible in a shell one-liner.

Sizing honesty, which matters more than the draw: at 121 findings the auto-close
frame is a few dozen and a 10% sample is a handful. Finding zero errors in ten
audited closures is consistent with a true error rate of up to 26%, and
`AuditResult` reports that bound rather than the 0% that a naive division gives.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from pramaan.evals.stats import EvalError, InsufficientData, Rate, zero_events_upper_bound

__all__ = [
    "DEFAULT_AUDIT_FRACTION",
    "AuditOutcome",
    "AuditResult",
    "AuditSample",
    "draw",
    "eligible_ids",
    "record",
]

DEFAULT_AUDIT_FRACTION = 0.10


def eligible_ids(decisions: Iterable[Any]) -> tuple[str, ...]:
    """Finding ids from the auto-close frame.

    Reads `Decision.audit_sample_eligible`, which the policy engine sets on
    exactly the row-1 auto-closures. Anything else — escalations, tickets, fix
    candidates — already has a human attached and is not what this sample is
    for.

    Accepts `(finding_id, decision)` pairs or objects carrying both.
    """
    out: list[str] = []
    for entry in decisions:
        if isinstance(entry, tuple) and len(entry) == 2:
            finding_id, decision = entry
        else:
            finding_id = getattr(entry, "finding_id", None)
            decision = getattr(entry, "decision", entry)
        if finding_id is None:
            raise EvalError(
                "cannot determine finding_id; pass (finding_id, decision) pairs"
            )
        if getattr(decision, "audit_sample_eligible", False):
            out.append(str(finding_id))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class AuditSample:
    """A reproducible draw from the auto-close frame."""

    seed: str
    fraction: float
    frame_size: int
    sample_ids: tuple[str, ...]
    frame_digest: str
    min_size: int = 1

    @property
    def size(self) -> int:
        return len(self.sample_ids)

    @property
    def realised_fraction(self) -> float:
        return 0.0 if self.frame_size == 0 else self.size / self.frame_size

    def verify(self, frame: Sequence[str]) -> bool:
        """Recompute the whole draw — sample, frame size and frame digest.

        A published sample that cannot be verified is a published assertion.
        The frame digest is part of the comparison because a hash-ordered draw
        is deliberately stable under small frame changes: removing an unsampled
        finding leaves the sample identical, and a verifier that only compared
        ids would call that the same draw when it is a draw from a different
        population.
        """
        return (
            draw(
                frame,
                fraction=self.fraction,
                seed=self.seed,
                min_size=self.min_size,
            )
            == self
        )

    def unaudited_statement(self) -> str:
        """The sentence to publish when the sample was drawn but not audited.

        TODO 2 gives two acceptable answers — audit it, or say plainly that
        nobody did. This is the second answer, written out, so that omitting it
        is a deliberate act rather than an oversight.
        """
        return (
            f"A {self.fraction:.0%} random sample of the auto-closed findings "
            f"({self.size} of {self.frame_size}) was drawn with seed "
            f"{self.seed!r} and queued for audit. NO AUDIT WAS PERFORMED in "
            f"this build: no auditor is named, no outcomes are recorded, and "
            f"the auto-close error rate is therefore unmeasured. The sampled "
            f"ids are published so the audit can be reproduced by anyone: "
            f"{', '.join(self.sample_ids) if self.sample_ids else '(empty frame)'}."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "fraction": self.fraction,
            "frame_size": self.frame_size,
            "frame_digest": self.frame_digest,
            "sample_size": self.size,
            "realised_fraction": self.realised_fraction,
            "sample_ids": list(self.sample_ids),
        }


@dataclass(frozen=True, slots=True)
class AuditOutcome:
    """One audited closure. `agreed` means the auto-close was correct."""

    finding_id: str
    agreed: bool
    note: str = ""


@dataclass(frozen=True, slots=True)
class AuditResult:
    sample: AuditSample
    auditor: str
    n_audited: int
    n_errors: int
    error_rate: Rate
    zero_error_upper_bound: float | None
    projected_frame_errors: tuple[float, float] | None
    unaudited_ids: tuple[str, ...]
    errors: tuple[AuditOutcome, ...]
    notes: tuple[str, ...] = ()

    def render(self) -> str:
        lines = [
            f"auto-close audit ({self.auditor}): {self.n_audited} of "
            f"{self.sample.size} sampled closures reviewed",
            f"  {self.error_rate.render()}",
        ]
        if self.zero_error_upper_bound is not None:
            lines.append(
                f"  zero errors found; 95% upper bound on the true auto-close "
                f"error rate is {self.zero_error_upper_bound:.2f}"
            )
        if self.projected_frame_errors is not None:
            lo, hi = self.projected_frame_errors
            lines.append(
                f"  projected wrong closures across the {self.sample.frame_size}"
                f"-finding frame: {lo:.1f}–{hi:.1f}"
            )
        for err in self.errors:
            lines.append(f"  ERROR {err.finding_id}: {err.note or 'no note'}")
        if self.unaudited_ids:
            lines.append(
                f"  {len(self.unaudited_ids)} sampled findings were not "
                f"reviewed: {', '.join(self.unaudited_ids)}"
            )
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample": self.sample.to_dict(),
            "auditor": self.auditor,
            "n_audited": self.n_audited,
            "n_errors": self.n_errors,
            "error_rate": self.error_rate.to_dict(),
            "zero_error_upper_bound": self.zero_error_upper_bound,
            "projected_frame_errors": (
                list(self.projected_frame_errors)
                if self.projected_frame_errors
                else None
            ),
            "unaudited_ids": list(self.unaudited_ids),
            "errors": [
                {"finding_id": e.finding_id, "note": e.note} for e in self.errors
            ],
            "notes": list(self.notes),
        }


def _rank(seed: str, finding_id: str) -> str:
    return hashlib.sha256(f"{seed}|{finding_id}".encode("utf-8")).hexdigest()


def draw(
    frame: Sequence[str],
    *,
    fraction: float = DEFAULT_AUDIT_FRACTION,
    seed: str,
    min_size: int = 1,
) -> AuditSample:
    """Draw the audit sample from the auto-close frame.

    Deterministic in `(frame contents, fraction, seed)` and independent of the
    order the frame is supplied in, so two people who agree on which findings
    were auto-closed will agree on which ones to audit.

    Args:
        frame: finding ids eligible for audit (`audit_sample_eligible`).
        fraction: share to draw. 10% is the policy commitment.
        seed: published alongside the sample. Not optional — an unseeded draw
            is not reproducible and therefore not a control.
        min_size: floor on the sample size, so a small frame still yields at
            least one item to look at. Capped by the frame size.

    Raises:
        EvalError: duplicate ids in the frame (the sample would be ambiguous).
    """
    if not 0.0 < fraction <= 1.0:
        raise ValueError(f"fraction must be in (0, 1], got {fraction}")
    if not seed or not seed.strip():
        raise ValueError("seed must be a non-empty published string")
    if min_size < 0:
        raise ValueError("min_size must be >= 0")

    ids = list(frame)
    if len(set(ids)) != len(ids):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        raise EvalError(f"duplicate ids in the audit frame: {duplicates}")

    unique = sorted(ids)
    digest = hashlib.sha256("\n".join(unique).encode("utf-8")).hexdigest()[:16]
    if not unique:
        return AuditSample(
            seed=seed,
            fraction=fraction,
            frame_size=0,
            sample_ids=(),
            frame_digest=digest,
            min_size=min_size,
        )

    size = min(len(unique), max(min_size, math.ceil(fraction * len(unique))))
    ordered = sorted(unique, key=lambda i: _rank(seed, i))
    # Re-sorted so the published list reads in a stable, human-checkable order;
    # membership, not order, is what the draw decides.
    return AuditSample(
        seed=seed,
        fraction=fraction,
        frame_size=len(unique),
        sample_ids=tuple(sorted(ordered[:size])),
        frame_digest=digest,
        min_size=min_size,
    )


def record(
    sample: AuditSample,
    outcomes: Iterable[AuditOutcome],
    *,
    auditor: str,
    min_n: int = 5,
) -> AuditResult:
    """Record an audit. `auditor` is mandatory (TODO 2).

    An audit with no named auditor is the paper control this TODO exists to
    close, so there is no way to produce an `AuditResult` without naming
    someone. If nobody audited the sample, publish
    `AuditSample.unaudited_statement()` instead — that is the honest output, and
    it is a supported one.
    """
    if not auditor or not auditor.strip():
        raise EvalError(
            "an audit needs a named auditor; if nobody audited the sample, "
            "publish AuditSample.unaudited_statement() rather than an "
            "AuditResult with an empty name"
        )
    recorded = list(outcomes)
    seen = [o.finding_id for o in recorded]
    if len(set(seen)) != len(seen):
        raise EvalError("the same finding was audited twice")
    stray = sorted(set(seen) - set(sample.sample_ids))
    if stray:
        raise EvalError(
            f"audit outcomes for findings outside the drawn sample: {stray}"
        )
    if not recorded:
        raise InsufficientData(
            "no audit outcomes recorded; use unaudited_statement() instead"
        )

    errors = tuple(o for o in recorded if not o.agreed)
    rate = Rate(
        len(errors),
        len(recorded),
        min_n=min_n,
        label="auto-close error rate (audited sample)",
    )
    upper = (
        zero_events_upper_bound(len(recorded)) if not errors else None
    )
    projected: tuple[float, float] | None = None
    interval = rate.interval
    if interval is not None:
        # No finite-population correction: the sample is drawn without
        # replacement from a small frame, so the true interval is narrower than
        # this. Erring wide is the direction that cannot overstate the result.
        projected = (
            interval[0] * sample.frame_size,
            interval[1] * sample.frame_size,
        )

    unaudited = tuple(sorted(set(sample.sample_ids) - set(seen)))
    notes: list[str] = []
    if unaudited:
        notes.append(
            f"{len(unaudited)} of {sample.size} sampled findings were not "
            "reviewed; the rate below is over what was actually audited"
        )
    if not rate.reportable:
        notes.append(
            f"n={len(recorded)} audited: report the counts, not the rate"
        )
    if errors:
        notes.append(
            f"{len(errors)} auto-closures were wrong; those findings were "
            "closed without a human and the closure was incorrect"
        )
    notes.append(
        "the projected range carries no finite-population correction and is "
        "therefore wider than the true interval"
    )

    return AuditResult(
        sample=sample,
        auditor=auditor.strip(),
        n_audited=len(recorded),
        n_errors=len(errors),
        error_rate=rate,
        zero_error_upper_bound=upper,
        projected_frame_errors=projected,
        unaudited_ids=unaudited,
        errors=errors,
        notes=tuple(notes),
    )
