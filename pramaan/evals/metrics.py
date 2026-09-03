"""Precision, recall and F1 for the false-positive class — and the miss rate.

The positive class here is `false_positive`, because that is the class the
harness acts on: an FP verdict at or above tau is closed without a human ever
reading it. So the four cells of the confusion matrix have operational names,
and two of them are not symmetric at all:

    model says FP, really is FP   -> a correct auto-close
    model says FP, really is TP   -> a MISS: a real defect suppressed silently
    model says TP, really is FP   -> a needless review: a human's twenty minutes
    model says TP, really is TP   -> a correct escalation

A miss is not a needless review with the sign flipped. Practitioners' standing
complaint about FP-suppression tooling is that vendors publish precision and
never publish what the filter threw away, and Florian Roth's THOR benchmark
convention prices that asymmetry at 4:1. This module reports the miss rate on
its own, and reports a weighted cost with a miss at `MISS_WEIGHT` times a
needless review, against the two trivial baselines — review everything, close
everything — so a reader can see whether the harness beats doing nothing.

`needs_human` and unparsed outputs are not misses and not errors. They are the
harness declining to act, which is what the policy wants when it is unsure;
scoring them as wrong would train the design towards guessing. They fall on the
"not auto-closed" side of every count and are reported separately.

Passing `tau` scores the *operational* matrix — an FP verdict below tau is not
closed, so it costs a review rather than risking a miss. Passing `tau=None`
scores the classifier itself. Both are legitimate; say which one you published.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pramaan.evals.labels import (
    LabelledVerdict,
    check_scoring_unit,
    one_corpus,
    split_by_corpus,
)
from pramaan.evals.stats import InsufficientData, Rate

__all__ = [
    "MISS_WEIGHT",
    "Confusion",
    "CostModel",
    "MetricsResult",
    "confusion",
    "fp_class_metrics",
    "fp_class_metrics_per_corpus",
]

# THOR benchmark convention: a missed detection costs four needless reviews.
MISS_WEIGHT = 4.0


@dataclass(frozen=True, slots=True)
class Confusion:
    """FP class as positive. Field names say what each cell costs."""

    correct_auto_close: int   # predicted FP, truly FP
    miss: int                 # predicted FP, truly TP  <- the expensive cell
    needless_review: int      # not predicted FP, truly FP
    correct_escalation: int   # not predicted FP, truly TP
    undecidable_on_real: int  # needs_human / unparsed where the defect is real
    undecidable_on_fp: int    # needs_human / unparsed where it is not
    below_tau_on_real: int    # FP verdict the gate withheld, defect was real
    below_tau_on_fp: int      # FP verdict the gate withheld, defect was not

    @property
    def n(self) -> int:
        return (
            self.correct_auto_close
            + self.miss
            + self.needless_review
            + self.correct_escalation
        )

    @property
    def n_real_defects(self) -> int:
        return self.miss + self.correct_escalation

    @property
    def n_false_positives(self) -> int:
        return self.correct_auto_close + self.needless_review

    @property
    def n_predicted_fp(self) -> int:
        return self.correct_auto_close + self.miss

    def to_dict(self) -> dict[str, Any]:
        return {
            "correct_auto_close": self.correct_auto_close,
            "miss": self.miss,
            "needless_review": self.needless_review,
            "correct_escalation": self.correct_escalation,
            "undecidable_on_real": self.undecidable_on_real,
            "undecidable_on_fp": self.undecidable_on_fp,
            "below_tau_on_real": self.below_tau_on_real,
            "below_tau_on_fp": self.below_tau_on_fp,
            "n": self.n,
            "n_real_defects": self.n_real_defects,
            "n_false_positives": self.n_false_positives,
        }


@dataclass(frozen=True, slots=True)
class CostModel:
    """Asymmetric cost, in units of one needless review."""

    miss_weight: float
    total: float
    per_finding: float
    from_misses: float
    from_reviews: float
    review_everything: float
    close_everything: float

    @property
    def miss_share(self) -> float:
        """Fraction of total cost that is suppressed defects. A harness whose
        cost is 90% misses is not a triage aid, it is a filter with a leak."""
        return 0.0 if self.total == 0 else self.from_misses / self.total

    @property
    def vs_review_everything(self) -> float:
        """Ratio to the trivial baseline of escalating every finding.

        Above 1.0 means the harness costs more than a human reading everything,
        under this cost model. That is the number that decides whether the
        thing is worth running at all, and it is the one most easily left out.
        """
        return (
            float("inf")
            if self.review_everything == 0
            else self.total / self.review_everything
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "miss_weight": self.miss_weight,
            "total": self.total,
            "per_finding": self.per_finding,
            "from_misses": self.from_misses,
            "from_reviews": self.from_reviews,
            "miss_share": self.miss_share,
            "baseline_review_everything": self.review_everything,
            "baseline_close_everything": self.close_everything,
            "vs_review_everything": self.vs_review_everything,
        }


@dataclass(frozen=True, slots=True)
class MetricsResult:
    corpus: str
    tau: float | None
    matrix: Confusion
    precision: Rate
    recall: Rate
    f1: float | None
    miss_rate: Rate
    needless_review_rate: Rate
    cost: CostModel
    notes: tuple[str, ...] = ()

    def render(self) -> str:
        gate = "ungated (classifier)" if self.tau is None else f"tau={self.tau:.3f}"
        f1 = "undefined" if self.f1 is None else f"{self.f1:.3f}"
        lines = [
            f"FP-class metrics ({self.corpus}, {gate}), n={self.matrix.n}",
            f"  {self.precision.render()}",
            f"  {self.recall.render()}",
            f"  F1: {f1}",
            f"  {self.miss_rate.render()}",
            f"  {self.needless_review_rate.render()}",
            f"  cost @ {self.cost.miss_weight:g}x: {self.cost.total:.1f} "
            f"({self.cost.per_finding:.3f}/finding, "
            f"{self.cost.miss_share:.0%} of it from misses)",
            f"  baselines: review-everything {self.cost.review_everything:.1f}, "
            f"close-everything {self.cost.close_everything:.1f} "
            f"(harness/review-everything = {self.cost.vs_review_everything:.2f})",
        ]
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "tau": self.tau,
            "confusion": self.matrix.to_dict(),
            "precision_fp_class": self.precision.to_dict(),
            "recall_fp_class": self.recall.to_dict(),
            "f1_fp_class": self.f1,
            "miss_rate": self.miss_rate.to_dict(),
            "needless_review_rate": self.needless_review_rate.to_dict(),
            "cost": self.cost.to_dict(),
            "notes": list(self.notes),
        }


def confusion(
    items: Sequence[LabelledVerdict], *, tau: float | None = None
) -> Confusion:
    """Build the FP-class confusion matrix, optionally gated at `tau`.

    With `tau`, a false-positive verdict below the gate is *not* a positive
    prediction: the policy escalates it, so it costs a review and cannot
    produce a miss. That is the matrix the deployed system actually generates,
    and it is usually kinder than the ungated one — which is exactly why the
    gate has to be stated whenever the numbers are.
    """
    if tau is not None and not 0.0 <= tau <= 1.0:
        raise ValueError(f"tau must be in [0, 1], got {tau!r}")

    cells = dict.fromkeys(
        (
            "correct_auto_close",
            "miss",
            "needless_review",
            "correct_escalation",
            "undecidable_on_real",
            "undecidable_on_fp",
            "below_tau_on_real",
            "below_tau_on_fp",
        ),
        0,
    )
    for row in items:
        real = row.is_really_a_defect
        says_fp = row.says_false_positive
        gated_out = says_fp and tau is not None and row.confidence < tau
        predicted_fp = says_fp and not gated_out

        if not row.is_decidable:
            cells["undecidable_on_real" if real else "undecidable_on_fp"] += 1
        if gated_out:
            cells["below_tau_on_real" if real else "below_tau_on_fp"] += 1

        if predicted_fp:
            cells["miss" if real else "correct_auto_close"] += 1
        else:
            cells["correct_escalation" if real else "needless_review"] += 1
    return Confusion(**cells)


def fp_class_metrics(
    items: Sequence[LabelledVerdict],
    *,
    tau: float | None = None,
    miss_weight: float = MISS_WEIGHT,
    min_n: int = 5,
    allow_repeated_runs: bool = False,
) -> MetricsResult:
    """Precision, recall, F1 for the FP class plus the asymmetric-cost view.

    Pure. One corpus only (D16) — the OWASP Benchmark arm and the hand-labelled
    PHP arm have different base rates and pooling their precision produces a
    figure that describes neither. One row per finding, too: five verdicts about
    one defect are not five defects, and the miss rate is gated at 2%, which is
    a threshold a fivefold inflated denominator would sail under.
    """
    if not items:
        raise InsufficientData("fp_class_metrics() needs labelled rows")
    if miss_weight <= 0:
        raise ValueError("miss_weight must be > 0")
    corpus = one_corpus(items, what="fp_class_metrics")
    unit_notes = check_scoring_unit(
        items, what="fp_class_metrics", allow_repeated_runs=allow_repeated_runs
    )
    m = confusion(items, tau=tau)

    precision = Rate(
        m.correct_auto_close,
        m.n_predicted_fp,
        min_n=min_n,
        label="FP-class precision (auto-closes that were really false positives)",
    )
    recall = Rate(
        m.correct_auto_close,
        m.n_false_positives,
        min_n=min_n,
        label="FP-class recall (real false positives the harness closed)",
    )
    p, r = precision.point, recall.point
    f1 = None if p is None or r is None or (p + r) == 0 else 2 * p * r / (p + r)

    miss_rate = Rate(
        m.miss,
        m.n_real_defects,
        min_n=min_n,
        label="miss rate (real defects suppressed as false positives)",
    )
    needless = Rate(
        m.needless_review,
        m.n_false_positives,
        min_n=min_n,
        label="needless-review rate (false positives sent to a human anyway)",
    )

    from_misses = miss_weight * m.miss
    from_reviews = float(m.needless_review)
    cost = CostModel(
        miss_weight=miss_weight,
        total=from_misses + from_reviews,
        per_finding=0.0 if m.n == 0 else (from_misses + from_reviews) / m.n,
        from_misses=from_misses,
        from_reviews=from_reviews,
        # Escalate everything: every genuine FP becomes a review, no misses.
        review_everything=float(m.n_false_positives),
        # Close everything: every real defect is suppressed.
        close_everything=miss_weight * m.n_real_defects,
    )

    notes: list[str] = list(unit_notes)
    if not miss_rate.reportable:
        notes.append(
            f"miss rate is over {m.n_real_defects} real defects — too few to "
            "compare against the 2% CI gate; report the count, not the rate"
        )
    if not precision.reportable:
        notes.append(
            f"precision is over {m.n_predicted_fp} auto-close predictions; "
            "n too small to report as a rate"
        )
    undecidable = m.undecidable_on_real + m.undecidable_on_fp
    if undecidable:
        notes.append(
            f"{undecidable} findings produced needs_human or unparsed output; "
            "counted as not-auto-closed, never as misses"
        )
    if tau is not None and (m.below_tau_on_real or m.below_tau_on_fp):
        notes.append(
            f"the gate withheld {m.below_tau_on_real + m.below_tau_on_fp} "
            f"false-positive verdicts ({m.below_tau_on_real} of them on real "
            "defects, i.e. misses the gate prevented)"
        )
    if cost.vs_review_everything >= 1.0:
        notes.append(
            f"under a {miss_weight:g}x miss weight this configuration costs "
            f"{cost.vs_review_everything:.2f}x the review-everything baseline; "
            "it is not earning its place"
        )
    return MetricsResult(
        corpus=corpus,
        tau=tau,
        matrix=m,
        precision=precision,
        recall=recall,
        f1=f1,
        miss_rate=miss_rate,
        needless_review_rate=needless,
        cost=cost,
        notes=tuple(notes),
    )


def fp_class_metrics_per_corpus(
    items: Sequence[LabelledVerdict], **kwargs: Any
) -> dict[str, MetricsResult]:
    """One `MetricsResult` per corpus (D16)."""
    return {
        name: fp_class_metrics(rows, **kwargs)
        for name, rows in split_by_corpus(items).items()
    }
