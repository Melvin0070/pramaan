"""Intra-rater agreement, and the thing that is not agreement (D18).

There is one human on this project. The original plan called for a second rater
on ~50 findings and reported Cohen's kappa against them; there is no second
rater, so that number does not exist and must not be manufactured. What *can* be
measured is whether the one rater agrees with themselves: label a subset, wait
out a wash-out period long enough that the first pass is not being recalled, and
label it again cold.

That statistic is **intra-rater** agreement. It is named intra-rater in this
module's name, in every function name, in every dataclass field and in every
rendered line, because "kappa: 0.81" in a report is read as inter-rater
reliability by everyone who has ever seen the number, and quietly letting that
misreading stand would be the single most dishonest thing this suite could do.
It measures rater stability — Razorpay's own write-up names fatigue-driven
inconsistency as the problem — and it says nothing whatever about whether the
labels are *right*.

Two hard rules live here:

1. **The wash-out is enforced, not assumed.** Re-labelling the same items the
   same afternoon measures short-term memory. `min_washout_days` defaults to 7
   (D18) and `strict=True` raises rather than returning a flattering number.

2. **Model-vs-human agreement is not kappa and never will be.**
   `model_vs_human_agreement()` returns raw agreement with an interval and has
   no kappa field, no chance correction, and no path to acquiring one. A
   chance-corrected coefficient implies two exchangeable raters. The model is
   the system under test, not a rater; correcting it for chance would let a
   coin-flipping triage agent post a respectable number.

Weighted kappa on severity is deliberately absent and must not be reintroduced:
94% of the corpus is one CWE, and at that prevalence the coefficient collapses
towards zero regardless of how well the labels actually agree. That is what
`prevalence` and `degenerate` on the result exist to make visible.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from pramaan.evals.stats import EvalError, InsufficientData, Rate, bootstrap_ci

__all__ = [
    "DEGENERATE_PREVALENCE",
    "IntraRaterAgreement",
    "ModelHumanAgreement",
    "Rating",
    "WashoutViolation",
    "intra_rater_kappa",
    "model_vs_human_agreement",
]

MIN_WASHOUT_DAYS = 7
# Above this share in one category, a chance-corrected coefficient stops being
# interpretable: pe approaches 1, so (po - pe) / (1 - pe) divides a small number
# by a smaller one and swings wildly. This is exactly why weighted kappa on
# severity was dropped from the plan rather than reported low.
DEGENERATE_PREVALENCE = 0.90


class WashoutViolation(EvalError):
    """Two labelling passes too close together to be independent (D18)."""


@dataclass(frozen=True, slots=True)
class Rating:
    """One rater's label for one item at one point in time."""

    item_id: str
    label: str
    rated_at: datetime
    corpus: str = "unnamed"
    session: str = ""

    def __post_init__(self) -> None:
        if not self.item_id.strip():
            raise ValueError("item_id must be non-empty")
        if not self.label.strip():
            raise ValueError("label must be non-empty")
        if self.rated_at.tzinfo is None:
            # A naive timestamp makes the wash-out gap unverifiable across the
            # DST boundary the labelling passes will straddle.
            raise ValueError(
                f"rated_at for {self.item_id!r} must be timezone-aware"
            )


@dataclass(frozen=True, slots=True)
class IntraRaterAgreement:
    """Cohen's kappa between two passes by the **same** rater.

    Every field carries the `intra_rater_` prefix so that no consumer can
    render this as inter-rater reliability by accident — including a future
    report template that iterates over `to_dict()`.
    """

    corpus: str
    intra_rater_n: int
    intra_rater_categories: tuple[str, ...]
    intra_rater_kappa: float | None
    intra_rater_kappa_ci95: tuple[float, float] | None
    intra_rater_observed_agreement: Rate
    intra_rater_expected_agreement: float
    intra_rater_confusion: dict[tuple[str, str], int]
    intra_rater_washout_days_min: float
    intra_rater_washout_days_median: float
    intra_rater_washout_satisfied: bool
    intra_rater_washout_violations: tuple[str, ...]
    intra_rater_prevalence: float
    intra_rater_degenerate: bool
    intra_rater_flips: tuple[tuple[str, str, str], ...]
    notes: tuple[str, ...] = ()

    def render(self) -> str:
        kappa = (
            "undefined (degenerate marginals)"
            if self.intra_rater_kappa is None
            else f"{self.intra_rater_kappa:.3f}"
        )
        ci = (
            f" [95% CI {self.intra_rater_kappa_ci95[0]:.3f}–"
            f"{self.intra_rater_kappa_ci95[1]:.3f}]"
            if self.intra_rater_kappa_ci95
            else ""
        )
        lines = [
            f"intra-rater agreement ({self.corpus}), n={self.intra_rater_n}",
            f"  intra-rater kappa: {kappa}{ci}",
            f"  {self.intra_rater_observed_agreement.render()}",
            f"  expected by chance: {self.intra_rater_expected_agreement:.3f}",
            f"  wash-out: min {self.intra_rater_washout_days_min:.1f}d, "
            f"median {self.intra_rater_washout_days_median:.1f}d, "
            f"satisfied={self.intra_rater_washout_satisfied}",
            f"  majority-category prevalence: {self.intra_rater_prevalence:.3f}",
            "  this is rater self-consistency, NOT inter-rater reliability and "
            "NOT label correctness",
        ]
        if self.intra_rater_flips:
            lines.append(f"  items relabelled: {len(self.intra_rater_flips)}")
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "statistic": "intra_rater_cohens_kappa",
            "intra_rater_n": self.intra_rater_n,
            "intra_rater_categories": list(self.intra_rater_categories),
            "intra_rater_kappa": self.intra_rater_kappa,
            "intra_rater_kappa_ci95": (
                list(self.intra_rater_kappa_ci95)
                if self.intra_rater_kappa_ci95
                else None
            ),
            "intra_rater_observed_agreement": (
                self.intra_rater_observed_agreement.to_dict()
            ),
            "intra_rater_expected_agreement": self.intra_rater_expected_agreement,
            "intra_rater_confusion": {
                f"{a}->{b}": n for (a, b), n in sorted(self.intra_rater_confusion.items())
            },
            "intra_rater_washout_days_min": self.intra_rater_washout_days_min,
            "intra_rater_washout_days_median": self.intra_rater_washout_days_median,
            "intra_rater_washout_satisfied": self.intra_rater_washout_satisfied,
            "intra_rater_washout_violations": list(
                self.intra_rater_washout_violations
            ),
            "intra_rater_prevalence": self.intra_rater_prevalence,
            "intra_rater_degenerate": self.intra_rater_degenerate,
            "intra_rater_flips": [list(f) for f in self.intra_rater_flips],
            "interpretation": (
                "rater self-consistency across a wash-out; not inter-rater "
                "reliability, not label accuracy"
            ),
            "notes": list(self.notes),
        }


def _cohens_kappa(
    pairs: Sequence[tuple[str, str]], categories: Sequence[str]
) -> float:
    """(po - pe) / (1 - pe). Raises when pe == 1 rather than returning 0."""
    n = len(pairs)
    if n == 0:
        raise InsufficientData("kappa of an empty sample")
    po = sum(1 for a, b in pairs if a == b) / n
    pe = 0.0
    for cat in categories:
        first = sum(1 for a, _ in pairs if a == cat) / n
        second = sum(1 for _, b in pairs if b == cat) / n
        pe += first * second
    if pe >= 1.0:
        raise InsufficientData(
            "expected agreement is 1.0 — both passes used a single category, so "
            "kappa is undefined rather than zero"
        )
    return (po - pe) / (1.0 - pe)


def intra_rater_kappa(
    pass_one: Iterable[Rating],
    pass_two: Iterable[Rating],
    *,
    min_washout_days: int = MIN_WASHOUT_DAYS,
    strict: bool = True,
    bootstrap: int = 1000,
    seed: str = "pramaan-intra-rater-v1",
    min_n: int = 20,
) -> IntraRaterAgreement:
    """Cohen's kappa between one rater's two labelling passes (D18).

    Args:
        pass_one, pass_two: the same rater's labels. Items present in only one
            pass are dropped and reported; items labelled twice within one pass
            are an error.
        min_washout_days: minimum gap between an item's two labellings. Seven
            days is the plan's commitment. A shorter gap measures recall, not
            stability.
        strict: raise `WashoutViolation` when any pair is inside the wash-out.
            `strict=False` computes anyway and marks
            `intra_rater_washout_satisfied=False` — for a partially re-labelled
            corpus mid-pass, never for a published number.
        bootstrap: resamples for the kappa interval; 0 disables. At n≈50 the
            interval is wide and reporting kappa without it invites the reader
            to compare a noisy 0.71 against a 0.6 threshold.
        min_n: below this, kappa is computed but flagged unreportable.

    Raises:
        WashoutViolation: under `strict`, a pair inside the wash-out.
        InsufficientData: no overlapping items.
    """
    first = _index(pass_one, "pass_one")
    second = _index(pass_two, "pass_two")
    shared = sorted(set(first) & set(second))
    if not shared:
        raise InsufficientData(
            "the two labelling passes share no items; there is nothing to "
            "compare"
        )

    corpora = {first[i].corpus for i in shared} | {second[i].corpus for i in shared}
    corpus = corpora.pop() if len(corpora) == 1 else "mixed"

    threshold = timedelta(days=min_washout_days)
    gaps: list[float] = []
    violations: list[str] = []
    for item in shared:
        gap = abs(second[item].rated_at - first[item].rated_at)
        gaps.append(gap.total_seconds() / 86400.0)
        if gap < threshold:
            violations.append(item)
    if violations and strict:
        raise WashoutViolation(
            f"{len(violations)} of {len(shared)} items were re-labelled inside "
            f"the {min_washout_days}-day wash-out (e.g. {violations[:3]}); "
            "agreement across a short gap measures recall of the first pass, "
            "not rater stability"
        )

    pairs = [(first[i].label, second[i].label) for i in shared]
    categories = tuple(sorted({label for pair in pairs for label in pair}))

    confusion: dict[tuple[str, str], int] = {}
    for pair in pairs:
        confusion[pair] = confusion.get(pair, 0) + 1

    counts: dict[str, int] = {}
    for a, b in pairs:
        counts[a] = counts.get(a, 0) + 1
        counts[b] = counts.get(b, 0) + 1
    prevalence = max(counts.values()) / (2 * len(pairs))

    n = len(pairs)
    po_hits = sum(1 for a, b in pairs if a == b)
    pe = 0.0
    for cat in categories:
        pe += (sum(1 for a, _ in pairs if a == cat) / n) * (
            sum(1 for _, b in pairs if b == cat) / n
        )

    degenerate = pe >= 1.0 or prevalence >= DEGENERATE_PREVALENCE
    kappa: float | None
    try:
        kappa = _cohens_kappa(pairs, categories)
    except InsufficientData:
        kappa = None

    kappa_ci: tuple[float, float] | None = None
    if kappa is not None and bootstrap:
        try:
            kappa_ci = bootstrap_ci(
                pairs,
                lambda sample: _cohens_kappa(sample, categories),
                seed=f"{seed}|intra-rater",
                resamples=bootstrap,
            )
        except InsufficientData:
            kappa_ci = None

    flips = tuple(
        (item, first[item].label, second[item].label)
        for item in shared
        if first[item].label != second[item].label
    )

    notes: list[str] = []
    dropped = (set(first) | set(second)) - set(shared)
    if dropped:
        notes.append(
            f"{len(dropped)} items appear in only one pass and are excluded"
        )
    if violations:
        notes.append(
            f"{len(violations)} pairs are inside the {min_washout_days}-day "
            "wash-out; this result is not publishable as intra-rater agreement"
        )
    if degenerate:
        notes.append(
            f"marginals are degenerate (majority category holds "
            f"{prevalence:.1%}); kappa is not interpretable at this prevalence "
            "and observed agreement should be reported instead. This is the "
            "same failure that removed weighted kappa on severity from the plan"
        )
    if n < min_n:
        notes.append(
            f"n={n} pairs; the bootstrap interval is wide and kappa should not "
            "be compared against a fixed threshold at this size"
        )

    return IntraRaterAgreement(
        corpus=corpus,
        intra_rater_n=n,
        intra_rater_categories=categories,
        intra_rater_kappa=kappa,
        intra_rater_kappa_ci95=kappa_ci,
        intra_rater_observed_agreement=Rate(
            po_hits, n, min_n=min_n, label="intra-rater observed agreement"
        ),
        intra_rater_expected_agreement=pe,
        intra_rater_confusion=confusion,
        intra_rater_washout_days_min=min(gaps),
        intra_rater_washout_days_median=sorted(gaps)[len(gaps) // 2],
        intra_rater_washout_satisfied=not violations,
        intra_rater_washout_violations=tuple(violations),
        intra_rater_prevalence=prevalence,
        intra_rater_degenerate=degenerate,
        intra_rater_flips=flips,
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------- #
# Model vs human — separate, and not kappa
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ModelHumanAgreement:
    """How often the model's label matched the human's.

    There is no chance-corrected field on this class and adding one would be a
    category error. Chance correction models two raters drawing from their own
    marginal distributions; here one side is ground truth and the other is the
    system being graded. `tests/test_agreement.py` asserts that no attribute of
    this class contains the string "kappa", so the omission survives a refactor.
    """

    corpus: str
    n: int
    raw_agreement: Rate
    per_class: dict[str, Rate]
    disagreements: tuple[tuple[str, str, str], ...]
    excluded_undecidable: int
    notes: tuple[str, ...] = ()

    def render(self) -> str:
        lines = [
            f"model-vs-human agreement ({self.corpus}), n={self.n}",
            f"  {self.raw_agreement.render()}",
        ]
        for label, r in sorted(self.per_class.items()):
            lines.append(f"  {r.render()}")
        lines.append(
            "  raw agreement only: the model is the system under test, not a "
            "second rater, so this is deliberately not chance-corrected and is "
            "never reported as kappa (D18)"
        )
        if self.excluded_undecidable:
            lines.append(
                f"  {self.excluded_undecidable} model outputs were needs_human "
                "or unparsed and are excluded from the numerator and the "
                "denominator"
            )
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "statistic": "raw_agreement_not_chance_corrected",
            "n": self.n,
            "raw_agreement": self.raw_agreement.to_dict(),
            "per_class": {k: v.to_dict() for k, v in sorted(self.per_class.items())},
            "disagreements": [list(d) for d in self.disagreements],
            "excluded_undecidable": self.excluded_undecidable,
            "interpretation": (
                "share of findings where the model's label matched the human "
                "label; not chance-corrected, not kappa, not a reliability "
                "coefficient"
            ),
            "notes": list(self.notes),
        }


def model_vs_human_agreement(
    model: Iterable[Rating],
    human: Iterable[Rating],
    *,
    undecidable_labels: Sequence[str] = ("needs_human", "unparsed"),
    min_n: int = 20,
) -> ModelHumanAgreement:
    """Raw agreement between model labels and human labels. Not kappa.

    Model outputs in `undecidable_labels` are excluded from both numerator and
    denominator: `needs_human` is the harness working as designed, and scoring
    it as a disagreement would push the model towards guessing.
    """
    model_by_id = _index(model, "model")
    human_by_id = _index(human, "human")
    shared = sorted(set(model_by_id) & set(human_by_id))
    if not shared:
        raise InsufficientData("model and human label sets do not overlap")

    undecidable = {label for label in undecidable_labels}
    scored = [i for i in shared if model_by_id[i].label not in undecidable]
    excluded = len(shared) - len(scored)
    if not scored:
        raise InsufficientData(
            "every model output was undecidable; there is no agreement to "
            "measure"
        )

    corpora = {human_by_id[i].corpus for i in scored}
    corpus = corpora.pop() if len(corpora) == 1 else "mixed"

    hits = sum(1 for i in scored if model_by_id[i].label == human_by_id[i].label)
    per_class: dict[str, Rate] = {}
    for label in sorted({human_by_id[i].label for i in scored}):
        members = [i for i in scored if human_by_id[i].label == label]
        per_class[label] = Rate(
            sum(1 for i in members if model_by_id[i].label == label),
            len(members),
            min_n=min_n,
            label=f"agreement on human-labelled {label}",
        )

    notes: list[str] = []
    if excluded:
        notes.append(
            f"{excluded} of {len(shared)} findings had an undecidable model "
            "output and are outside this measurement entirely"
        )
    if len(scored) < min_n:
        notes.append(f"n={len(scored)}; too small to compare against a threshold")

    return ModelHumanAgreement(
        corpus=corpus,
        n=len(scored),
        raw_agreement=Rate(
            hits, len(scored), min_n=min_n, label="model-vs-human raw agreement"
        ),
        per_class=per_class,
        disagreements=tuple(
            (i, model_by_id[i].label, human_by_id[i].label)
            for i in scored
            if model_by_id[i].label != human_by_id[i].label
        ),
        excluded_undecidable=excluded,
        notes=tuple(notes),
    )


def _index(ratings: Iterable[Rating], what: str) -> dict[str, Rating]:
    out: dict[str, Rating] = {}
    for rating in ratings:
        if rating.item_id in out:
            raise EvalError(
                f"{what}: item {rating.item_id!r} labelled twice in the same "
                "pass; one pass must carry one label per item"
            )
        out[rating.item_id] = rating
    return out
