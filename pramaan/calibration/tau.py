"""tau, the confidence gate, derived by repeated k-fold cross-validation (D3).

tau is the confidence at which the policy engine is willing to auto-close a
false-positive verdict without a human ever seeing it. It is therefore the most
consequential single number this project publishes, and the easiest one to get
flatteringly wrong: pick the threshold that maximises precision on the same rows
you measured precision on, and you will publish a gate that looks perfect and
generalises to nothing.

So tau is never fitted and scored on the same data. `derive()` runs repeated
k-fold cross-validation — k folds, `repeats` independent permutations — fits a
threshold on the k-1 training folds and scores it on the held-out fold it has
never seen. The output is a **spread**, not a point: `TauResult` has no `.tau`
attribute, deliberately, because a single number here would be quoted without
its variance and D3 exists to stop exactly that.

Fold isolation, concretely
--------------------------
`_fit_threshold()` receives a sequence of rows and nothing else. It has no
access to the fold structure, the full item list, or any label outside what it
was handed. `derive()` materialises the training rows and passes only those. The
property that matters — "the threshold fitted for fold f is unchanged by
arbitrary corruption of fold f's labels" — is asserted directly in
`tests/test_tau.py`, together with the positive control that the same corruption
*does* move the threshold when those rows are in the training set. A leakage test
without that positive control proves nothing, because a test that would pass on
an implementation with no fitting at all is not a test.

Definition of the threshold
---------------------------
tau is the lowest stated confidence at which false-positive verdicts are at
least `target_precision` correct, evaluated only where the support is large
enough to mean anything, and required to *hold continuously above that point*.
The continuity requirement is why the scan runs downward: precision as a
function of the threshold is not monotone at n=121, and taking the first upward
crossing would let a single lucky bucket at 0.62 set the gate for everything
above it.

Also here: the reliability diagram and the expected calibration error, the two
numbers that say whether "confidence 0.9" means anything at all. Both are pure
functions over labelled verdicts, so the whole calibration re-derives from the
published verdict table with no API key — which is the point of the exercise.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from pramaan.evals.labels import (
    LabelledVerdict,
    canonical_order,
    check_scoring_unit,
    one_corpus,
    split_by_corpus,
)
from pramaan.evals.stats import (
    InsufficientData,
    Rate,
    bootstrap_ci,
    mean,
    median,
    quantile,
    stdev,
)

__all__ = [
    "DEFAULT_SEED",
    "NEVER_ACHIEVED",
    "Fold",
    "FoldTau",
    "ReliabilityBin",
    "ReliabilityDiagram",
    "Spread",
    "TauResult",
    "derive",
    "derive_per_corpus",
    "expected_calibration_error",
    "grouping_keys",
    "kfold_indices",
    "reliability_diagram",
]

DEFAULT_SEED = "pramaan-tau-v1"

# The value a fold reports when no threshold in its training data reached the
# target precision at adequate support.
#
# Caveat worth knowing: `policy.engine.decide` gates on `confidence >= tau`, so a
# verdict stating exactly 1.0 confidence would still clear this. A genuinely
# closed gate would need tau > 1.0, which `decide` rejects by contract. The real
# protection is that `TauResult.recommended_tau()` refuses to return a number at
# all when too few folds achieved the target — a failed derivation must not
# quietly become a usable gate.
NEVER_ACHIEVED = 1.0

# (train indices, test indices) into the canonical row order.
Fold = tuple[tuple[int, ...], tuple[int, ...]]


# --------------------------------------------------------------------------- #
# Fold construction
# --------------------------------------------------------------------------- #

def kfold_indices(
    keys: Sequence[str],
    *,
    k: int = 5,
    repeats: int = 10,
    seed: str = DEFAULT_SEED,
) -> tuple[tuple[Fold, ...], ...]:
    """Repeated k-fold splits over `keys`, as index tuples.

    The permutation is derived from `sha256(seed | repeat | ordinal | key)`
    rather than `random.shuffle`, so the split is reproducible from the seed in
    any language by anyone holding the published verdict table. That matters
    more than it sounds: "we cross-validated with seed 7" is only a verifiable
    claim if the reader can rebuild the same folds.

    Each repeat is a full partition — every index appears in exactly one test
    fold — and fold sizes differ by at most one.
    """
    n = len(keys)
    if k < 2:
        raise ValueError(f"k must be >= 2, got {k}")
    if repeats < 1:
        raise ValueError(f"repeats must be >= 1, got {repeats}")
    if n < k:
        # Not silently reduced to k=n: a caller who asked for 5-fold on 3 rows
        # has a data problem, and answering anyway hides it.
        raise InsufficientData(
            f"cannot build {k} folds from {n} rows; the corpus is too small "
            "for this cross-validation design"
        )

    out: list[tuple[Fold, ...]] = []
    for repeat in range(repeats):
        order = sorted(
            range(n),
            key=lambda i: hashlib.sha256(
                f"{seed}|{repeat}|{i}|{keys[i]}".encode("utf-8")
            ).hexdigest(),
        )
        base, extra = divmod(n, k)
        folds: list[Fold] = []
        start = 0
        blocks: list[tuple[int, ...]] = []
        for f in range(k):
            size = base + (1 if f < extra else 0)
            blocks.append(tuple(order[start : start + size]))
            start += size
        for f in range(k):
            test = blocks[f]
            held = set(test)
            train = tuple(i for i in range(n) if i not in held)
            folds.append((train, test))
        out.append(tuple(folds))
    return tuple(out)


def grouping_keys(items: Sequence[LabelledVerdict]) -> tuple[str, ...]:
    """The finding ids `derive` splits over, in the order it splits them.

    Public so that a reader — or a leakage test — can rebuild the exact folds
    from the published verdict table and the seed.
    """
    return tuple(sorted({row.finding_id for row in canonical_order(items)}))


# --------------------------------------------------------------------------- #
# Fitting — the only function that reads training labels
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class _Fit:
    tau: float
    achieved: bool
    support: int
    precision: float | None
    candidates: int


def _fit_threshold(
    train: Sequence[LabelledVerdict],
    *,
    target_precision: float,
    min_support: int,
) -> _Fit:
    """Fit tau on training rows alone.

    This function is handed a list. It cannot see the fold structure, the test
    rows, or the full corpus, and it must stay that way: every argument added
    here is a potential channel for the held-out labels to reach the fit.
    """
    fp_rows = [row for row in train if row.says_false_positive]
    candidates = sorted({row.confidence for row in fp_rows}, reverse=True)
    if not candidates:
        return _Fit(NEVER_ACHIEVED, False, 0, None, 0)

    best: float | None = None
    best_support = 0
    best_precision: float | None = None
    for t in candidates:
        selected = [row for row in fp_rows if row.confidence >= t]
        n = len(selected)
        if n < min_support:
            # Not evaluable rather than failing: a 2-row bucket neither
            # confirms nor refutes the target, so the scan continues downward.
            continue
        hits = sum(1 for row in selected if row.true_label == "false_positive")
        precision = hits / n
        if precision >= target_precision:
            best, best_support, best_precision = t, n, precision
        else:
            # Scanning downward, so this is the first evaluable threshold that
            # breaks the target. Everything below inherits these rows, so the
            # sustained condition cannot recover.
            break
    if best is None:
        return _Fit(NEVER_ACHIEVED, False, 0, None, len(candidates))
    return _Fit(best, True, best_support, best_precision, len(candidates))


def _score_fold(tau: float, test: Sequence[LabelledVerdict]) -> tuple[int, int, int]:
    """(hits, selected, fp_rows) for the held-out fold at `tau`."""
    fp_rows = [row for row in test if row.says_false_positive]
    selected = [row for row in fp_rows if row.confidence >= tau]
    hits = sum(1 for row in selected if row.true_label == "false_positive")
    return hits, len(selected), len(fp_rows)


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class Spread:
    """The shape of a distribution, for a report that must never print a mean
    on its own."""

    minimum: float
    q1: float
    median: float
    q3: float
    maximum: float
    mean: float
    stdev: float
    n: int

    @property
    def iqr(self) -> float:
        return self.q3 - self.q1

    def render(self, *, places: int = 3) -> str:
        f = f".{places}f"
        return (
            f"median {self.median:{f}} "
            f"(IQR {self.q1:{f}}–{self.q3:{f}}, "
            f"range {self.minimum:{f}}–{self.maximum:{f}}, "
            f"sd {self.stdev:{f}}, n={self.n})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min": self.minimum,
            "q1": self.q1,
            "median": self.median,
            "q3": self.q3,
            "max": self.maximum,
            "mean": self.mean,
            "stdev": self.stdev,
            "iqr": self.iqr,
            "n": self.n,
        }


def _spread(values: Sequence[float]) -> Spread:
    if not values:
        raise InsufficientData("spread of an empty sequence")
    return Spread(
        minimum=min(values),
        q1=quantile(values, 0.25),
        median=median(values),
        q3=quantile(values, 0.75),
        maximum=max(values),
        mean=mean(values),
        stdev=stdev(values),
        n=len(values),
    )


@dataclass(frozen=True, slots=True)
class FoldTau:
    """One (repeat, fold) outcome. `tau` here is a *fold* estimate; the
    production gate is `TauResult.recommended_tau()`, never this."""

    repeat: int
    fold: int
    tau: float
    achieved: bool
    train_n: int
    test_n: int
    train_support: int
    train_precision: float | None
    heldout_hits: int
    heldout_selected: int
    heldout_fp_rows: int

    @property
    def heldout_precision(self) -> float | None:
        return None if self.heldout_selected == 0 else self.heldout_hits / self.heldout_selected

    @property
    def heldout_coverage(self) -> float | None:
        """Share of the fold's false-positive verdicts that clear tau — i.e. how
        much of the auto-close workload the gate actually accepts. A perfectly
        precise gate that closes nothing is not a useful gate."""
        return None if self.heldout_fp_rows == 0 else self.heldout_selected / self.heldout_fp_rows


@dataclass(frozen=True, slots=True)
class TauResult:
    """The derivation, with its spread. There is no `.tau` attribute.

    That absence is load-bearing. Anything that needs a single gate value calls
    `recommended_tau()`, which refuses when too few folds achieved the target,
    and every rendering of it carries `spread`.
    """

    corpus: str
    k: int
    repeats: int
    seed: str
    target_precision: float
    min_support: int
    n_items: int
    n_fp_verdicts: int
    folds: tuple[FoldTau, ...]
    spread: Spread
    achieved_folds: int
    heldout_precision: Rate
    heldout_coverage: Rate
    underpowered: bool
    notes: tuple[str, ...] = ()

    @property
    def achieved_fraction(self) -> float:
        return self.achieved_folds / len(self.folds)

    def recommended_tau(
        self, *, quantile_: float = 0.75, min_achieved_fraction: float = 0.9
    ) -> float:
        """A single gate value for `policy.engine.decide`, or `InsufficientData`.

        The upper quartile of the fold taus, not the median: the median is the
        threshold that failed to reach target precision on roughly half the
        folds, and this gate decides what gets closed without a human. Erring
        high costs needless reviews; erring low costs suppressed defects, and
        the asymmetric cost model in `evals.metrics` weights the second at 4x.

        Refuses outright when fewer than `min_achieved_fraction` of folds ever
        reached the target — a derivation that mostly failed must not become a
        production number with a comment attached.
        """
        if not 0.0 <= quantile_ <= 1.0:
            raise ValueError("quantile_ must be in [0, 1]")
        if self.achieved_fraction < min_achieved_fraction:
            raise InsufficientData(
                f"only {self.achieved_folds}/{len(self.folds)} folds reached "
                f"precision {self.target_precision:.2f} at support "
                f">= {self.min_support}; there is no defensible tau for corpus "
                f"{self.corpus!r} on this data"
            )
        return quantile([f.tau for f in self.folds if f.achieved], quantile_)

    def render(self) -> str:
        lines = [
            f"tau ({self.corpus}, {self.repeats}x{self.k}-fold, seed={self.seed})",
            f"  target: FP verdicts >= {self.target_precision:.2f} correct "
            f"at support >= {self.min_support}",
            f"  folds:  {self.spread.render()}",
            f"  achieved: {self.achieved_folds}/{len(self.folds)} folds",
            f"  {self.heldout_precision.render()}",
            f"  {self.heldout_coverage.render()}",
        ]
        try:
            lines.append(f"  recommended tau (p75): {self.recommended_tau():.3f}")
        except InsufficientData as exc:
            lines.append(f"  recommended tau: UNAVAILABLE — {exc}")
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        try:
            recommended: float | None = self.recommended_tau()
        except InsufficientData:
            recommended = None
        return {
            "corpus": self.corpus,
            "k": self.k,
            "repeats": self.repeats,
            "seed": self.seed,
            "target_precision": self.target_precision,
            "min_support": self.min_support,
            "n_items": self.n_items,
            "n_fp_verdicts": self.n_fp_verdicts,
            "fold_spread": self.spread.to_dict(),
            "achieved_folds": self.achieved_folds,
            "achieved_fraction": self.achieved_fraction,
            "recommended_tau_p75": recommended,
            "heldout_precision": self.heldout_precision.to_dict(),
            "heldout_coverage": self.heldout_coverage.to_dict(),
            "underpowered": self.underpowered,
            "notes": list(self.notes),
            "fold_taus": [f.tau for f in self.folds],
        }


# --------------------------------------------------------------------------- #
# derive
# --------------------------------------------------------------------------- #

def derive(
    items: Sequence[LabelledVerdict],
    *,
    k: int = 5,
    repeats: int = 10,
    seed: str = DEFAULT_SEED,
    target_precision: float = 0.95,
    min_support: int = 5,
    underpowered_below: int = 50,
    allow_repeated_runs: bool = False,
) -> TauResult:
    """Derive tau by repeated k-fold cross-validation (D3).

    Pure: no clock, no filesystem, no network, no model. Everything it needs is
    in the published verdict table plus a label sheet.

    Args:
        items: labelled verdicts from **one** corpus (D16 — enforced, not
            documented; pass two corpora and it raises).
        k: folds per repeat.
        repeats: independent permutations. 10 x 5 = 50 fold estimates, which is
            what gives the spread enough resolution to be worth publishing.
        seed: names the permutation. Published, so a reader rebuilds the folds.
        target_precision: the bar a threshold must clear on training rows.
        min_support: fewest FP verdicts above a candidate threshold for that
            threshold to be evaluable at all. Without it, the highest confidence
            in the corpus trivially achieves precision 1.0 on a single row.
        underpowered_below: below this many rows the result is flagged. It is
            still computed — the flag is the honest output, not an exception.
        allow_repeated_runs: score the k runs of a pass^k table as separate
            rows. Folds are grouped by finding either way, so this never causes
            leakage — but it does inflate the held-out denominator, so the
            result carries a note saying the interval is optimistic.

    Raises:
        BlendedCorpusError: two corpora in one call.
        RepeatedRunsError: several rows per finding without the opt-in.
        InsufficientData: fewer findings than folds.
    """
    if not items:
        raise InsufficientData("derive() needs labelled rows")
    if not 0.0 < target_precision <= 1.0:
        raise ValueError("target_precision must be in (0, 1]")
    if min_support < 1:
        raise ValueError("min_support must be >= 1")

    corpus = one_corpus(items, what="tau.derive")
    unit_notes = check_scoring_unit(
        items, what="tau.derive", allow_repeated_runs=allow_repeated_runs
    )
    rows = canonical_order(items)

    # Folds are drawn over *findings*, not rows. A pass^k run contributes five
    # verdicts for the same defect on the same code; splitting them across the
    # boundary would put four near-copies of a test row into training and call
    # the result cross-validation. Grouped splitting is the whole difference
    # between a held-out fold and a held-out row.
    groups: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(row.finding_id, []).append(index)
    keys = sorted(groups)
    splits = kfold_indices(keys, k=k, repeats=repeats, seed=seed)

    fold_results: list[FoldTau] = []
    per_repeat_precision: list[tuple[int, int]] = []
    per_repeat_coverage: list[tuple[int, int]] = []

    for repeat_index, repeat in enumerate(splits):
        repeat_hits = repeat_selected = repeat_fp = 0
        for fold_index, (train_groups, test_groups) in enumerate(repeat):
            # The whole isolation guarantee is these two lines: the fit sees
            # `train` and only `train`.
            train = tuple(
                rows[i] for g in train_groups for i in groups[keys[g]]
            )
            test = tuple(rows[i] for g in test_groups for i in groups[keys[g]])

            fit = _fit_threshold(
                train,
                target_precision=target_precision,
                min_support=min_support,
            )
            hits, selected, fp_rows = _score_fold(fit.tau, test)

            fold_results.append(
                FoldTau(
                    repeat=repeat_index,
                    fold=fold_index,
                    tau=fit.tau,
                    achieved=fit.achieved,
                    train_n=len(train),
                    test_n=len(test),
                    train_support=fit.support,
                    train_precision=fit.precision,
                    heldout_hits=hits,
                    heldout_selected=selected,
                    heldout_fp_rows=fp_rows,
                )
            )
            repeat_hits += hits
            repeat_selected += selected
            repeat_fp += fp_rows
        per_repeat_precision.append((repeat_hits, repeat_selected))
        per_repeat_coverage.append((repeat_selected, repeat_fp))

    n_fp = sum(1 for row in rows if row.says_false_positive)
    achieved = sum(1 for f in fold_results if f.achieved)

    # Pooling all 50 folds would count every row `repeats` times and shrink the
    # interval by sqrt(repeats) for free. The denominator here is one repeat's
    # worth of rows — each row exactly once — and the note says so.
    reuse_note = (
        f"point estimate averaged over {repeats} repeats; the interval uses one "
        "repeat's denominator because repeats reuse the same rows and do not "
        "enlarge n"
    )
    precision_rate = _averaged_rate(
        per_repeat_precision,
        label="held-out auto-close precision at fold tau",
        note=reuse_note,
    )
    coverage_rate = _averaged_rate(
        per_repeat_coverage,
        label="held-out coverage (FP verdicts clearing tau)",
        note=reuse_note,
    )

    notes: list[str] = list(unit_notes)
    if len(rows) < underpowered_below:
        notes.append(
            f"underpowered: {len(rows)} labelled rows; fold spread is wide by "
            "construction and should be read as a range, not a value"
        )
    if achieved < len(fold_results):
        notes.append(
            f"{len(fold_results) - achieved} of {len(fold_results)} folds found "
            f"no threshold reaching precision {target_precision:.2f} at support "
            f">= {min_support}; those folds report tau={NEVER_ACHIEVED}"
        )
    if n_fp < min_support * k:
        notes.append(
            f"only {n_fp} false-positive verdicts across the corpus; with k={k} "
            f"and min_support={min_support} most training folds cannot evaluate "
            "a threshold at all"
        )

    return TauResult(
        corpus=corpus,
        k=k,
        repeats=repeats,
        seed=seed,
        target_precision=target_precision,
        min_support=min_support,
        n_items=len(rows),
        n_fp_verdicts=n_fp,
        folds=tuple(fold_results),
        spread=_spread([f.tau for f in fold_results]),
        achieved_folds=achieved,
        heldout_precision=precision_rate,
        heldout_coverage=coverage_rate,
        underpowered=len(rows) < underpowered_below,
        notes=tuple(notes),
    )


def derive_per_corpus(
    items: Iterable[LabelledVerdict], **kwargs: Any
) -> dict[str, TauResult]:
    """One `TauResult` per corpus (D16). The only supported way to derive tau
    over a mixed input — and it returns two numbers, never one."""
    return {
        name: derive(rows, **kwargs)
        for name, rows in split_by_corpus(items).items()
    }


def _averaged_rate(pairs: Sequence[tuple[int, int]], *, label: str, note: str) -> Rate:
    """Mean numerator over mean denominator, both rounded to whole rows.

    Rounding keeps `Rate`'s invariant (integer counts) and keeps the interval
    honest about how many distinct rows are behind it.
    """
    if not pairs:
        return Rate(0, 0, label=label, note=note)
    n = round(mean([d for _, d in pairs]))
    s = min(round(mean([num for num, _ in pairs])), n)
    return Rate(s, n, label=label, note=note)


# --------------------------------------------------------------------------- #
# Reliability diagram and expected calibration error
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ReliabilityBin:
    lower: float
    upper: float
    n: int
    mean_confidence: float | None
    accuracy: Rate

    @property
    def gap(self) -> float | None:
        """Signed: positive means over-confident (stated above observed)."""
        if self.mean_confidence is None or self.accuracy.point is None:
            return None
        return self.mean_confidence - self.accuracy.point

    @property
    def reportable(self) -> bool:
        return self.accuracy.reportable

    def to_dict(self) -> dict[str, Any]:
        return {
            "lower": self.lower,
            "upper": self.upper,
            "n": self.n,
            "mean_confidence": self.mean_confidence,
            "accuracy": self.accuracy.to_dict(),
            "gap": self.gap,
            "reportable": self.reportable,
        }


@dataclass(frozen=True, slots=True)
class ReliabilityDiagram:
    corpus: str
    bins: tuple[ReliabilityBin, ...]
    n_scored: int
    n_excluded: int
    excluded_by_status: dict[str, int]
    ece: float
    mce: float
    ece_ci: tuple[float, float] | None
    ece_seed: str | None
    underpowered_bins: tuple[int, ...]
    notes: tuple[str, ...] = ()

    def render(self) -> str:
        lines = [
            f"reliability ({self.corpus}): n={self.n_scored} scored, "
            f"{self.n_excluded} excluded",
            f"  ECE = {self.ece:.4f}" + (
                f" [95% CI {self.ece_ci[0]:.4f}–{self.ece_ci[1]:.4f}, "
                f"seed={self.ece_seed}]"
                if self.ece_ci
                else "  (no interval computed — do not publish this bare)"
            ),
            f"  MCE = {self.mce:.4f}",
        ]
        for b in self.bins:
            if b.n == 0:
                continue
            flag = "" if b.reportable else "  <- n too small to read"
            lines.append(
                f"  [{b.lower:.1f},{b.upper:.1f}) n={b.n:>3} "
                f"conf={b.mean_confidence:.3f} "  # type: ignore[str-format]
                f"acc={b.accuracy.point:.3f} "  # type: ignore[str-format]
                f"gap={b.gap:+.3f}{flag}"  # type: ignore[str-format]
            )
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "n_scored": self.n_scored,
            "n_excluded": self.n_excluded,
            "excluded_by_status": dict(self.excluded_by_status),
            "ece": self.ece,
            "mce": self.mce,
            "ece_ci95": list(self.ece_ci) if self.ece_ci else None,
            "ece_seed": self.ece_seed,
            "underpowered_bins": list(self.underpowered_bins),
            "bins": [b.to_dict() for b in self.bins],
            "notes": list(self.notes),
        }


def _bin_index(confidence: float, bins: int) -> int:
    idx = int(confidence * bins)
    return bins - 1 if idx >= bins else idx  # 1.0 belongs in the top bin


def _ece_of(rows: Sequence[LabelledVerdict], bins: int) -> float:
    if not rows:
        raise InsufficientData("ECE of an empty sample")
    buckets: list[list[LabelledVerdict]] = [[] for _ in range(bins)]
    for row in rows:
        buckets[_bin_index(row.confidence, bins)].append(row)
    total = len(rows)
    return math_fsum(
        (len(bucket) / total)
        * abs(
            (sum(1 for r in bucket if r.correct) / len(bucket))
            - (math_fsum(r.confidence for r in bucket) / len(bucket))
        )
        for bucket in buckets
        if bucket
    )


def expected_calibration_error(
    items: Sequence[LabelledVerdict], *, bins: int = 10
) -> float:
    """ECE over the decidable verdicts of one corpus.

    Equal-width binning, weighted by bin occupancy. Published alongside its bin
    counts and, in the nightly run, a bootstrap interval — a bare ECE at n=121
    with 10 bins is roughly twelve rows per bin, and moves by more than the
    0.05 CI gate on a handful of relabelled findings.
    """
    scored = [row for row in items if row.is_decidable]
    if not scored:
        raise InsufficientData("no decidable verdicts to calibrate")
    if bins < 1:
        raise ValueError("bins must be >= 1")
    return _ece_of(scored, bins)


def reliability_diagram(
    items: Sequence[LabelledVerdict],
    *,
    bins: int = 10,
    min_bin_n: int = 5,
    bootstrap: int = 0,
    seed: str = DEFAULT_SEED,
    allow_repeated_runs: bool = False,
) -> ReliabilityDiagram:
    """Bucket verdicts by stated confidence and measure what actually happened.

    `bootstrap=0` (the default) skips the interval, because CI runs this on
    every push and 1000 resamples is not free. The nightly run passes a real
    resample count; `render()` says loudly when no interval was computed, since
    a bare ECE is the exact failure mode this suite exists to prevent.
    """
    if bins < 1:
        raise ValueError("bins must be >= 1")
    if not items:
        raise InsufficientData("reliability_diagram() needs labelled rows")

    corpus = one_corpus(items, what="reliability_diagram")
    unit_notes = check_scoring_unit(
        items,
        what="reliability_diagram",
        allow_repeated_runs=allow_repeated_runs,
    )
    scored = [row for row in items if row.is_decidable]
    excluded = [row for row in items if not row.is_decidable]
    excluded_by_status: dict[str, int] = {}
    for row in excluded:
        keyname = row.status if row.status != "valid" else row.model_verdict
        excluded_by_status[keyname] = excluded_by_status.get(keyname, 0) + 1
    if not scored:
        raise InsufficientData(
            "no decidable verdicts: every attempt was needs_human or unparsed"
        )

    buckets: list[list[LabelledVerdict]] = [[] for _ in range(bins)]
    for row in scored:
        buckets[_bin_index(row.confidence, bins)].append(row)

    out: list[ReliabilityBin] = []
    underpowered: list[int] = []
    for i, bucket in enumerate(buckets):
        lower, upper = i / bins, (i + 1) / bins
        if not bucket:
            out.append(
                ReliabilityBin(
                    lower,
                    upper,
                    0,
                    None,
                    Rate(0, 0, min_n=min_bin_n, label=f"bin[{lower:.1f},{upper:.1f})"),
                )
            )
            continue
        hits = sum(1 for r in bucket if r.correct)
        accuracy = Rate(
            hits,
            len(bucket),
            min_n=min_bin_n,
            label=f"bin[{lower:.1f},{upper:.1f})",
        )
        if not accuracy.reportable:
            underpowered.append(i)
        out.append(
            ReliabilityBin(
                lower,
                upper,
                len(bucket),
                math_fsum(r.confidence for r in bucket) / len(bucket),
                accuracy,
            )
        )

    ece = _ece_of(scored, bins)
    gaps = [abs(b.gap) for b in out if b.gap is not None and b.reportable]
    # MCE over reportable bins only: the worst gap is otherwise always whichever
    # bin happened to catch two rows.
    mce = max(gaps) if gaps else 0.0

    ece_ci: tuple[float, float] | None = None
    if bootstrap:
        ece_ci = bootstrap_ci(
            scored,
            lambda sample: _ece_of(sample, bins),
            seed=f"{seed}|ece",
            resamples=bootstrap,
        )

    notes: list[str] = list(unit_notes)
    if underpowered:
        notes.append(
            f"{len(underpowered)} of {sum(1 for b in out if b.n)} occupied bins "
            f"hold fewer than {min_bin_n} rows; their per-bin accuracy is not "
            "readable and MCE ignores them"
        )
    if len(scored) < bins * min_bin_n:
        notes.append(
            f"{len(scored)} scored rows across {bins} bins averages "
            f"{len(scored) / bins:.1f} per bin; consider fewer bins before "
            "quoting ECE against a 0.05 gate"
        )
    if ece_ci is None:
        notes.append(
            "no bootstrap interval computed (bootstrap=0); ECE must not be "
            "published as a point estimate"
        )
    elif ece_ci[0] > ece:
        # Not a bug and worth stating plainly, because it looks like one. ECE
        # sums |accuracy - confidence|, which is bounded below by zero, so
        # resampling noise can only ever add to it: near a well-calibrated
        # model the whole bootstrap distribution sits above the plug-in
        # estimate. The interval is an upper bound on miscalibration, not a
        # symmetric error bar, and the CI gate is checked against the point.
        notes.append(
            f"the bootstrap interval ({ece_ci[0]:.4f}–{ece_ci[1]:.4f}) lies "
            f"entirely above the plug-in ECE of {ece:.4f}. ECE is a sum of "
            "absolute deviations and cannot go below zero, so it is upward-"
            "biased under resampling at small values; read this interval as an "
            "upper bound on miscalibration, not as an error bar around the "
            "point estimate"
        )

    return ReliabilityDiagram(
        corpus=corpus,
        bins=tuple(out),
        n_scored=len(scored),
        n_excluded=len(excluded),
        excluded_by_status=excluded_by_status,
        ece=ece,
        mce=mce,
        ece_ci=ece_ci,
        ece_seed=f"{seed}|ece" if ece_ci else None,
        underpowered_bins=tuple(underpowered),
        notes=tuple(notes),
    )


# `math.fsum` throughout rather than the built-in `sum`: ECE adds many small
# products and the ordinary running sum drifts by enough to matter against a
# gate set at 0.05.
math_fsum = math.fsum
