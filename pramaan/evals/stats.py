"""Small-sample statistics for the Kasauti suite.

Nothing in this project is measured over a large corpus. The hand-labelled set is
121 findings, the intra-rater subset is ~50, and TODO 1 breaks injection ASR into
four channels of roughly ten payloads each. At those sizes a bare point estimate
is not a measurement — it is a coin flip wearing a decimal point.

So no function here returns a naked float where a proportion is meant. `Rate`
carries its numerator, its denominator, a Wilson score interval and a
`reportable` flag, and `require_point()` raises rather than hand a caller a
number the corpus cannot support. A trust report that silently divides by three
is worse than one that says "n too small to report".

Wilson rather than the normal approximation because the normal interval is
actively wrong at the sizes and the extremes this suite lives at: it produces
zero-width intervals at p=0 and p=1, which is precisely where the injection ASR
is expected to sit.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "EvalError",
    "InsufficientData",
    "BlendedCorpusError",
    "RepeatedRunsError",
    "MIN_REPORTABLE_N",
    "Z_95",
    "Rate",
    "bootstrap_ci",
    "mean",
    "median",
    "quantile",
    "stdev",
    "wilson_interval",
    "zero_events_upper_bound",
]

# 97.5th percentile of the standard normal — the two-sided 95% z.
Z_95 = 1.959963984540054

# Below this, a proportion is reported as counts only. Five is not a magic
# number with a theory behind it; it is the point at which a Wilson interval on
# a proportion stops being narrower than the interval [0, 1] by any useful
# margin. Callers that need a different bar pass their own `min_n`.
MIN_REPORTABLE_N = 5


class EvalError(Exception):
    """Base class for every measurement failure in the eval suite."""


class InsufficientData(EvalError):
    """The corpus cannot support the number that was asked for."""


class BlendedCorpusError(EvalError):
    """D16: the 121 hand-labelled PHP findings and OWASP Benchmark v1.2 are
    reported separately, always. Any function that would pool them raises this
    instead of returning a number nobody can interpret."""


class RepeatedRunsError(EvalError):
    """The same finding was handed to a scorer more than once.

    A pass^k measurement produces five verdicts per defect. Scoring all five as
    independent observations multiplies every denominator by five and shrinks
    every interval by sqrt(5) for nothing — the mirror image of silently
    dividing on n=3. The scored unit is the finding; run-to-run variation is
    measured by `evals.consistency`, which is where it belongs.
    """


def wilson_interval(
    successes: int, n: int, *, z: float = Z_95
) -> tuple[float, float]:
    """Two-sided Wilson score interval for a binomial proportion.

    Well behaved at 0 and 1, which is where the injection ASR and the schema
    failure rate both live, and where the Wald interval degenerates to a point.
    """
    if n <= 0:
        raise InsufficientData("wilson_interval needs n >= 1")
    if not 0 <= successes <= n:
        raise ValueError(f"successes={successes} outside [0, {n}]")
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1.0 - p) / n + z2 / (4 * n * n))
    return (max(0.0, centre - half), min(1.0, centre + half))


def zero_events_upper_bound(n: int, *, confidence: float = 0.95) -> float:
    """Upper bound on a rate after observing zero events in `n` trials.

    The generalised rule of three: `1 - (1 - confidence)**(1/n)`. This is the
    honest reading of a clean run — "no injection succeeded in 10 attempts" is
    compatible with a true success rate of 26%, and the report has to say so
    rather than print 0%.
    """
    if n <= 0:
        raise InsufficientData("zero_events_upper_bound needs n >= 1")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    return 1.0 - (1.0 - confidence) ** (1.0 / n)


@dataclass(frozen=True, slots=True)
class Rate:
    """A proportion that refuses to be reported without its denominator.

    Only the two counts are stored. The point estimate and the interval are
    derived, so a `Rate` cannot be constructed carrying an interval that does
    not match its numerator — which is exactly the sort of quiet inconsistency
    that survives review.
    """

    successes: int
    n: int
    min_n: int = MIN_REPORTABLE_N
    label: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        if self.n < 0:
            raise ValueError(f"n must be >= 0, got {self.n}")
        if not 0 <= self.successes <= self.n:
            raise ValueError(
                f"successes={self.successes} outside [0, {self.n}] for {self.label!r}"
            )

    @property
    def point(self) -> float | None:
        """None on an empty denominator. Deliberately not 0.0 — a rate over no
        trials is unknown, and unknown is not zero."""
        return None if self.n == 0 else self.successes / self.n

    @property
    def interval(self) -> tuple[float, float] | None:
        return None if self.n == 0 else wilson_interval(self.successes, self.n)

    @property
    def low(self) -> float | None:
        iv = self.interval
        return None if iv is None else iv[0]

    @property
    def high(self) -> float | None:
        iv = self.interval
        return None if iv is None else iv[1]

    @property
    def reportable(self) -> bool:
        return self.n >= self.min_n

    @property
    def width(self) -> float | None:
        iv = self.interval
        return None if iv is None else iv[1] - iv[0]

    def require_point(self) -> float:
        """The point estimate, or `InsufficientData`.

        Gates and any published headline call this rather than `.point`, so a
        rate the corpus cannot support becomes an inconclusive gate rather than
        a confident number.
        """
        if not self.reportable:
            raise InsufficientData(
                f"{self.label or 'rate'}: n={self.n} below the reporting minimum "
                f"of {self.min_n} ({self.successes} events)"
            )
        point = self.point
        assert point is not None  # n >= min_n >= 1
        return point

    def render(self) -> str:
        head = f"{self.label}: " if self.label else ""
        tail = f" — {self.note}" if self.note else ""
        if self.n == 0:
            return f"{head}n=0, nothing to report{tail}"
        lo, hi = self.interval  # type: ignore[misc]
        body = (
            f"{self.successes}/{self.n} = {self.point:.3f} "  # type: ignore[str-format]
            f"[95% CI {lo:.3f}–{hi:.3f}]"
        )
        if not self.reportable:
            body += f" — n too small to report (min {self.min_n})"
        return f"{head}{body}{tail}"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.render()

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "successes": self.successes,
            "n": self.n,
            "point": self.point,
            "ci95_low": self.low,
            "ci95_high": self.high,
            "reportable": self.reportable,
            "min_n": self.min_n,
            "note": self.note,
        }


# --------------------------------------------------------------------------- #
# Descriptive helpers
#
# `statistics` covers mean/median/stdev; these wrappers exist to give the whole
# suite one empty-input failure mode (`InsufficientData`) instead of a mix of
# StatisticsError and ZeroDivisionError leaking out of different modules.
# --------------------------------------------------------------------------- #

def mean(values: Iterable[float]) -> float:
    xs = list(values)
    if not xs:
        raise InsufficientData("mean of an empty sequence")
    return math.fsum(xs) / len(xs)


def median(values: Iterable[float]) -> float:
    xs = sorted(values)
    if not xs:
        raise InsufficientData("median of an empty sequence")
    mid = len(xs) // 2
    if len(xs) % 2:
        return xs[mid]
    return (xs[mid - 1] + xs[mid]) / 2.0


def stdev(values: Iterable[float]) -> float:
    """Sample standard deviation. Zero for a single observation.

    Zero rather than an exception because a one-fold spread is a real (if
    useless) answer, and `TauResult` would otherwise have to special-case it.
    The accompanying fold count makes the uselessness visible.
    """
    xs = list(values)
    if not xs:
        raise InsufficientData("stdev of an empty sequence")
    if len(xs) == 1:
        return 0.0
    m = mean(xs)
    return math.sqrt(math.fsum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def quantile(values: Iterable[float], q: float) -> float:
    """Linearly interpolated quantile (the R type-7 / numpy default rule)."""
    if not 0.0 <= q <= 1.0:
        raise ValueError(f"q must be in [0, 1], got {q}")
    xs = sorted(values)
    if not xs:
        raise InsufficientData("quantile of an empty sequence")
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return xs[int(pos)]
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def bootstrap_ci(
    values: Sequence[Any],
    statistic: Callable[[Sequence[Any]], float],
    *,
    seed: str,
    resamples: int = 1000,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Seeded percentile bootstrap.

    For statistics that are not proportions — ECE, kappa — where no closed-form
    small-sample interval exists that is worth trusting. The seed is a string so
    the published report can name it and a reader can reproduce the interval.

    Resampling is at the level of whole observations, so it inherits the
    independence assumption of the data. For per-finding rows that holds; for
    the k runs of one finding it does not, which is why nothing here bootstraps
    pass^k.
    """
    if resamples < 1:
        raise ValueError("resamples must be >= 1")
    n = len(values)
    if n == 0:
        raise InsufficientData("bootstrap of an empty sample")
    rng = random.Random(seed)
    draws: list[float] = []
    for _ in range(resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        try:
            draws.append(statistic(sample))
        except (InsufficientData, ZeroDivisionError):
            # A resample can be degenerate (every row the same class). Dropping
            # it biases the interval slightly narrow; keeping a fabricated value
            # would bias it in an unknown direction, so the count of dropped
            # resamples is what the caller should watch.
            continue
    if not draws:
        raise InsufficientData("every bootstrap resample was degenerate")
    return (quantile(draws, alpha / 2.0), quantile(draws, 1.0 - alpha / 2.0))
