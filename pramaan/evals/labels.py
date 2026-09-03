"""The labelled row every scored metric in Lane F consumes.

One `LabelledVerdict` is one model verdict paired with one human ground-truth
label. Calibration, tau derivation and the FP-class metrics all read this type
and nothing else, so the rules about *which* rows may sit next to each other
live here in one place rather than being re-litigated in four modules.

Two of those rules are load-bearing:

  * **D16 — never blend the corpora.** The 121 hand-labelled real PHP findings
    and OWASP Benchmark v1.2 measure different things: one is a small sample of
    production Semgrep output on code the model has probably never seen, the
    other is 2,740 synthetic Java cases the model may well have memorised. A
    pooled precision over both is a number with no referent. `one_corpus()` is
    the guard, and every scoring entry point calls it.

  * **A failed attempt is a row, not a gap.** A `schema_invalid` or
    `budget_abort` attempt has no stated confidence, so it cannot enter a
    reliability bin — but it must still be counted, or the schema-failure rate
    (D10) and the calibration denominator quietly disagree. Such rows are built
    with `model_verdict="unparsed"` and excluded by `is_decidable`, never
    dropped on the floor.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pramaan.evals.stats import (
    BlendedCorpusError,
    InsufficientData,
    RepeatedRunsError,
)
from pramaan.schemas import Attempt

__all__ = [
    "GroundTruth",
    "LabelledVerdict",
    "ModelVerdict",
    "canonical_order",
    "check_scoring_unit",
    "from_attempts",
    "one_corpus",
    "one_row_per_finding",
    "repeated_findings",
    "split_by_corpus",
]

# Ground truth has two values. There is no human label for "needs human": the
# rater decides whether the finding is a real defect, and an undecidable finding
# is dropped from the labelled set rather than given a third label that would
# then need a third row in every confusion matrix.
GroundTruth = Literal["true_positive", "false_positive"]

ModelVerdict = Literal[
    "true_positive",
    "false_positive",
    "needs_human",
    "unparsed",  # the attempt never produced a schema-valid verdict (D10)
]

_MODEL_VERDICTS: frozenset[str] = frozenset(
    {"true_positive", "false_positive", "needs_human", "unparsed"}
)
_GROUND_TRUTHS: frozenset[str] = frozenset({"true_positive", "false_positive"})


@dataclass(frozen=True, slots=True)
class LabelledVerdict:
    """One model verdict against one human label."""

    finding_id: str
    corpus: str
    model_verdict: ModelVerdict
    confidence: float
    true_label: GroundTruth
    fingerprint: str = ""
    cwe: str = ""
    status: str = "valid"
    run_index: int = 0
    metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.model_verdict not in _MODEL_VERDICTS:
            raise ValueError(f"unknown model_verdict {self.model_verdict!r}")
        if self.true_label not in _GROUND_TRUTHS:
            raise ValueError(f"unknown true_label {self.true_label!r}")
        if not self.corpus.strip():
            raise ValueError(
                "corpus must be named — an unnamed corpus is how two corpora get "
                "blended without anyone noticing (D16)"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence {self.confidence!r} outside [0, 1]")

    @property
    def is_decidable(self) -> bool:
        """Did the model commit to a true/false-positive call?

        `needs_human` and `unparsed` are not wrong answers, they are absent
        ones. Scoring them as errors would punish the harness for the one
        behaviour the policy layer actually wants when it is unsure.
        """
        return self.status == "valid" and self.model_verdict in _GROUND_TRUTHS

    @property
    def correct(self) -> bool:
        """Only meaningful when `is_decidable`; False otherwise, never None,
        so a caller cannot accidentally sum `None` into a numerator."""
        return self.is_decidable and self.model_verdict == self.true_label

    @property
    def says_false_positive(self) -> bool:
        return self.is_decidable and self.model_verdict == "false_positive"

    @property
    def is_really_a_defect(self) -> bool:
        return self.true_label == "true_positive"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "corpus": self.corpus,
            "model_verdict": self.model_verdict,
            "confidence": self.confidence,
            "true_label": self.true_label,
            "fingerprint": self.fingerprint,
            "cwe": self.cwe,
            "status": self.status,
            "run_index": self.run_index,
        }


def one_corpus(items: Sequence[LabelledVerdict], *, what: str = "this metric") -> str:
    """Return the single corpus name, or raise (D16).

    Called by every scoring entry point. Pooling is not prevented by a comment
    in the report — it is prevented here, where it would otherwise happen.
    """
    if not items:
        raise InsufficientData(f"{what}: no labelled rows")
    names = sorted({item.corpus for item in items})
    if len(names) > 1:
        raise BlendedCorpusError(
            f"{what}: refusing to pool corpora {names}. D16 requires the "
            "hand-labelled PHP corpus and OWASP Benchmark v1.2 to be reported "
            "separately — call split_by_corpus() and score each one."
        )
    return names[0]


def split_by_corpus(
    items: Iterable[LabelledVerdict],
) -> dict[str, list[LabelledVerdict]]:
    """Group rows by corpus, in sorted-name order for a stable report."""
    out: dict[str, list[LabelledVerdict]] = {}
    for item in items:
        out.setdefault(item.corpus, []).append(item)
    return {name: out[name] for name in sorted(out)}


def canonical_order(
    items: Iterable[LabelledVerdict],
) -> tuple[LabelledVerdict, ...]:
    """A total, content-derived order.

    Every seeded draw in this lane — the k-fold permutation, the CI stratified
    subset, the audit sample — is computed against this order, so a caller who
    hands the same rows in a different sequence gets the same folds and the same
    sample. Without it "seed=X" would not be a reproducible instruction.
    """
    return tuple(
        sorted(
            items,
            key=lambda i: (
                i.corpus,
                i.finding_id,
                i.run_index,
                i.model_verdict,
                f"{i.confidence:.12f}",
            ),
        )
    )


def repeated_findings(items: Iterable[LabelledVerdict]) -> dict[str, int]:
    """Findings contributing more than one row, and how many."""
    counts: dict[str, int] = {}
    for item in items:
        counts[item.finding_id] = counts.get(item.finding_id, 0) + 1
    return {k: v for k, v in sorted(counts.items()) if v > 1}


def one_row_per_finding(
    items: Iterable[LabelledVerdict], *, run_index: int | None = None
) -> list[LabelledVerdict]:
    """Reduce a pass^k table to one scored row per finding.

    Deterministic: the lowest `run_index` for each finding, or exactly
    `run_index` when one is named. *Which* run is arbitrary and that is fine —
    what is not fine is treating five verdicts about one defect as five
    independent observations. The variation between them is measured by
    `evals.consistency.pass_at_k`; blending it into a precision interval would
    make the interval look tighter than the evidence is.
    """
    best: dict[str, LabelledVerdict] = {}
    for item in canonical_order(items):
        if run_index is not None and item.run_index != run_index:
            continue
        current = best.get(item.finding_id)
        if current is None or item.run_index < current.run_index:
            best[item.finding_id] = item
    if not best:
        raise InsufficientData(
            f"no rows left after selecting run_index={run_index!r}"
        )
    return [best[key] for key in sorted(best)]


def check_scoring_unit(
    items: Sequence[LabelledVerdict], *, what: str, allow_repeated_runs: bool
) -> tuple[str, ...]:
    """Guard the finding-level scoring unit; return notes if it is waived.

    Raises unless the caller has explicitly said it wants the k runs scored as
    separate rows. Waiving it is legitimate — more rows fit a better threshold —
    but it inflates every denominator, so the waiver comes with a note that
    follows the number into the report.
    """
    repeats = repeated_findings(items)
    if not repeats:
        return ()
    worst = max(repeats.values())
    if not allow_repeated_runs:
        raise RepeatedRunsError(
            f"{what}: {len(repeats)} findings contribute more than one row "
            f"(up to {worst}). Scoring the k runs of a pass^k table as "
            "independent observations shrinks every interval by sqrt(k). Call "
            "labels.one_row_per_finding() first, or pass "
            "allow_repeated_runs=True and accept the note."
        )
    return (
        f"scored at row level: {len(repeats)} findings contribute up to {worst} "
        "rows each, so the denominators count verdicts rather than independent "
        "defects and every interval here is narrower than the evidence "
        "supports",
    )


def from_attempts(
    attempts: Iterable[Attempt],
    labels: Mapping[str, GroundTruth],
    *,
    corpus_of: Callable[[Attempt], str] | None = None,
    on_missing_label: Literal["skip", "error"] = "skip",
) -> list[LabelledVerdict]:
    """Build labelled rows from cached attempts and a human label sheet.

    `labels` is keyed on `finding_id`. An attempt with no label is skipped by
    default — the OWASP arm labels everything, the real arm does not, and an
    unlabelled finding is simply not evidence.

    Failed attempts survive as `unparsed` rows so the schema-failure rate and
    the calibration denominator are computed over the same population.
    """
    resolve = corpus_of or _corpus_from_metadata
    rows: list[LabelledVerdict] = []
    for attempt in attempts:
        label = labels.get(attempt.finding_id)
        if label is None:
            if on_missing_label == "error":
                raise InsufficientData(
                    f"no ground-truth label for {attempt.finding_id!r}"
                )
            continue
        verdict = attempt.verdict if attempt.is_valid else None
        if verdict is None:
            model_verdict: ModelVerdict = "unparsed"
            confidence = 0.0
            cwe = ""
        else:
            model_verdict = verdict.get("verdict", "unparsed")  # type: ignore[assignment]
            if model_verdict not in _MODEL_VERDICTS:
                model_verdict = "unparsed"
            confidence = float(verdict.get("confidence", 0.0) or 0.0)
            cwe = str(verdict.get("cwe", "") or "")
        rows.append(
            LabelledVerdict(
                finding_id=attempt.finding_id,
                corpus=resolve(attempt),
                model_verdict=model_verdict,
                confidence=confidence,
                true_label=label,
                fingerprint=attempt.fingerprint,
                cwe=cwe,
                status=attempt.status,
                run_index=attempt.run_index,
            )
        )
    return rows


def _corpus_from_metadata(attempt: Attempt) -> str:
    """Read the corpus off `Attempt.metadata['corpus']`.

    Raises rather than defaulting: an attempt that does not say which corpus it
    came from is precisely the row that would silently blend the two (D16).
    """
    corpus = (attempt.metadata or {}).get("corpus")
    if not isinstance(corpus, str) or not corpus.strip():
        raise BlendedCorpusError(
            f"attempt {attempt.finding_id!r} carries no metadata['corpus']; "
            "pass corpus_of=... explicitly rather than letting it default"
        )
    return corpus
