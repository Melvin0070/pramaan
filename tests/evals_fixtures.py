"""Synthetic fixtures for the Lane F tests.

No recorded model output and no network: every number these tests check is a
consequence of data constructed here, so a failure points at the statistics
rather than at a captured transcript that drifted.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pramaan.evals.labels import LabelledVerdict
from pramaan.schemas import Attempt

CORPUS = "php-121"
OTHER_CORPUS = "owasp-benchmark-1.2"


def verdict_payload(
    *,
    finding_id: str = "semgrep:sqli:src/Api.php:42",
    verdict: str = "true_positive",
    confidence: float = 0.9,
    cwe: str = "CWE-89",
    injection_observed: bool = False,
    business_impact: dict[str, bool] | None = None,
    rationale: str = "user input reaches the query builder unescaped",
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "verdict": verdict,
        "confidence": confidence,
        "cwe": cwe,
        "evidence": [{"file": "src/Api.php", "line": 42, "why": "unparameterised"}],
        "reachability": "reachable_from_http",
        "business_impact": business_impact
        or {
            "payment_path": False,
            "auth_or_session": False,
            "pci_scope_hint": False,
            "kyc_or_settlement": False,
        },
        "injection_observed": injection_observed,
        "rationale": rationale,
    }


def make_attempt(
    *,
    finding_id: str = "F000",
    fingerprint: str | None = None,
    run_index: int = 0,
    status: str = "valid",
    verdict: str | None = "true_positive",
    confidence: float = 0.9,
    model: str = "claude-sonnet-5",
    effort: str = "medium",
    context_config: str = "w50_callers",
    prompt_hash: str = "p" * 32,
    run_epoch: str = "epoch-ci-1",
    corpus: str = CORPUS,
    raw_text: str = "",
    metadata: dict[str, Any] | None = None,
) -> Attempt:
    payload = (
        verdict_payload(
            finding_id=finding_id, verdict=verdict, confidence=confidence
        )
        if status == "valid" and verdict is not None
        else None
    )
    meta: dict[str, Any] = {"corpus": corpus}
    meta.update(metadata or {})
    return Attempt(
        finding_id=finding_id,
        fingerprint=fingerprint or f"fp-{finding_id}",
        run_index=run_index,
        status=status,  # type: ignore[arg-type]
        verdict=payload,
        raw_text=raw_text or (None if payload else "<unparseable>"),
        model=model,
        effort=effort,
        context_config=context_config,
        prompt_hash=prompt_hash,
        run_epoch=run_epoch,
        metadata=meta,
    )


def k_attempts(
    finding_id: str,
    verdicts: Sequence[str | None],
    *,
    statuses: Sequence[str] | None = None,
    confidence: float = 0.9,
    run_epoch: str = "epoch-ci-1",
    corpus: str = CORPUS,
) -> list[Attempt]:
    """One pass^k group. `verdicts[i] is None` pairs with a failure status."""
    stats = list(statuses or ["valid"] * len(verdicts))
    return [
        make_attempt(
            finding_id=finding_id,
            run_index=i,
            status=stats[i],
            verdict=verdicts[i],
            confidence=confidence,
            run_epoch=run_epoch,
            corpus=corpus,
        )
        for i in range(len(verdicts))
    ]


def tau_corpus(
    *, n_fp: int = 80, n_tp: int = 20, corpus: str = CORPUS
) -> list[LabelledVerdict]:
    """A corpus with a real knee in it.

    False-positive verdicts run from confidence 0.20 to 0.99. Above 0.60 every
    one is genuinely a false positive; below it, one in three is really a defect.
    So a threshold-fitting routine that works finds tau somewhere just under
    0.60, and one that does not will be obvious.
    """
    rows: list[LabelledVerdict] = []
    step = 0.79 / (n_fp - 1)
    for i in range(n_fp):
        confidence = round(0.20 + i * step, 4)
        genuinely_fp = confidence >= 0.60 or (i % 3 != 0)
        rows.append(
            LabelledVerdict(
                finding_id=f"F{i:03d}",
                corpus=corpus,
                model_verdict="false_positive",
                confidence=confidence,
                true_label="false_positive" if genuinely_fp else "true_positive",
            )
        )
    for j in range(n_tp):
        rows.append(
            LabelledVerdict(
                finding_id=f"T{j:03d}",
                corpus=corpus,
                model_verdict="true_positive",
                confidence=round(min(0.55 + j * 0.02, 0.99), 4),
                true_label="true_positive",
            )
        )
    return rows


def poison(
    rows: Sequence[LabelledVerdict], ids: set[str]
) -> list[LabelledVerdict]:
    """Corrupt the ground-truth labels of `ids`, maximally.

    Every false-positive verdict among them becomes a real defect, which is the
    single change that most destroys the precision a threshold is fitted
    against. Only `true_label` moves, so the canonical order — and therefore the
    fold assignment — is untouched, which is what makes the leakage comparison
    apples to apples.
    """
    out: list[LabelledVerdict] = []
    for row in rows:
        if row.finding_id in ids and row.model_verdict == "false_positive":
            out.append(
                LabelledVerdict(
                    finding_id=row.finding_id,
                    corpus=row.corpus,
                    model_verdict=row.model_verdict,
                    confidence=row.confidence,
                    true_label="true_positive",
                    fingerprint=row.fingerprint,
                    cwe=row.cwe,
                    status=row.status,
                    run_index=row.run_index,
                )
            )
        else:
            out.append(row)
    return out
