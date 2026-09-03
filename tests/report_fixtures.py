"""Shared fixtures for the Lane G tests.

The corpus fixture is the real one. `real_corpus()` reads
`data/corpus/findings.jsonl` — 121 hand-collected Semgrep findings across 13
live Razorpay PHP repositories — because the disclosure test is only worth
running against the paths it is actually protecting. A synthetic path called
`src/Api.php` would pass a leak test that the real
`admin/view/template/payment/razorpay.twig` fails.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pramaan.evals.injection import CONTROL_ARM, HARDENED_ARM, run_paired
from pramaan.evals.runner import SuiteResult, ci_suite
from pramaan.proof.bundle import build_bundle
from pramaan.schemas import Finding, ProofBundle, TestsValidation, ValidatorResult
from pramaan.validators.poc import PoCOutcome

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "data" / "corpus" / "findings.jsonl"

STAMP = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


def real_corpus() -> list[Finding]:
    """The 121 real findings, straight off disk."""
    with CORPUS_PATH.open("r", encoding="utf-8") as handle:
        return [
            Finding.from_dict(json.loads(line))
            for line in handle
            if line.strip()
        ]


def synthetic_finding(
    *,
    finding_id: str = "semgrep:xss:juice-shop:routes/search.js:12",
    repo: str = "juice-shop",
    path: str = "routes/search.js",
    rule_id: str = "javascript.express.security.audit.xss",
    line_start: int = 12,
    snippet: str | None = "res.send('<h1>' + req.query.q + '</h1>')",
) -> Finding:
    """A finding on an allowlisted synthetic target."""
    return Finding(
        finding_id=finding_id,
        fingerprint=f"fp-{abs(hash(finding_id)) % (10**12):012d}",
        tool="semgrep",
        rule_id=rule_id,
        message="Reflected user input.",
        severity_reported="high",
        repo=repo,
        path=path,
        line_start=line_start,
        line_end=line_start,
        cwe="CWE-79",
        snippet=snippet,
    )


def full_proof_bundle(finding_id: str, *, reviewer_approved: bool = True) -> ProofBundle:
    return build_bundle(
        finding_id=finding_id,
        funnel="full_proof",
        tests=TestsValidation(
            result="PASS", base_executed=40, base_passed=40,
            patched_executed=40, patched_passed=40,
        ),
        validators=[
            ValidatorResult("diff_in_scope", "pass"),
            ValidatorResult("no_cheating", "pass"),
            ValidatorResult("rescan_clean", "pass"),
        ],
        poc=PoCOutcome(
            result="BLOCKED",
            outcome="pass",
            detail="exploit reproduced on base, blocked on patched",
            base_exploited=True,
            patched_exploited=False,
        ),
        reviewer_approved=reviewer_approved,
    )


def partial_proof_bundle(
    finding_id: str,
    *,
    tests: TestsValidation | None = None,
    rescan: str = "pass",
) -> ProofBundle:
    return build_bundle(
        finding_id=finding_id,
        funnel="partial_proof",
        tests=tests
        or TestsValidation(
            result="PASS", base_executed=32, base_passed=32,
            patched_executed=32, patched_passed=32,
        ),
        validators=[
            ValidatorResult("diff_in_scope", "pass"),
            ValidatorResult("no_cheating", "pass"),
            ValidatorResult("rescan_clean", rescan),  # type: ignore[arg-type]
        ],
        poc=None,
        reviewer_approved=False,
    )


def no_suite_bundle(finding_id: str) -> ProofBundle:
    """D5: a target with no test suite. `NO_SUITE` fails closed."""
    return partial_proof_bundle(
        finding_id,
        tests=TestsValidation(result="NO_SUITE", detail="no phpunit.xml in this tree"),
    )


def suite_result(**kwargs: Any) -> SuiteResult:
    """A real `SuiteResult` from the CI tier, over synthetic labelled rows."""
    from test_eval_runner import suite_corpus  # local import: reuse Lane F's builder

    attempts, labels = suite_corpus(**kwargs)
    return ci_suite(attempts, labels, fraction=1.0)


def paired_injection(*, hardened_wins: set[str] | None = None):
    """A paired run whose control arm falls over on every deliverable channel."""
    from test_injection import make_run_trial

    return run_paired(
        make_run_trial(control_wins=None, hardened_wins=hardened_wins or set()),
        control=CONTROL_ARM,
        hardened=HARDENED_ARM,
    )
