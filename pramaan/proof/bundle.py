"""Assemble a graded `ProofBundle`, and report the funnel (D4).

This module does not decide anything. `ProofBundle.may_open_pr` is the gate and
it is already written; `pramaan.policy.engine.decide_after_proof` turns that gate
into a policy decision. What happens here is assembly and *labelling*: every
validator that could have run appears in the bundle with an honest outcome, so
that "four validators passed" can never mean "four validators, two of which
never executed".

The funnel is the deliverable. AutoPatchBench found ~60% of LLM patches "work"
until fuzzing and differential testing cut that to 5-11%. A harness that reports
only its final number reproduces the 60%; one that reports how many candidates
survived each stage reproduces the 5-11% and shows where the other 50 points
went. `funnel_report` produces exactly that, per funnel kind, never blended.

D4's two funnels are kept apart by construction: `build_bundle` refuses a
`full_proof` bundle with no PoC and a `partial_proof` bundle that has one, and
`funnel_report` refuses a mixed list.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from pramaan.schemas import (
    FunnelKind,
    ProofBundle,
    TestsValidation,
    ValidatorResult,
)
from pramaan.validators.cheating import validate_no_cheating
from pramaan.validators.diff_scope import validate_diff_scope
from pramaan.validators.poc import PoCOutcome, PoCSpec, run_poc
from pramaan.validators.process import CommandRunner, run_command, which
from pramaan.validators.rescan import rescan
from pramaan.validators.tests_validator import SuiteSpec, validate_tests

__all__ = [
    "STAGE_ORDER",
    "TESTS_VALIDATOR_NAME",
    "FunnelReport",
    "ProofRequest",
    "build_bundle",
    "funnel_report",
    "run_proof",
    "split_by_funnel",
]

# `TestsValidation.as_validator()` owns this name; the schema appends it to
# `all_validators` on its own, so passing one in would double-count it.
TESTS_VALIDATOR_NAME = "tests_green"

# Cheapest and most diagnostic first: a patch that edited eleven files is not
# worth a 30-minute test run to reject.
STAGE_ORDER: tuple[str, ...] = (
    "diff_in_scope",
    "no_cheating",
    "regression_test",
    "rescan_clean",
    TESTS_VALIDATOR_NAME,
    "poc_blocked",
)


def _order_key(name: str) -> tuple[int, str]:
    return (STAGE_ORDER.index(name), "") if name in STAGE_ORDER else (len(STAGE_ORDER), name)


def build_bundle(
    *,
    finding_id: str,
    funnel: FunnelKind,
    tests: TestsValidation,
    validators: Sequence[ValidatorResult] = (),
    poc: PoCOutcome | None = None,
    reviewer_approved: bool | None = None,
    diff_stat: Mapping[str, Any] | None = None,
    commit_sha: str | None = None,
    model: str | None = None,
    cost_usd: float = 0.0,
) -> ProofBundle:
    """Build one graded bundle.

    Args:
        validators: every non-tests validator, in any order. Sorted into
            `STAGE_ORDER` here so two bundles are always comparable.
        poc: the PoC outcome. `None` is not the same as "no PoC" - it means the
            PoC validator was never constructed, which is `unavailable`. Pass a
            `PoCOutcome` with `NO_POC` for a target that has no exploit.
        reviewer_approved: `None` until a reviewer has actually returned a
            verdict. The frozen schema fails closed on `None`; nothing here
            defaults it to anything else.

    Raises:
        ValueError: on a duplicated validator name, on a caller-supplied
            `tests_green` result, or on a bundle whose funnel label and PoC
            disagree (D4: the two funnels are never blended).
    """
    supplied = list(validators)

    names = [v.name for v in supplied]
    duplicates = sorted({n for n, c in Counter(names).items() if c > 1})
    if duplicates:
        raise ValueError(f"duplicate validator names in bundle: {duplicates}")
    if TESTS_VALIDATOR_NAME in names:
        raise ValueError(
            f"{TESTS_VALIDATOR_NAME!r} is produced by TestsValidation.as_validator(); "
            "pass the TestsValidation, not a ValidatorResult"
        )

    poc_result = poc.result if poc is not None else None
    if funnel == "full_proof" and poc_result in (None, "NO_POC"):
        raise ValueError(
            "full_proof requires a PoC exploit (D4). A finding with no PoC belongs "
            "in the partial_proof funnel, not in this one with a NO_POC row."
        )
    if funnel == "partial_proof" and poc_result not in (None, "NO_POC"):
        raise ValueError(
            f"partial_proof carries no PoC (D4), got poc={poc_result!r}. Relabel the "
            "bundle as full_proof rather than blending the funnels."
        )

    if poc is not None:
        supplied.append(poc.as_validator())
    else:
        supplied.append(
            ValidatorResult(
                "poc_blocked", "unavailable", "the PoC validator was never constructed"
            )
        )

    ordered = sorted(supplied, key=lambda v: _order_key(v.name))
    return ProofBundle(
        finding_id=finding_id,
        funnel=funnel,
        validators=ordered,
        tests=tests,
        poc=poc.result if poc is not None else "NO_POC",
        reviewer_approved=reviewer_approved,
        diff_stat=dict(diff_stat or {}),
        commit_sha=commit_sha,
        model=model,
        cost_usd=cost_usd,
    )


# --------------------------------------------------------------------------- #
# Running the validators
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ProofRequest:
    """Everything the deterministic layer needs. No model, no network."""

    finding_id: str
    funnel: FunnelKind
    base_tree: str | Path
    patched_tree: str | Path
    diff_text: str | None = None
    finding_path: str | None = None
    rule_id: str | None = None
    semgrep_config: str | None = None
    repo: str | None = None
    poc: PoCSpec | None = None
    suite: SuiteSpec | None = None
    extra_allowed: tuple[str, ...] = ()
    extra_validators: tuple[ValidatorResult, ...] = ()
    commit_sha: str | None = None
    model: str | None = None
    cost_usd: float = 0.0
    diff_stat: Mapping[str, Any] = field(default_factory=dict)
    rescan_from_base: bool = True


def run_proof(
    request: ProofRequest,
    *,
    reviewer_approved: bool | None = None,
    runner: CommandRunner = run_command,
    which_fn: Callable[[str], str | None] = which,
) -> ProofBundle:
    """Run every deterministic validator and assemble the bundle.

    `reviewer_approved` stays `None` unless a reviewer verdict is passed in.
    There is no code path here that sets it to `True`.
    """
    diff_result = validate_diff_scope(
        request.diff_text,
        finding_path=request.finding_path,
        extra_allowed=request.extra_allowed,
    )
    cheat_result = validate_no_cheating(
        request.diff_text,
        finding_path=request.finding_path,
        extra_allowed=request.extra_allowed,
    )

    if request.semgrep_config is None:
        rescan_result = ValidatorResult(
            "rescan_clean",
            "unavailable",
            "no semgrep ruleset was configured for this rescan",
        )
    else:
        rescan_result = rescan(
            patched_tree=request.patched_tree,
            base_tree=request.base_tree if request.rescan_from_base else None,
            config=request.semgrep_config,
            rule_id=request.rule_id,
            path=request.finding_path,
            repo=request.repo,
            runner=runner,
            which_fn=which_fn,
        )

    tests = validate_tests(
        base_tree=request.base_tree,
        patched_tree=request.patched_tree,
        suite=request.suite,
        runner=runner,
        which_fn=which_fn,
    )

    poc_outcome = run_poc(
        base_tree=request.base_tree,
        patched_tree=request.patched_tree,
        spec=request.poc,
        runner=runner,
        which_fn=which_fn,
    )

    return build_bundle(
        finding_id=request.finding_id,
        funnel=request.funnel,
        tests=tests,
        validators=[diff_result, cheat_result, rescan_result, *request.extra_validators],
        poc=poc_outcome,
        reviewer_approved=reviewer_approved,
        diff_stat=request.diff_stat,
        commit_sha=request.commit_sha,
        model=request.model,
        cost_usd=request.cost_usd,
    )


# --------------------------------------------------------------------------- #
# The funnel
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class FunnelReport:
    """N drafted -> survived stage 1 -> ... -> may open a PR."""

    funnel: FunnelKind
    drafted: int
    stages: tuple[str, ...]
    per_stage_pass: dict[str, int]
    per_stage_outcomes: dict[str, dict[str, int]]
    cumulative: dict[str, int]
    reviewer_approved: int
    may_open_pr: int

    @property
    def survival_rate(self) -> float:
        return self.may_open_pr / self.drafted if self.drafted else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "funnel": self.funnel,
            "drafted": self.drafted,
            "stages": list(self.stages),
            "per_stage_pass": dict(self.per_stage_pass),
            "per_stage_outcomes": {k: dict(v) for k, v in self.per_stage_outcomes.items()},
            "cumulative": dict(self.cumulative),
            "reviewer_approved": self.reviewer_approved,
            "may_open_pr": self.may_open_pr,
            "survival_rate": self.survival_rate,
        }


def split_by_funnel(
    bundles: Iterable[ProofBundle],
) -> dict[FunnelKind, list[ProofBundle]]:
    out: dict[FunnelKind, list[ProofBundle]] = {}
    for b in bundles:
        out.setdefault(b.funnel, []).append(b)
    return out


def funnel_report(bundles: Sequence[ProofBundle]) -> FunnelReport:
    """Stage-by-stage survival for one funnel.

    Raises:
        ValueError: on an empty list, or on bundles from more than one funnel.
            D4 forbids blending them, and a mixed denominator is exactly how a
            partial-proof result gets reported as a full-proof one.
    """
    if not bundles:
        raise ValueError("funnel_report needs at least one bundle to have a denominator")
    kinds = {b.funnel for b in bundles}
    if len(kinds) > 1:
        raise ValueError(
            f"refusing to blend funnels {sorted(kinds)} (D4); call split_by_funnel first"
        )
    kind = next(iter(kinds))

    stages: list[str] = []
    for b in bundles:
        for v in b.all_validators:
            if v.name not in stages:
                stages.append(v.name)
    stages.sort(key=_order_key)

    per_stage_pass = {s: 0 for s in stages}
    per_stage_outcomes: dict[str, dict[str, int]] = {
        s: {"pass": 0, "fail": 0, "skipped": 0, "unavailable": 0, "absent": 0}
        for s in stages
    }
    cumulative = {s: 0 for s in stages}

    for b in bundles:
        by_name = {v.name: v for v in b.all_validators}
        alive = True
        for stage in stages:
            v = by_name.get(stage)
            if v is None:
                per_stage_outcomes[stage]["absent"] += 1
                # A stage that is not even present cannot have been survived.
                alive = False
                continue
            per_stage_outcomes[stage][v.outcome] += 1
            if v.outcome == "pass":
                per_stage_pass[stage] += 1
            else:
                alive = False
            if alive:
                cumulative[stage] += 1

    return FunnelReport(
        funnel=kind,
        drafted=len(bundles),
        stages=tuple(stages),
        per_stage_pass=per_stage_pass,
        per_stage_outcomes=per_stage_outcomes,
        cumulative=cumulative,
        reviewer_approved=sum(1 for b in bundles if b.reviewer_approved is True),
        may_open_pr=sum(1 for b in bundles if b.may_open_pr),
    )
