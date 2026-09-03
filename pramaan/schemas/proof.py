"""Graded proof bundle (binding decisions D4 and D5).

A proof bundle is never a boolean. Each validator records whether it RAN, was
SKIPPED (not applicable to this target) or was UNAVAILABLE (should have run,
could not). "All validators passed" on a target where three of them never ran is
the exact dishonesty this schema exists to prevent — AutoPatchBench found ~60%
of patches "work" until you actually test them.

Two funnels are reported, never blended (D4):
  - full_proof:    Juice Shop, PoC exploit available
  - partial_proof: real razorpay-php findings, no PoC
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ValidatorOutcome = Literal["pass", "fail", "skipped", "unavailable"]
TestsResult = Literal["PASS", "FAIL", "NO_SUITE"]
PoCResult = Literal["BLOCKED", "STILL_EXPLOITABLE", "INVALID_POC", "NO_POC"]
FunnelKind = Literal["full_proof", "partial_proof"]


@dataclass(frozen=True, slots=True)
class ValidatorResult:
    name: str
    outcome: ValidatorOutcome
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def blocks_pr(self) -> bool:
        """Fail closed: anything that is not an explicit pass blocks the PR."""
        return self.outcome != "pass"


@dataclass(frozen=True, slots=True)
class TestsValidation:
    """D5: tri-state, with counts from BOTH trees so a cheating patch is visible."""

    result: TestsResult
    base_executed: int = 0
    base_passed: int = 0
    patched_executed: int = 0
    patched_passed: int = 0
    detail: str = ""

    @property
    def fewer_tests_ran(self) -> bool:
        """A patch that deletes or skips tests runs fewer of them. That is cheating."""
        return self.patched_executed < self.base_executed

    def as_validator(self) -> ValidatorResult:
        if self.result == "NO_SUITE":
            # D5: NO_SUITE fails closed. No suite is not evidence of a working fix.
            return ValidatorResult(
                "tests_green", "unavailable", self.detail or "target has no test suite",
                asdict(self),
            )
        if self.fewer_tests_ran:
            return ValidatorResult(
                "tests_green", "fail",
                f"cheating-patch flag: patched tree ran {self.patched_executed} tests, "
                f"base ran {self.base_executed}",
                asdict(self),
            )
        return ValidatorResult(
            "tests_green", "pass" if self.result == "PASS" else "fail",
            self.detail, asdict(self),
        )


@dataclass(frozen=True, slots=True)
class ProofBundle:
    finding_id: str
    funnel: FunnelKind
    validators: list[ValidatorResult]
    tests: TestsValidation
    poc: PoCResult = "NO_POC"
    reviewer_approved: bool | None = None
    diff_stat: dict[str, Any] = field(default_factory=dict)
    commit_sha: str | None = None
    model: str | None = None
    cost_usd: float = 0.0

    @property
    def all_validators(self) -> list[ValidatorResult]:
        return [*self.validators, self.tests.as_validator()]

    @property
    def blocking(self) -> list[ValidatorResult]:
        return [v for v in self.all_validators if v.blocks_pr]

    @property
    def may_open_pr(self) -> bool:
        """Every validator passed AND the reviewer approved. Fail closed on None."""
        return not self.blocking and self.reviewer_approved is True

    def grade(self) -> dict[str, int]:
        counts = {"pass": 0, "fail": 0, "skipped": 0, "unavailable": 0}
        for v in self.all_validators:
            counts[v.outcome] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["grade"] = self.grade()
        d["may_open_pr"] = self.may_open_pr
        d["blocking"] = [v.name for v in self.blocking]
        return d
