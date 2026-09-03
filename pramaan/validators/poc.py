"""`poc_blocked`: run the exploit before the patch and after it.

The ordering is the whole validator. "The exploit fails on the patched tree" is
worth nothing on its own — an exploit that never worked also fails on the
patched tree, and so does one whose target service failed to boot. **A PoC that
does not succeed on the base tree is `INVALID_POC`, not a pass.** That single
rule is the difference between proving a fix and proving that a script exited
non-zero twice.

The four `PoCResult` values map onto validator outcomes like this:

| result             | outcome       | meaning                                        |
|--------------------|---------------|------------------------------------------------|
| `BLOCKED`          | `pass`        | exploited before, not after                    |
| `STILL_EXPLOITABLE`| `fail`        | exploited before and after                     |
| `INVALID_POC`      | `fail`        | did not exploit the base tree - the PoC is wrong|
| `INVALID_POC`      | `unavailable` | the harness could not run or timed out          |
| `NO_POC`           | `skipped`     | partial-proof funnel: no exploit exists (D4)    |

`INVALID_POC` covers two distinct situations and they are graded differently on
purpose. A PoC that ran cleanly and failed to exploit a known-vulnerable tree is
a definite negative result about the PoC; a PoC that never executed is an
absence of information. Both block the PR - `ValidatorResult.blocks_pr` is
`outcome != "pass"` - but only the first is a finding about the evidence.

`NO_POC` -> `skipped` -> blocks. That is intended and it is what D4's two
funnels mean in code: `partial_proof` findings (the real razorpay-php ones) have
no exploit harness, so they can never reach `may_open_pr`. D17 already says no
`file:line` disclosure and no PRs for those; this makes it structural rather
than a matter of remembering.

A timeout on the patched tree is `unavailable`, never `BLOCKED`. A hung exploit
looks exactly like a defeated one from the outside.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from pramaan.schemas import PoCResult, ValidatorOutcome, ValidatorResult
from pramaan.validators.process import (
    CommandResult,
    CommandRunner,
    run_command,
    which,
)

__all__ = [
    "POC_TIMEOUT_S",
    "PoCOutcome",
    "PoCSpec",
    "run_poc",
    "validate_poc",
]

VALIDATOR_NAME = "poc_blocked"
POC_TIMEOUT_S = 300.0


@dataclass(frozen=True, slots=True)
class PoCSpec:
    """How to run one exploit, and how to read what it says.

    `exploit_exit_code` defaults to 0 - the harness convention is "the PoC exits
    0 when the exploit lands". `success_marker`, when set, wins: a script that
    always exits 0 and prints its verdict is easier to write correctly than one
    that manages exit codes, and getting this wrong inverts the validator.
    """

    argv: tuple[str, ...]
    name: str = "poc"
    exploit_exit_code: int = 0
    success_marker: str | None = None
    timeout_s: float = POC_TIMEOUT_S
    bin_name: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)

    @property
    def command(self) -> str:
        return " ".join(self.argv)

    @property
    def runner_bin(self) -> str:
        return self.bin_name or (self.argv[0] if self.argv else "")


@dataclass(frozen=True, slots=True)
class PoCOutcome:
    result: PoCResult
    outcome: ValidatorOutcome
    detail: str = ""
    base_exploited: bool | None = None
    patched_exploited: bool | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_validator(self) -> ValidatorResult:
        return ValidatorResult(
            VALIDATOR_NAME,
            self.outcome,
            self.detail,
            {
                "poc_result": self.result,
                "base_exploited": self.base_exploited,
                "patched_exploited": self.patched_exploited,
                **self.evidence,
            },
        )


def _exploited(result: CommandResult, spec: PoCSpec) -> bool:
    if spec.success_marker is not None:
        return spec.success_marker in result.output
    return result.returncode == spec.exploit_exit_code


def _run_stage(
    tree: str | Path, spec: PoCSpec, runner: CommandRunner
) -> CommandResult:
    return runner(spec.argv, cwd=tree, timeout_s=spec.timeout_s, env=spec.env)


def _stage_evidence(stage: str, result: CommandResult) -> dict[str, Any]:
    tail = result.output.strip()
    return {
        f"{stage}_exit_code": result.returncode,
        f"{stage}_timed_out": result.timed_out,
        f"{stage}_output_tail": tail[-400:] if tail else "",
    }


def run_poc(
    *,
    base_tree: str | Path,
    patched_tree: str | Path,
    spec: PoCSpec | None,
    runner: CommandRunner = run_command,
    which_fn: Callable[[str], str | None] = which,
) -> PoCOutcome:
    """Run `spec` on the base tree, then on the patched tree, in that order."""
    if spec is None:
        return PoCOutcome(
            "NO_POC",
            "skipped",
            "no PoC exploit exists for this finding (partial-proof funnel, D4)",
        )

    if spec.runner_bin and which_fn(spec.runner_bin) is None:
        return PoCOutcome(
            "INVALID_POC",
            "unavailable",
            f"PoC runner {spec.runner_bin!r} is not installed; the exploit did not run",
            evidence={"command": spec.command},
        )

    base = _run_stage(base_tree, spec, runner)
    evidence: dict[str, Any] = {"command": spec.command, **_stage_evidence("base", base)}

    if not base.usable:
        return PoCOutcome(
            "INVALID_POC",
            "unavailable",
            f"PoC did not complete on the base tree: {base.summary()}",
            evidence=evidence,
        )

    if not _exploited(base, spec):
        # The load-bearing branch. Everything downstream of a PoC that cannot
        # exploit a known-vulnerable tree is theatre.
        return PoCOutcome(
            "INVALID_POC",
            "fail",
            (
                "PoC did not exploit the BASE tree, so it proves nothing about the "
                f"patch (exit {base.returncode}); fix the exploit before trusting "
                "any 'blocked' result from it"
            ),
            base_exploited=False,
            evidence=evidence,
        )

    patched = _run_stage(patched_tree, spec, runner)
    evidence.update(_stage_evidence("patched", patched))

    if not patched.usable:
        # A hung or crashed harness is indistinguishable from a defeated exploit
        # by exit code alone, so it is never read as one.
        return PoCOutcome(
            "INVALID_POC",
            "unavailable",
            f"PoC did not complete on the patched tree: {patched.summary()}",
            base_exploited=True,
            evidence=evidence,
        )

    if _exploited(patched, spec):
        return PoCOutcome(
            "STILL_EXPLOITABLE",
            "fail",
            "exploit still succeeds after the patch",
            base_exploited=True,
            patched_exploited=True,
            evidence=evidence,
        )

    return PoCOutcome(
        "BLOCKED",
        "pass",
        (
            f"exploit succeeded on the base tree (exit {base.returncode}) and fails "
            f"on the patched tree (exit {patched.returncode})"
        ),
        base_exploited=True,
        patched_exploited=False,
        evidence=evidence,
    )


def validate_poc(
    *,
    base_tree: str | Path,
    patched_tree: str | Path,
    spec: PoCSpec | None,
    runner: CommandRunner = run_command,
    which_fn: Callable[[str], str | None] = which,
) -> ValidatorResult:
    return run_poc(
        base_tree=base_tree,
        patched_tree=patched_tree,
        spec=spec,
        runner=runner,
        which_fn=which_fn,
    ).as_validator()
