"""Shadow mode: the actuator's one on/off switch.

Ships this way on purpose. The design doc: "ship it in shadow mode first...
until the eval gates pass" — the same pattern Razorpay used for its Oncall Agent
and Anthropic describes for new automated reviewers. That makes shadow mode a
first-class mode, not a debug flag scattered as `if DEBUG` checks through every
call site: `ActuatorMode` is one `Literal`, read in exactly one place
(`Actuator.process` and its per-outcome methods below), and every one of those
methods either

  * logs a `ShadowAction` and returns *before* touching `self.github` /
    `self.dojo` / `self.tickets` (shadow), or
  * calls straight through to the real function (live),

with no third path and nothing that reads the mode anywhere else. "Every verdict
is logged" is met by `ShadowRecorder.record` running unconditionally, in both
modes, before the branch; "zero external actions" is met by the shadow branch
never holding a reference to anything that could take one.

Proving that inertness is a fake's job, not a flag's: the test suite wires
`Actuator(mode="shadow", ...)` with fakes for `GitHubClient`, `DojoClient` and
`TicketAdapter` that record every call they receive, runs a batch of realistic
findings through `Actuator.process`, and asserts those fakes recorded nothing —
never by reading `Actuator.mode` back and trusting it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Literal

from pramaan.agent.hooks import AuditLogger
from pramaan.mcp import dojo_tools, github_tools
from pramaan.mcp.dojo_tools import DojoClient
from pramaan.mcp.errors import GuardrailViolation
from pramaan.mcp.github_tools import GitHubClient, PullRequestRef
from pramaan.mcp.records import RecordStore
from pramaan.policy.engine import Decision
from pramaan.schemas import Finding, ProofBundle, Verdict
from pramaan.tickets.adapter import TicketAdapter, TicketRef

__all__ = ["ActuatorMode", "SHADOW", "LIVE", "ShadowAction", "ShadowRecorder", "Actuator"]

ActuatorMode = Literal["shadow", "live"]
SHADOW: ActuatorMode = "shadow"
LIVE: ActuatorMode = "live"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ShadowAction:
    """One thing the actuator would have done. `verb` names the real function
    live mode would have called instead of recording this."""

    finding_id: str
    verb: str
    detail: dict[str, Any] = field(default_factory=dict)
    ts: str = ""


class ShadowRecorder:
    """Every verdict processed, logged — regardless of mode.

    Kept in memory (`actions`, what the tests assert against) and, optionally,
    mirrored into the same hash-chained `AuditLogger` every other lane writes
    to. A shadow run then leaves the same tamper-evident trail a live run would,
    which is the point of shipping shadow mode as something to publish rather
    than a silent no-op nobody can later verify actually ran.
    """

    def __init__(
        self, *, audit: AuditLogger | None = None, clock: Callable[[], datetime] = _utc_now
    ) -> None:
        self.audit = audit
        self._clock = clock
        self.actions: list[ShadowAction] = []

    def record(self, verb: str, finding_id: str, detail: dict[str, Any]) -> ShadowAction:
        action = ShadowAction(
            finding_id=finding_id, verb=verb, detail=detail, ts=self._clock().isoformat()
        )
        self.actions.append(action)
        if self.audit is not None:
            self.audit.append(
                {"event": "actuator_action", "verb": verb, "finding_id": finding_id, "detail": detail}
            )
        return action

    def verbs_for(self, finding_id: str) -> list[str]:
        return [a.verb for a in self.actions if a.finding_id == finding_id]


class Actuator:
    """Dispatches a policy `Decision` to the right actuator call, or, in shadow
    mode, to a log entry instead.

    `mode` is read exactly once per method, at the top, before any client is
    touched — see the module docstring for why that ordering is the whole
    guarantee.
    """

    def __init__(
        self,
        mode: ActuatorMode,
        *,
        github: GitHubClient,
        dojo: DojoClient,
        tickets: TicketAdapter,
        pr_store: RecordStore,
        owner: str,
        repo: str,
        recorder: ShadowRecorder | None = None,
    ) -> None:
        self.mode = mode
        self.github = github
        self.dojo = dojo
        self.tickets = tickets
        self.pr_store = pr_store
        self.owner = owner
        self.repo = repo
        self.recorder = recorder if recorder is not None else ShadowRecorder()

    @property
    def is_shadow(self) -> bool:
        return self.mode == SHADOW

    # -- per-outcome methods ------------------------------------------------

    def auto_close(self, finding: Finding, verdict: Verdict, decision: Decision) -> ShadowAction | dict[str, Any]:
        self.recorder.record(
            "dojo.update_finding", finding.finding_id,
            {"verdict": verdict.verdict, "close": True, "rationale": decision.rationale},
        )
        if self.is_shadow:
            return self.recorder.actions[-1]
        return dojo_tools.update_finding(
            self.dojo, finding_id=finding.finding_id, verdict=verdict.verdict,
            rationale=decision.rationale, close=True,
        )

    def open_ticket(self, finding: Finding, decision: Decision) -> ShadowAction | TicketRef:
        self.recorder.record(
            "tickets.create_ticket", finding.finding_id,
            {"severity": decision.severity, "rationale": decision.rationale},
        )
        if self.is_shadow:
            return self.recorder.actions[-1]
        return self.tickets.create_ticket(finding, decision)

    def escalate(self, finding: Finding, verdict: Verdict, decision: Decision) -> ShadowAction | TicketRef:
        self.recorder.record(
            "tickets.create_ticket", finding.finding_id,
            {"escalate_reason": decision.escalate_reason, "rationale": decision.rationale},
        )
        if self.is_shadow:
            return self.recorder.actions[-1]
        return self.tickets.create_ticket(finding, decision)

    def open_draft_pr(
        self,
        finding: Finding,
        decision: Decision,
        proof: ProofBundle,
        *,
        title: str,
        body: str,
        base_branch: str = "main",
    ) -> ShadowAction | PullRequestRef:
        """Row 4 into row 6: only reachable once `decision.invokes_fixer` and the
        proof bundle actually permits a PR. Both are checked here too, not only
        by whatever upstream orchestration called this — a `fix_candidate`
        decision or a failed proof bundle refuses before either mode touches
        anything, so this method cannot be talked into opening a PR by a caller
        that skipped a step."""
        if not decision.invokes_fixer:
            raise GuardrailViolation(
                f"open_draft_pr called for {finding.finding_id!r} but its decision "
                f"is {decision.recommended_action!r}, not fix_candidate"
            )
        if not proof.may_open_pr:
            raise GuardrailViolation(
                f"proof bundle for {finding.finding_id!r} does not permit a PR: "
                f"blocking={[v.name for v in proof.blocking]}, "
                f"reviewer_approved={proof.reviewer_approved}"
            )
        self.recorder.record("github.create_draft_pr", finding.finding_id, {"title": title})
        if self.is_shadow:
            return self.recorder.actions[-1]
        return github_tools.create_draft_pr(
            self.pr_store, self.github, finding_id=finding.finding_id, owner=self.owner,
            repo=self.repo, title=title, body=body, base_branch=base_branch,
        )

    # -- dispatch -------------------------------------------------------------

    def process(
        self,
        finding: Finding,
        verdict: Verdict,
        decision: Decision,
        *,
        proof: ProofBundle | None = None,
        pr_title: str = "",
        pr_body: str = "",
    ) -> ShadowAction | dict[str, Any] | TicketRef | PullRequestRef:
        """Dispatch on `decision.recommended_action`. Fails closed on anything
        this policy layer did not teach it — same posture as `policy.engine.decide`
        itself, which fails closed on an unhandled verdict label.
        """
        action = decision.recommended_action
        if action == "auto_close":
            return self.auto_close(finding, verdict, decision)
        if action == "open_ticket":
            return self.open_ticket(finding, decision)
        if action == "escalate_human":
            return self.escalate(finding, verdict, decision)
        if action == "fix_candidate":
            if proof is None:
                # Upstream of the fixer/prover lanes: nothing to actuate yet.
                # Recorded like every other branch; no PR is opened without proof.
                return self.recorder.record(
                    "await_proof", finding.finding_id, {"cwe": verdict.cwe}
                )
            return self.open_draft_pr(finding, decision, proof, title=pr_title, body=pr_body)
        raise GuardrailViolation(f"unhandled recommended_action: {action!r}")
