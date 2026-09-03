"""`shadow.py`: the `Actuator` dispatch table, and the inertness proof.

The recording fakes below stand in for "the real thing" the way `FakeGitHubClient`
does in `test_mcp_github_tools.py`. The central test in this file
(`test_shadow_mode_takes_zero_external_actions_across_a_realistic_batch`) proves
shadow mode by asserting these fakes recorded nothing — never by reading
`Actuator.mode` back. Its twin
(`test_live_mode_calls_through_for_the_same_batch`) proves the dispatch table
is not simply dead code that happens to look inert: the same batch, same
`Actuator.process` calls, only the mode flipped, and the fakes light up.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from pramaan.agent.hooks import AuditLogger
from pramaan.mcp.dojo_tools import DojoClient
from pramaan.mcp.errors import GuardrailViolation, KillSwitchEngaged
from pramaan.mcp.github_tools import CommentRef, GitHubClient, IssueRef, PullRequestRef
from pramaan.mcp.records import InMemoryRecordStore
from pramaan.mcp.shadow import LIVE, SHADOW, Actuator, ShadowRecorder
from pramaan.policy.engine import decide
from pramaan.schemas import (
    BusinessImpact,
    Evidence,
    Finding,
    ProofBundle,
    ValidatorResult,
    Verdict,
)
# Aliased: pytest tries to collect any module-level name starting with "Test".
from pramaan.schemas import TestsValidation as SuiteRun
from pramaan.tickets.adapter import TicketAdapter, TicketRef

TAU = 0.85


# --------------------------------------------------------------------------- #
# Recording fakes — the "real thing" the tests prove was, or was not, touched
# --------------------------------------------------------------------------- #


class RecordingGitHubClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._seq = 100

    def find_pull_request_by_head(self, *, owner, repo, head, base):
        self.calls.append(("find_pull_request_by_head", {"head": head}))
        return None

    def create_pull_request(self, *, owner, repo, title, body, head, base, draft):
        self.calls.append(("create_pull_request", {"title": title}))
        self._seq += 1
        return PullRequestRef(number=self._seq, url=f"https://x/{self._seq}", head=head, base=base, draft=draft)

    def list_issue_comments(self, *, owner, repo, number):
        self.calls.append(("list_issue_comments", {"number": number}))
        return []

    def create_issue_comment(self, *, owner, repo, number, body):
        self.calls.append(("create_issue_comment", {"number": number}))
        return CommentRef(id=1, url="https://x/c1", target_number=number, body=body)

    def find_issue_by_marker(self, *, owner, repo, marker):
        self.calls.append(("find_issue_by_marker", {"marker": marker}))
        return None

    def create_issue(self, *, owner, repo, title, body, labels):
        self.calls.append(("create_issue", {"title": title}))
        return IssueRef(number=1, url="https://x/i1", body=body)


class RecordingDojoClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def get_finding(self, finding_id):
        self.calls.append(("get_finding", finding_id))
        return None

    def update_finding(self, finding_id, fields):
        self.calls.append(("update_finding", finding_id, dict(fields)))
        return {"finding_id": finding_id, **fields}


class RecordingTicketAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def create_ticket(self, finding, decision) -> TicketRef:
        self.calls.append(("create_ticket", finding.finding_id))
        return TicketRef(system="github_issues", id="1", url="https://x/1", finding_id=finding.finding_id)

    def find_ticket(self, finding_id):
        self.calls.append(("find_ticket", finding_id))
        return None

    def add_comment(self, ticket, body) -> None:
        self.calls.append(("add_comment", ticket.finding_id))


def test_recording_fakes_satisfy_their_protocols() -> None:
    assert isinstance(RecordingGitHubClient(), GitHubClient)
    assert isinstance(RecordingDojoClient(), DojoClient)
    assert isinstance(RecordingTicketAdapter(), TicketAdapter)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _finding(finding_id: str, path: str = "includes/misc.php", **overrides) -> Finding:
    base = dict(
        finding_id=finding_id, fingerprint="a" * 32, tool="semgrep", rule_id="php.tainted-sql",
        message="scanner message", severity_reported="high", repo="razorpay-woocommerce",
        path=path, line_start=5, line_end=5, cwe="CWE-89",
    )
    base.update(overrides)
    return Finding(**base)


def _verdict(finding_id: str, verdict: str, **overrides) -> Verdict:
    base = dict(
        finding_id=finding_id, verdict=verdict, confidence=0.9, cwe="CWE-89",
        evidence=[Evidence(file="includes/misc.php", line=5, why="tainted sink")],
        reachability="reachable_from_http", business_impact=BusinessImpact(),
        injection_observed=False, rationale="model prose",
    )
    base.update(overrides)
    return Verdict(**base)


def _passing_proof(finding_id: str) -> ProofBundle:
    return ProofBundle(
        finding_id=finding_id,
        funnel="full_proof",
        validators=[
            ValidatorResult("rescan_clean", "pass"),
            ValidatorResult("poc_blocked", "pass"),
            ValidatorResult("diff_in_scope", "pass"),
        ],
        tests=SuiteRun(result="PASS", base_executed=10, base_passed=10, patched_executed=11, patched_passed=11),
        poc="BLOCKED",
        reviewer_approved=True,
    )


def _failing_proof(finding_id: str) -> ProofBundle:
    return ProofBundle(
        finding_id=finding_id,
        funnel="full_proof",
        validators=[ValidatorResult("rescan_clean", "fail", "still flagged")],
        tests=SuiteRun(result="PASS", base_executed=10, base_passed=10, patched_executed=10, patched_passed=10),
        poc="STILL_EXPLOITABLE",
        reviewer_approved=True,
    )


def _actuator(mode, *, github=None, dojo=None, tickets=None, pr_store=None, recorder=None) -> Actuator:
    return Actuator(
        mode,
        github=github or RecordingGitHubClient(),
        dojo=dojo or RecordingDojoClient(),
        tickets=tickets or RecordingTicketAdapter(),
        pr_store=pr_store if pr_store is not None else InMemoryRecordStore(),
        owner="me",
        repo="fork",
        recorder=recorder,
    )


# A batch covering every branch of `decide`, built from the REAL policy engine
# rather than hand-authored decisions, so this exercises the actual verdict ->
# decision -> action path Pramaan ships.
def _realistic_batch() -> list[tuple[Finding, Verdict]]:
    return [
        (_finding("f-autoclose"), _verdict("f-autoclose", "false_positive", confidence=0.95)),
        (_finding("f-ticket", path="includes/path-traversal.php"), _verdict("f-ticket", "true_positive", cwe="CWE-22")),
        (
            _finding("f-sensitive", path="includes/payments/capture.php"),
            _verdict("f-sensitive", "true_positive", business_impact=BusinessImpact(payment_path=True)),
        ),
        (_finding("f-fixcandidate"), _verdict("f-fixcandidate", "true_positive", cwe="CWE-89")),
    ]


# --------------------------------------------------------------------------- #
# Per-outcome dispatch, in live mode
# --------------------------------------------------------------------------- #


def test_auto_close_dispatches_to_dojo_update_finding() -> None:
    dojo = RecordingDojoClient()
    act = _actuator(LIVE, dojo=dojo)
    finding, verdict = _finding("f1"), _verdict("f1", "false_positive", confidence=0.95)
    decision = decide(verdict, BusinessImpact(), TAU)
    assert decision.recommended_action == "auto_close"

    act.process(finding, verdict, decision)

    assert dojo.calls[0][0] == "update_finding"
    assert dojo.calls[0][2]["active"] is False


def test_open_ticket_dispatches_to_tickets_create_ticket() -> None:
    tickets = RecordingTicketAdapter()
    act = _actuator(LIVE, tickets=tickets)
    finding = _finding("f1", path="includes/path-traversal.php")
    verdict = _verdict("f1", "true_positive", cwe="CWE-22")
    decision = decide(verdict, BusinessImpact(), TAU)
    assert decision.recommended_action == "open_ticket"

    act.process(finding, verdict, decision)

    assert tickets.calls == [("create_ticket", "f1")]


def test_escalate_human_dispatches_to_tickets_create_ticket() -> None:
    tickets = RecordingTicketAdapter()
    act = _actuator(LIVE, tickets=tickets)
    finding = _finding("f1", path="includes/payments/capture.php")
    verdict = _verdict("f1", "true_positive", business_impact=BusinessImpact(payment_path=True))
    decision = decide(verdict, BusinessImpact(), TAU)
    assert decision.recommended_action == "escalate_human"

    act.process(finding, verdict, decision)

    assert tickets.calls == [("create_ticket", "f1")]


def test_fix_candidate_without_proof_takes_no_action_yet() -> None:
    github, dojo, tickets = RecordingGitHubClient(), RecordingDojoClient(), RecordingTicketAdapter()
    act = _actuator(LIVE, github=github, dojo=dojo, tickets=tickets)
    finding, verdict = _finding("f1"), _verdict("f1", "true_positive", cwe="CWE-89")
    decision = decide(verdict, BusinessImpact(), TAU)
    assert decision.recommended_action == "fix_candidate"

    result = act.process(finding, verdict, decision)  # no proof= given

    assert github.calls == [] and dojo.calls == [] and tickets.calls == []
    assert result.verb == "await_proof"


def test_fix_candidate_with_passing_proof_opens_a_draft_pr() -> None:
    github = RecordingGitHubClient()
    act = _actuator(LIVE, github=github)
    finding, verdict = _finding("f1"), _verdict("f1", "true_positive", cwe="CWE-89")
    decision = decide(verdict, BusinessImpact(), TAU)

    ref = act.process(finding, verdict, decision, proof=_passing_proof("f1"), pr_title="fix sqli")

    assert isinstance(ref, PullRequestRef)
    assert github.calls[-1] == ("create_pull_request", {"title": "fix sqli"})


def test_fix_candidate_with_failing_proof_refuses_to_open_a_pr() -> None:
    github = RecordingGitHubClient()
    act = _actuator(LIVE, github=github)
    finding, verdict = _finding("f1"), _verdict("f1", "true_positive", cwe="CWE-89")
    decision = decide(verdict, BusinessImpact(), TAU)

    with pytest.raises(GuardrailViolation):
        act.process(finding, verdict, decision, proof=_failing_proof("f1"), pr_title="fix sqli")

    assert github.calls == []


def test_open_draft_pr_refuses_when_decision_is_not_fix_candidate() -> None:
    """Defence in depth: even called directly, `open_draft_pr` will not act on a
    decision that never reached `fix_candidate`, regardless of the proof."""
    github = RecordingGitHubClient()
    act = _actuator(LIVE, github=github)
    finding = _finding("f1", path="includes/path-traversal.php")
    verdict = _verdict("f1", "true_positive", cwe="CWE-22")
    decision = decide(verdict, BusinessImpact(), TAU)
    assert decision.recommended_action == "open_ticket"

    with pytest.raises(GuardrailViolation):
        act.open_draft_pr(finding, decision, _passing_proof("f1"), title="t", body="b")

    assert github.calls == []


def test_actuator_fails_closed_on_an_unhandled_recommended_action() -> None:
    act = _actuator(LIVE)
    finding, verdict = _finding("f1"), _verdict("f1", "true_positive")
    decision = replace(decide(verdict, BusinessImpact(), TAU), recommended_action="do_something_new")  # type: ignore[arg-type]

    with pytest.raises(GuardrailViolation):
        act.process(finding, verdict, decision)


def test_live_actuator_is_still_stopped_by_the_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    """The kill switch reaches through the dispatcher: `Actuator` does not
    bypass the per-function checks in `github_tools`/`dojo_tools`/`tickets`."""
    monkeypatch.setenv("PRAMAAN_KILLSWITCH", "1")
    dojo = RecordingDojoClient()
    act = _actuator(LIVE, dojo=dojo)
    finding, verdict = _finding("f1"), _verdict("f1", "false_positive", confidence=0.95)
    decision = decide(verdict, BusinessImpact(), TAU)

    with pytest.raises(KillSwitchEngaged):
        act.process(finding, verdict, decision)

    assert dojo.calls == []


# --------------------------------------------------------------------------- #
# The inertness proof
# --------------------------------------------------------------------------- #


def test_shadow_mode_takes_zero_external_actions_across_a_realistic_batch() -> None:
    github, dojo, tickets = RecordingGitHubClient(), RecordingDojoClient(), RecordingTicketAdapter()
    pr_store = InMemoryRecordStore()
    act = _actuator(SHADOW, github=github, dojo=dojo, tickets=tickets, pr_store=pr_store)

    batch = _realistic_batch()
    for finding, verdict in batch:
        decision = decide(verdict, BusinessImpact(), TAU)
        proof = _passing_proof(finding.finding_id) if decision.recommended_action == "fix_candidate" else None
        act.process(finding, verdict, decision, proof=proof, pr_title="fix", pr_body="body")

    # The proof: not "the flag says shadow", but that the fakes standing in for
    # the real world never received a single call.
    assert github.calls == []
    assert dojo.calls == []
    assert tickets.calls == []
    assert len(pr_store) == 0

    # And the pipeline did run: one verdict in, one logged action out, for
    # every finding in the batch.
    assert len(act.recorder.actions) == len(batch)
    assert {a.finding_id for a in act.recorder.actions} == {f.finding_id for f, _ in batch}


def test_live_mode_calls_through_for_the_same_batch() -> None:
    """The flip side: the same dispatch table, only the mode changed, and the
    fakes light up — proving the shadow test above is not vacuously true of a
    dispatcher that never calls anything in either mode."""
    github, dojo, tickets = RecordingGitHubClient(), RecordingDojoClient(), RecordingTicketAdapter()
    act = _actuator(LIVE, github=github, dojo=dojo, tickets=tickets)

    batch = _realistic_batch()
    for finding, verdict in batch:
        decision = decide(verdict, BusinessImpact(), TAU)
        proof = _passing_proof(finding.finding_id) if decision.recommended_action == "fix_candidate" else None
        act.process(finding, verdict, decision, proof=proof, pr_title="fix", pr_body="body")

    assert dojo.calls, "auto_close should have reached dojo"
    assert tickets.calls, "open_ticket/escalate_human should have reached tickets"
    assert github.calls, "fix_candidate + passing proof should have reached github"
    assert len(act.recorder.actions) == len(batch)


def test_every_verdict_is_logged_in_both_modes() -> None:
    batch = _realistic_batch()
    for mode in (SHADOW, LIVE):
        act = _actuator(mode)
        for finding, verdict in batch:
            decision = decide(verdict, BusinessImpact(), TAU)
            proof = _passing_proof(finding.finding_id) if decision.recommended_action == "fix_candidate" else None
            act.process(finding, verdict, decision, proof=proof, pr_title="fix", pr_body="body")
        assert len(act.recorder.actions) == len(batch)


def test_shadow_recorder_mirrors_into_the_audit_log(tmp_path) -> None:
    log = tmp_path / "audit.jsonl"
    recorder = ShadowRecorder(audit=AuditLogger(log))
    act = _actuator(SHADOW, recorder=recorder)
    finding, verdict = _finding("f1"), _verdict("f1", "false_positive", confidence=0.95)
    decision = decide(verdict, BusinessImpact(), TAU)

    act.process(finding, verdict, decision)

    assert AuditLogger.verify(log) is True
    from pramaan.agent.hooks import iter_audit_records

    records = list(iter_audit_records(log))
    assert len(records) == 1
    assert records[0]["event"] == "actuator_action"
    assert records[0]["finding_id"] == "f1"
