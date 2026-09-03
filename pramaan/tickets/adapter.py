"""Ticket adapter: routes an `open_ticket` / `escalate_human` decision to a
tracker.

`GitHubIssuesAdapter` is real, built on the same `GitHubClient` seam
`pramaan.mcp.github_tools.create_draft_pr` uses. `DevRevAdapter` is a week-2
stub in the same shape as `pramaan.store.defectdojo_adapter.DefectDojoAdapter`:
every method raises `NotImplementedError` naming the endpoint it would call,
because a half-working client that silently no-ops is worse than one that says
so. Razorpay routes verdicts to DevRev per the design doc; this is the seam that
swap lands in.

No verb here can delete or close a ticket. `create_ticket` opens one, idempotent
by `finding_id`; `find_ticket` looks one up; `add_comment` posts an update. That
is the entire `TicketAdapter` Protocol — consistent with the guardrail table's
"no delete, no close-TP, no merge" for this whole lane. A human closes a ticket
by hand, in GitHub's or DevRev's own UI.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from pramaan.mcp.errors import GuardrailViolation
from pramaan.mcp.github_tools import GitHubClient
from pramaan.mcp.github_tools import comment as github_comment
from pramaan.mcp.killswitch import raise_if_engaged
from pramaan.mcp.records import RecordStore
from pramaan.policy.engine import Decision
from pramaan.schemas import Finding

__all__ = [
    "DevRevAdapter",
    "GitHubIssuesAdapter",
    "TicketAdapter",
    "TicketRef",
    "ticket_body",
    "ticket_title",
]


@dataclass(frozen=True, slots=True)
class TicketRef:
    system: str  # "github_issues" | "devrev"
    id: str  # issue number, or a DevRev work-item id, always as a string
    url: str
    finding_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> TicketRef:
        return cls(
            system=str(d["system"]),
            id=str(d["id"]),
            url=str(d["url"]),
            finding_id=str(d["finding_id"]),
        )


@runtime_checkable
class TicketAdapter(Protocol):
    """Create, find, comment. Nothing else — see the module docstring."""

    def create_ticket(self, finding: Finding, decision: Decision) -> TicketRef: ...

    def find_ticket(self, finding_id: str) -> TicketRef | None: ...

    def add_comment(self, ticket: TicketRef, body: str) -> None: ...


def ticket_title(finding: Finding, decision: Decision) -> str:
    return f"[{decision.severity.upper()}] {finding.rule_id}: {finding.path}:{finding.line_start}"


def ticket_body(finding: Finding, decision: Decision) -> str:
    # `finding.message` (the scanner's own text, attacker-influenced per the
    # triage lane's threat model) deliberately never reaches this string. Every
    # field used here is either scanner metadata that is not free text
    # (rule_id, cwe, path, line numbers) or `decision.*`, which
    # `pramaan.policy.engine` builds only from enum members and floats it owns
    # — never from model prose. A ticket assembled this way cannot carry an
    # injection payload through to whoever reads it.
    return (
        f"Finding: `{finding.finding_id}`\n"
        f"Rule: `{finding.rule_id}` ({finding.cwe or 'CWE unspecified'})\n"
        f"Location: `{finding.path}:{finding.line_start}-{finding.line_end}`\n"
        f"Severity: **{decision.severity}** (SSVC: {decision.ssvc_decision})\n\n"
        f"{decision.rationale}\n"
    )


def _marker(finding_id: str) -> str:
    digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:16]
    return f"<!-- pramaan:ticket finding_id={digest} -->"


class GitHubIssuesAdapter:
    """Backs tickets with GitHub Issues.

    Idempotency mirrors `create_draft_pr`: a local record short-circuits; a miss
    falls back to a marker search over GitHub's own issues (ground truth); only
    then is an issue created. A crash between a successful `create_issue` call
    and the local write below self-heals the same way `create_draft_pr` does.
    """

    def __init__(
        self,
        client: GitHubClient,
        store: RecordStore,
        comment_store: RecordStore,
        *,
        owner: str,
        repo: str,
    ) -> None:
        self.client = client
        self.store = store
        self.comment_store = comment_store
        self.owner = owner
        self.repo = repo

    def create_ticket(self, finding: Finding, decision: Decision) -> TicketRef:
        if not finding.finding_id:
            raise GuardrailViolation("create_ticket requires a non-empty finding_id")
        raise_if_engaged()

        cached = self.store.get(finding.finding_id)
        if cached is not None:
            return TicketRef.from_dict(cached)

        marker = _marker(finding.finding_id)
        found = self.client.find_issue_by_marker(owner=self.owner, repo=self.repo, marker=marker)
        if found is not None:
            ref = TicketRef(
                system="github_issues", id=str(found.number), url=found.url,
                finding_id=finding.finding_id,
            )
            self.store.put(finding.finding_id, ref.to_dict())
            return ref

        body = f"{ticket_body(finding, decision)}\n{marker}\n"
        issue = self.client.create_issue(
            owner=self.owner,
            repo=self.repo,
            title=ticket_title(finding, decision),
            body=body,
            labels=(decision.severity,),
        )
        ref = TicketRef(
            system="github_issues", id=str(issue.number), url=issue.url,
            finding_id=finding.finding_id,
        )
        self.store.put(finding.finding_id, ref.to_dict())
        return ref

    def find_ticket(self, finding_id: str) -> TicketRef | None:
        cached = self.store.get(finding_id)
        if cached is not None:
            return TicketRef.from_dict(cached)
        found = self.client.find_issue_by_marker(
            owner=self.owner, repo=self.repo, marker=_marker(finding_id)
        )
        if found is None:
            return None
        ref = TicketRef(
            system="github_issues", id=str(found.number), url=found.url, finding_id=finding_id
        )
        self.store.put(finding_id, ref.to_dict())
        return ref

    def add_comment(self, ticket: TicketRef, body: str) -> None:
        # Reuses `github_tools.comment` outright rather than re-implementing its
        # marker-based idempotency: same guarantee, one place it can be wrong.
        github_comment(
            self.comment_store,
            self.client,
            finding_id=ticket.finding_id,
            owner=self.owner,
            repo=self.repo,
            number=int(ticket.id),
            body=body,
            kind="ticket_update",
        )


class DevRevAdapter:
    """Week-2 stub (D6's `DefectDojoAdapter` pattern, applied to tickets): every
    method raises, naming the DevRev endpoint it would call. No HTTP client is
    implemented — use `GitHubIssuesAdapter` until this lands."""

    _NOT_YET = (
        "DevRevAdapter is a week-2 stub: no DevRev client is implemented. "
        "Use GitHubIssuesAdapter as the ticket system of record until it does."
    )

    def __init__(self, *, org_id: str, api_token: str | None = None) -> None:
        self.org_id = org_id
        # Held only so a caller can see whether credentials were supplied;
        # never logged, and there is nothing here that could transmit it yet.
        self._api_token = api_token

    def create_ticket(self, finding: Finding, decision: Decision) -> TicketRef:
        raise NotImplementedError(f"{self._NOT_YET} (create_ticket -> POST /works.create)")

    def find_ticket(self, finding_id: str) -> TicketRef | None:
        raise NotImplementedError(f"{self._NOT_YET} (find_ticket -> POST /works.list)")

    def add_comment(self, ticket: TicketRef, body: str) -> None:
        raise NotImplementedError(
            f"{self._NOT_YET} (add_comment -> POST /timeline-entries.create)"
        )
