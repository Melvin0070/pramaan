"""In-process MCP tools for GitHub (guardrails table, row "Ticketing / PR").

Exactly two verbs are exposed to a model as MCP tools: `create_draft_pr` and
`comment`. There is no delete, no merge, no close and no force-push anywhere in
this module — not gated behind a permission check that could be talked around,
simply absent from `GitHubClient`. A tool that does not exist cannot be talked
into firing.

**Idempotency, the headline requirement.** Two calls to `create_draft_pr` for the
same `finding_id` must yield exactly one pull request, including the case where
the first call's PR was created on GitHub but the process crashed before the
local record of it was written (a real failure mode: the API call and the local
write are two separate operations with no transaction spanning them). This is
solved by never trusting absence-of-a-local-record as evidence that nothing was
created:

  1. A `branch_name_for(finding_id)` is deterministic, so the same finding always
     targets the same head branch. That turns GitHub's own one-PR-per-(head,base)
     rule into a `finding_id`-keyed uniqueness constraint we get for free.
  2. `create_draft_pr` checks the local `RecordStore` first (fast path).
  3. On a miss, it asks GitHub directly via `find_pull_request_by_head` *before*
     creating anything. If a PR is already there — the crash scenario above —
     it is adopted: written into the local record and returned, never
     duplicated.
  4. If `create_pull_request` itself races and collides (GitHub returns
     "already exists"), the same lookup-and-adopt runs again rather than
     surfacing the collision as a failure.

`comment` gets the same treatment via a hidden marker embedded in the comment
body: a retry with identical content is a no-op, discovered either from the
local record or, on a miss, by scanning the target's existing comments for the
marker.

No network in this module's tests. `GitHubClient` is a `Protocol`; tests run
against a fake. `RestGitHubClient` is the real implementation and is never
exercised over a socket here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable
from urllib.parse import urlencode

from claude_agent_sdk import SdkMcpTool, create_sdk_mcp_server, tool
from claude_agent_sdk.types import McpSdkServerConfig

from pramaan.mcp._http import HttpError, request_json
from pramaan.mcp.errors import ActuatorError, ConfigurationError, GuardrailViolation
from pramaan.mcp.killswitch import raise_if_engaged
from pramaan.mcp.records import RecordStore

__all__ = [
    "GITHUB_API_BASE",
    "GITHUB_TOKEN_ENV_VAR",
    "CommentRef",
    "GitHubApiError",
    "GitHubClient",
    "IssueRef",
    "PullRequestAlreadyExists",
    "PullRequestRef",
    "RestGitHubClient",
    "branch_name_for",
    "build_github_tools",
    "comment",
    "create_draft_pr",
    "create_github_server",
]

GITHUB_API_BASE = "https://api.github.com"
GITHUB_TOKEN_ENV_VAR = "PRAMAAN_GITHUB_TOKEN"


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class GitHubApiError(ActuatorError):
    """Any non-2xx response from the GitHub REST API that is not the specific
    "a PR already exists" conflict `PullRequestAlreadyExists` covers."""


class PullRequestAlreadyExists(ActuatorError):
    """Raised by a `GitHubClient.create_pull_request` implementation when the
    create call itself collides with an existing PR for the same head/base.
    Recovered by `create_draft_pr` looking the existing PR up — never treated as
    a hard failure, and never used to justify creating a second one."""


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PullRequestRef:
    number: int
    url: str
    head: str
    base: str
    draft: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> PullRequestRef:
        return cls(
            number=int(d["number"]),
            url=str(d["url"]),
            head=str(d["head"]),
            base=str(d["base"]),
            draft=bool(d.get("draft", True)),
        )


@dataclass(frozen=True, slots=True)
class CommentRef:
    id: int
    url: str
    target_number: int
    body: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> CommentRef:
        return cls(
            id=int(d["id"]),
            url=str(d["url"]),
            target_number=int(d["target_number"]),
            body=str(d.get("body", "")),
        )


@dataclass(frozen=True, slots=True)
class IssueRef:
    number: int
    url: str
    body: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> IssueRef:
        return cls(number=int(d["number"]), url=str(d["url"]), body=str(d.get("body", "")))


# --------------------------------------------------------------------------- #
# The client seam
# --------------------------------------------------------------------------- #


@runtime_checkable
class GitHubClient(Protocol):
    """The entire GitHub surface this project is allowed to touch.

    Six methods, all read-or-create. Deliberately missing: delete ref/branch,
    merge, close issue/PR, force-push. `tickets.adapter.GitHubIssuesAdapter`
    reuses this same Protocol for its issue methods rather than defining a
    second, near-identical client — one seam, one place to audit for what it
    can and cannot do.
    """

    def find_pull_request_by_head(
        self, *, owner: str, repo: str, head: str, base: str
    ) -> PullRequestRef | None: ...

    def create_pull_request(
        self, *, owner: str, repo: str, title: str, body: str, head: str, base: str, draft: bool
    ) -> PullRequestRef: ...

    def list_issue_comments(self, *, owner: str, repo: str, number: int) -> list[CommentRef]: ...

    def create_issue_comment(
        self, *, owner: str, repo: str, number: int, body: str
    ) -> CommentRef: ...

    def find_issue_by_marker(self, *, owner: str, repo: str, marker: str) -> IssueRef | None: ...

    def create_issue(
        self, *, owner: str, repo: str, title: str, body: str, labels: Sequence[str]
    ) -> IssueRef: ...


class RestGitHubClient:
    """The real `GitHubClient`. Every method maps to exactly one GitHub REST
    call; there is no method here that maps to delete, merge or force-push,
    because `GitHubClient` does not declare one. Never exercised over a real
    socket in this project's own test suite — tests run against a fake."""

    def __init__(self, token: str, *, base_url: str = GITHUB_API_BASE) -> None:
        if not token or not token.strip():
            # Fail closed: a client built with no credentials must refuse to
            # exist, not construct successfully and silently no-op on its first
            # real call while the caller believes it worked.
            raise ConfigurationError(
                "GitHub token is empty; refusing to construct a client that "
                "would silently no-op on every call"
            )
        self._token = token
        self._base_url = base_url.rstrip("/")

    @classmethod
    def from_env(
        cls,
        *,
        env_var: str = GITHUB_TOKEN_ENV_VAR,
        env: Mapping[str, str] | None = None,
        base_url: str = GITHUB_API_BASE,
    ) -> RestGitHubClient:
        source = os.environ if env is None else env
        token = source.get(env_var, "")
        if not token.strip():
            raise ConfigurationError(
                f"${env_var} is not set; refusing to build a GitHub client with "
                "no token rather than deferring the failure to the first call"
            )
        return cls(token, base_url=base_url)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pramaan-actuator",
        }

    def find_pull_request_by_head(
        self, *, owner: str, repo: str, head: str, base: str
    ) -> PullRequestRef | None:
        query = urlencode({"head": f"{owner}:{head}", "base": base, "state": "all"})
        url = f"{self._base_url}/repos/{owner}/{repo}/pulls?{query}"
        results = self._get(url)
        if not results:
            return None
        first = results[0]
        return PullRequestRef(
            number=first["number"],
            url=first["html_url"],
            head=head,
            base=base,
            draft=bool(first.get("draft", False)),
        )

    def create_pull_request(
        self, *, owner: str, repo: str, title: str, body: str, head: str, base: str, draft: bool
    ) -> PullRequestRef:
        url = f"{self._base_url}/repos/{owner}/{repo}/pulls"
        payload = {"title": title, "body": body, "head": head, "base": base, "draft": draft}
        try:
            created = request_json("POST", url, headers=self._headers(), json_body=payload)
        except HttpError as exc:
            if exc.status == 422 and "already exists" in exc.body.lower():
                raise PullRequestAlreadyExists(
                    f"GitHub already has a PR for {head} -> {base}"
                ) from exc
            raise GitHubApiError(str(exc)) from exc
        return PullRequestRef(
            number=created["number"],
            url=created["html_url"],
            head=head,
            base=base,
            draft=bool(created.get("draft", draft)),
        )

    def list_issue_comments(self, *, owner: str, repo: str, number: int) -> list[CommentRef]:
        url = (
            f"{self._base_url}/repos/{owner}/{repo}/issues/{number}/comments"
            f"?{urlencode({'per_page': 100})}"
        )
        results = self._get(url) or []
        return [
            CommentRef(id=c["id"], url=c["html_url"], target_number=number, body=c.get("body", ""))
            for c in results
        ]

    def create_issue_comment(self, *, owner: str, repo: str, number: int, body: str) -> CommentRef:
        url = f"{self._base_url}/repos/{owner}/{repo}/issues/{number}/comments"
        try:
            created = request_json(
                "POST", url, headers=self._headers(), json_body={"body": body}
            )
        except HttpError as exc:
            raise GitHubApiError(str(exc)) from exc
        return CommentRef(
            id=created["id"], url=created["html_url"], target_number=number, body=body
        )

    def find_issue_by_marker(self, *, owner: str, repo: str, marker: str) -> IssueRef | None:
        search_terms = f'repo:{owner}/{repo} in:body "{marker}"'
        url = f"{self._base_url}/search/issues?{urlencode({'q': search_terms})}"
        result = self._get(url) or {}
        items = result.get("items") or []
        if not items:
            return None
        first = items[0]
        return IssueRef(number=first["number"], url=first["html_url"], body=first.get("body", ""))

    def create_issue(
        self, *, owner: str, repo: str, title: str, body: str, labels: Sequence[str]
    ) -> IssueRef:
        url = f"{self._base_url}/repos/{owner}/{repo}/issues"
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = list(labels)
        try:
            created = request_json("POST", url, headers=self._headers(), json_body=payload)
        except HttpError as exc:
            raise GitHubApiError(str(exc)) from exc
        return IssueRef(number=created["number"], url=created["html_url"], body=body)

    def _get(self, url: str) -> Any:
        try:
            return request_json("GET", url, headers=self._headers())
        except HttpError as exc:
            raise GitHubApiError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Branch naming — the idempotency key made concrete
# --------------------------------------------------------------------------- #

_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")
# Git refs have no hard length limit worth relying on across hosts; this keeps
# branch names comfortably short while the sha8 suffix keeps two findings that
# slugify the same (different punctuation, same letters) from colliding.
_MAX_SLUG_LEN = 160


def branch_name_for(finding_id: str) -> str:
    """Deterministic head-branch name for a finding.

    This *is* the idempotency key on the GitHub side: two calls for the same
    `finding_id` always target the same head, so GitHub's own one-PR-per-
    (head, base) rule does the deduplication in exactly the case where the local
    record is the thing that is missing.
    """
    if not finding_id:
        raise GuardrailViolation("branch_name_for requires a non-empty finding_id")
    slug = _SLUG_RE.sub("-", finding_id).strip("-").lower()[:_MAX_SLUG_LEN]
    digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:8]
    return f"pramaan/fix/{slug}-{digest}"


# --------------------------------------------------------------------------- #
# Core logic — plain functions, importable and testable without the SDK
# --------------------------------------------------------------------------- #


def create_draft_pr(
    store: RecordStore,
    client: GitHubClient,
    *,
    finding_id: str,
    owner: str,
    repo: str,
    title: str,
    body: str,
    base_branch: str = "main",
) -> PullRequestRef:
    """Open a draft PR for `finding_id`, or return the one that already exists.

    See the module docstring for the three-step recovery this implements. The
    contract callers rely on: after this returns (or raises `GitHubApiError`),
    there is at most one PR for this `finding_id` on GitHub, never two.
    """
    if not finding_id:
        raise GuardrailViolation(
            "create_draft_pr requires a non-empty finding_id: idempotency has "
            "nothing to key on without it"
        )
    raise_if_engaged()

    head = branch_name_for(finding_id)

    cached = store.get(finding_id)
    if cached is not None:
        return PullRequestRef.from_dict(cached)

    existing = client.find_pull_request_by_head(owner=owner, repo=repo, head=head, base=base_branch)
    if existing is not None:
        # Crash-recovery path: a previous call's `create_pull_request` reached
        # GitHub but the process died before the `store.put` below ran. GitHub's
        # head+base uniqueness is ground truth; adopt it instead of creating a
        # second PR for the same finding.
        store.put(finding_id, existing.to_dict())
        return existing

    try:
        created = client.create_pull_request(
            owner=owner, repo=repo, title=title, body=body, head=head, base=base_branch, draft=True
        )
    except PullRequestAlreadyExists:
        # The narrower race: the lookup above missed it (e.g. eventual
        # consistency on the real search/list endpoints) and the create call
        # hit GitHub's own uniqueness constraint instead. Same recovery either
        # way — look it up again rather than surfacing the collision as a
        # caller-visible failure.
        found = client.find_pull_request_by_head(owner=owner, repo=repo, head=head, base=base_branch)
        if found is None:
            raise GitHubApiError(
                f"GitHub reports a PR already exists for {head} -> {base_branch} "
                "but a follow-up lookup cannot find it"
            ) from None
        store.put(finding_id, found.to_dict())
        return found

    store.put(finding_id, created.to_dict())
    return created


def comment(
    store: RecordStore,
    client: GitHubClient,
    *,
    finding_id: str,
    owner: str,
    repo: str,
    number: int,
    body: str,
    kind: str = "note",
) -> CommentRef:
    """Post a comment on issue/PR `number`, unless one with identical content
    for this `finding_id` and `kind` is already there.

    A hidden marker carrying a content hash is appended to every posted body.
    Idempotency is content-addressed rather than a one-shot flag: calling this
    again with a *different* body for the same finding posts a new comment
    (a later status update is not a duplicate of an earlier one), while an exact
    retry — the crash-recovery case — is a no-op discovered either from the
    local record or, on a miss, from a scan of the target's existing comments.
    """
    if not finding_id:
        raise GuardrailViolation("comment requires a non-empty finding_id")
    raise_if_engaged()

    digest = hashlib.sha256(f"{kind}:{body}".encode("utf-8")).hexdigest()[:16]
    key = f"{finding_id}:{number}:{digest}"
    marker = f"<!-- pramaan:comment finding_id={finding_id} kind={kind} digest={digest} -->"

    cached = store.get(key)
    if cached is not None:
        return CommentRef.from_dict(cached)

    for existing in client.list_issue_comments(owner=owner, repo=repo, number=number):
        if marker in existing.body:
            store.put(key, existing.to_dict())
            return existing

    created = client.create_issue_comment(
        owner=owner, repo=repo, number=number, body=f"{body}\n\n{marker}"
    )
    store.put(key, created.to_dict())
    return created


# --------------------------------------------------------------------------- #
# MCP wiring
# --------------------------------------------------------------------------- #

_CREATE_DRAFT_PR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["finding_id", "title", "body"],
    "properties": {
        "finding_id": {"type": "string", "minLength": 1},
        "title": {"type": "string", "minLength": 1},
        "body": {"type": "string"},
        "base_branch": {"type": "string", "minLength": 1},
    },
}

_COMMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["finding_id", "number", "body"],
    "properties": {
        "finding_id": {"type": "string", "minLength": 1},
        "number": {"type": "integer", "minimum": 1},
        "body": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "minLength": 1},
    },
}


def _error_result(exc: Exception) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}


def _ok_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]}


def build_github_tools(
    store: RecordStore, client: GitHubClient, *, owner: str, repo: str
) -> list[SdkMcpTool[Any]]:
    """The two `SdkMcpTool` instances. `owner`/`repo` are closed over here, not
    taken as tool arguments — a single run targets one fork, and the model has
    no way to redirect a call at a repo of its choosing."""

    @tool(
        "create_draft_pr",
        "Open a draft pull request for a triaged, proven finding. Idempotent: "
        "calling this again for the same finding_id returns the existing PR "
        "instead of opening a second one.",
        _CREATE_DRAFT_PR_SCHEMA,
    )
    async def _create_draft_pr(args: dict[str, Any]) -> dict[str, Any]:
        try:
            ref = create_draft_pr(
                store,
                client,
                finding_id=args["finding_id"],
                owner=owner,
                repo=repo,
                title=args["title"],
                body=args["body"],
                base_branch=args.get("base_branch", "main"),
            )
        except ActuatorError as exc:
            return _error_result(exc)
        return _ok_result({"finding_id": args["finding_id"], **ref.to_dict()})

    @tool(
        "comment",
        "Post a status comment on an existing issue or pull request. Idempotent "
        "by finding_id and content: an identical retry does not double-post.",
        _COMMENT_SCHEMA,
    )
    async def _comment(args: dict[str, Any]) -> dict[str, Any]:
        try:
            ref = comment(
                store,
                client,
                finding_id=args["finding_id"],
                owner=owner,
                repo=repo,
                number=args["number"],
                body=args["body"],
                kind=args.get("kind", "note"),
            )
        except ActuatorError as exc:
            return _error_result(exc)
        return _ok_result({"finding_id": args["finding_id"], **ref.to_dict()})

    return [_create_draft_pr, _comment]


def create_github_server(
    store: RecordStore, client: GitHubClient, *, owner: str, repo: str, name: str = "github"
) -> McpSdkServerConfig:
    return create_sdk_mcp_server(
        name=name, tools=build_github_tools(store, client, owner=owner, repo=repo)
    )
