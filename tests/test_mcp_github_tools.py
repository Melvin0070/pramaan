"""`github_tools.py`: idempotency is the headline requirement here.

`FakeGitHubClient` below is an in-memory stand-in for the real GitHub API —
`create_pull_request` enforces the same one-PR-per-(head,base) uniqueness GitHub
itself enforces, including raising `PullRequestAlreadyExists` on a collision, so
the recovery paths in `create_draft_pr` are exercised the same way they would be
against the real API, with no network involved.
"""

from __future__ import annotations

import asyncio

import pytest

from pramaan.mcp.errors import ConfigurationError, GuardrailViolation, KillSwitchEngaged
from pramaan.mcp.github_tools import (
    GITHUB_TOKEN_ENV_VAR,
    CommentRef,
    GitHubApiError,
    GitHubClient,
    IssueRef,
    PullRequestAlreadyExists,
    PullRequestRef,
    RestGitHubClient,
    branch_name_for,
    build_github_tools,
    comment,
    create_draft_pr,
    create_github_server,
)
from pramaan.mcp.records import InMemoryRecordStore, JsonFileRecordStore


class FakeGitHubClient:
    """In-memory GitHub. `create_pull_request` raises `PullRequestAlreadyExists`
    on a head/base collision, exactly like the real API's 422; `miss_find_once`
    simulates the real search/list endpoints' eventual consistency."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._prs: dict[tuple[str, str], PullRequestRef] = {}
        self._comments: dict[int, list[CommentRef]] = {}
        self._issues: list[IssueRef] = []
        self._pr_seq = 100
        self._comment_seq = 1000
        self._issue_seq = 500
        self.miss_find_once = False

    def find_pull_request_by_head(self, *, owner, repo, head, base) -> PullRequestRef | None:
        self.calls.append(("find_pull_request_by_head", {"head": head, "base": base}))
        if self.miss_find_once:
            self.miss_find_once = False
            return None
        return self._prs.get((head, base))

    def create_pull_request(
        self, *, owner, repo, title, body, head, base, draft
    ) -> PullRequestRef:
        self.calls.append(("create_pull_request", {"head": head, "base": base}))
        if (head, base) in self._prs:
            raise PullRequestAlreadyExists(f"exists: {head} -> {base}")
        self._pr_seq += 1
        ref = PullRequestRef(
            number=self._pr_seq, url=f"https://example/pull/{self._pr_seq}",
            head=head, base=base, draft=draft,
        )
        self._prs[(head, base)] = ref
        return ref

    def list_issue_comments(self, *, owner, repo, number) -> list[CommentRef]:
        self.calls.append(("list_issue_comments", {"number": number}))
        return list(self._comments.get(number, []))

    def create_issue_comment(self, *, owner, repo, number, body) -> CommentRef:
        self.calls.append(("create_issue_comment", {"number": number}))
        self._comment_seq += 1
        ref = CommentRef(
            id=self._comment_seq, url=f"https://example/c/{self._comment_seq}",
            target_number=number, body=body,
        )
        self._comments.setdefault(number, []).append(ref)
        return ref

    def find_issue_by_marker(self, *, owner, repo, marker) -> IssueRef | None:
        self.calls.append(("find_issue_by_marker", {"marker": marker}))
        return next((i for i in self._issues if marker in i.body), None)

    def create_issue(self, *, owner, repo, title, body, labels) -> IssueRef:
        self.calls.append(("create_issue", {"title": title}))
        self._issue_seq += 1
        ref = IssueRef(number=self._issue_seq, url=f"https://example/issues/{self._issue_seq}", body=body)
        self._issues.append(ref)
        return ref


class AlwaysConflictingClient:
    """A pathological fake: every create collides and no lookup ever finds the
    thing it collided with. Used to prove `create_draft_pr` surfaces this as an
    error rather than looping or fabricating a result."""

    def find_pull_request_by_head(self, *, owner, repo, head, base) -> PullRequestRef | None:
        return None

    def create_pull_request(self, *, owner, repo, title, body, head, base, draft) -> PullRequestRef:
        raise PullRequestAlreadyExists("always conflicts")

    def list_issue_comments(self, *, owner, repo, number):
        return []

    def create_issue_comment(self, *, owner, repo, number, body):
        raise NotImplementedError

    def find_issue_by_marker(self, *, owner, repo, marker):
        return None

    def create_issue(self, *, owner, repo, title, body, labels):
        raise NotImplementedError


def test_fake_client_satisfies_the_protocol() -> None:
    assert isinstance(FakeGitHubClient(), GitHubClient)


# --- branch naming: the idempotency key made concrete -----------------------


def test_branch_name_for_is_deterministic() -> None:
    assert branch_name_for("semgrep:r:x.php:1") == branch_name_for("semgrep:r:x.php:1")


def test_branch_name_for_differs_by_finding() -> None:
    assert branch_name_for("f1") != branch_name_for("f2")


def test_branch_name_for_rejects_empty_finding_id() -> None:
    with pytest.raises(GuardrailViolation):
        branch_name_for("")


def test_branch_name_for_avoids_collisions_after_slugification() -> None:
    """Two ids that punctuation-strip to the same slug must still not collide —
    the sha suffix is what guarantees that, not the human-readable prefix."""
    a = branch_name_for("semgrep:rule:a/b.php:1")
    b = branch_name_for("semgrep-rule-a-b-php-1")
    assert a != b


# --- create_draft_pr: guardrails ---------------------------------------------


def test_create_draft_pr_requires_finding_id() -> None:
    client = FakeGitHubClient()
    with pytest.raises(GuardrailViolation):
        create_draft_pr(
            InMemoryRecordStore(), client, finding_id="", owner="o", repo="r",
            title="t", body="b",
        )
    assert client.calls == []


def test_create_draft_pr_is_blocked_by_the_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRAMAAN_KILLSWITCH", "1")
    client = FakeGitHubClient()
    with pytest.raises(KillSwitchEngaged):
        create_draft_pr(
            InMemoryRecordStore(), client, finding_id="f1", owner="o", repo="r",
            title="t", body="b",
        )
    assert client.calls == []


# --- create_draft_pr: idempotency, the headline requirement -----------------


def test_create_draft_pr_creates_exactly_one_pr() -> None:
    store, client = InMemoryRecordStore(), FakeGitHubClient()
    ref = create_draft_pr(store, client, finding_id="f1", owner="o", repo="r", title="t", body="b")
    assert isinstance(ref, PullRequestRef)
    assert [c for c in client.calls if c[0] == "create_pull_request"] == [
        ("create_pull_request", {"head": branch_name_for("f1"), "base": "main"})
    ]


def test_create_draft_pr_called_twice_with_the_same_store_yields_one_pr_and_one_api_call() -> None:
    store, client = InMemoryRecordStore(), FakeGitHubClient()

    ref1 = create_draft_pr(store, client, finding_id="f1", owner="o", repo="r", title="t", body="b")
    ref2 = create_draft_pr(store, client, finding_id="f1", owner="o", repo="r", title="t", body="b")

    assert ref1 == ref2
    creates = [c for c in client.calls if c[0] == "create_pull_request"]
    assert len(creates) == 1
    # The second call hit the local record and never touched the client at all.
    assert len([c for c in client.calls if c[0] == "find_pull_request_by_head"]) == 1


def test_create_draft_pr_survives_a_crash_between_the_api_call_and_the_local_write(
    tmp_path,
) -> None:
    """The case that actually happens: the first call's PR exists on GitHub, but
    the local record of it was never written (process died in between). A
    second call, with a fresh store pointed at the same file but no record in
    it, must adopt the existing PR rather than create a second one.
    """
    client = FakeGitHubClient()

    store_before_crash = JsonFileRecordStore(tmp_path / "pr_records.json")
    ref1 = create_draft_pr(
        store_before_crash, client, finding_id="crash-1", owner="o", repo="r",
        title="t", body="b",
    )
    # Simulate the crash: the write above genuinely reached disk (this is a
    # real, durable JsonFileRecordStore — that part of the pipeline is not what
    # is broken), but the *next* process's ledger does not have this row. That
    # is the gap a crash between "API call succeeded" and "local write ran"
    # leaves, whatever its exact cause — a different volume, a lost write, a
    # store that was reset. Modelled here as a second, still-empty file.
    store_after_crash = JsonFileRecordStore(tmp_path / "pr_records_after_crash.json")
    assert store_after_crash.get("crash-1") is None

    ref2 = create_draft_pr(
        store_after_crash, client, finding_id="crash-1", owner="o", repo="r",
        title="t", body="b",
    )

    assert ref1 == ref2
    creates = [c for c in client.calls if c[0] == "create_pull_request"]
    assert len(creates) == 1, f"expected exactly one PR created, got {creates}"
    # The second call must have self-healed the local record too.
    assert store_after_crash.get("crash-1") == ref2.to_dict()


def test_create_draft_pr_recovers_when_the_create_call_itself_collides() -> None:
    """The narrower race: the pre-create lookup misses (eventual consistency)
    and `create_pull_request` collides with GitHub's own uniqueness constraint.
    Recovery, not failure."""
    client = FakeGitHubClient()
    # Seed a PR that already exists remotely for this finding's branch.
    head = branch_name_for("race-1")
    client._prs[(head, "main")] = PullRequestRef(number=999, url="https://example/pull/999", head=head, base="main")
    client.miss_find_once = True  # the first lookup will not see it

    ref = create_draft_pr(
        InMemoryRecordStore(), client, finding_id="race-1", owner="o", repo="r",
        title="t", body="b",
    )

    assert ref.number == 999
    creates = [c for c in client.calls if c[0] == "create_pull_request"]
    assert len(creates) == 1  # the attempt that collided


def test_create_draft_pr_raises_when_the_collision_cannot_be_resolved() -> None:
    """If GitHub says a PR exists but no lookup can find it, that is a real
    inconsistency to surface, not something to paper over."""
    with pytest.raises(GitHubApiError):
        create_draft_pr(
            InMemoryRecordStore(), AlwaysConflictingClient(), finding_id="f1",
            owner="o", repo="r", title="t", body="b",
        )


def test_two_different_findings_get_two_different_prs() -> None:
    store, client = InMemoryRecordStore(), FakeGitHubClient()
    ref1 = create_draft_pr(store, client, finding_id="f1", owner="o", repo="r", title="t", body="b")
    ref2 = create_draft_pr(store, client, finding_id="f2", owner="o", repo="r", title="t", body="b")
    assert ref1.number != ref2.number
    assert ref1.head != ref2.head


def test_pull_request_ref_round_trips_through_dict() -> None:
    ref = PullRequestRef(number=1, url="https://x/1", head="h", base="main", draft=True)
    assert PullRequestRef.from_dict(ref.to_dict()) == ref


# --- comment: idempotency ------------------------------------------------------


def test_comment_requires_finding_id() -> None:
    with pytest.raises(GuardrailViolation):
        comment(InMemoryRecordStore(), FakeGitHubClient(), finding_id="", owner="o", repo="r", number=1, body="b")


def test_comment_is_blocked_by_the_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRAMAAN_KILLSWITCH", "1")
    client = FakeGitHubClient()
    with pytest.raises(KillSwitchEngaged):
        comment(InMemoryRecordStore(), client, finding_id="f1", owner="o", repo="r", number=1, body="b")
    assert client.calls == []


def test_comment_posted_twice_identically_is_a_single_comment() -> None:
    store, client = InMemoryRecordStore(), FakeGitHubClient()
    ref1 = comment(store, client, finding_id="f1", owner="o", repo="r", number=7, body="status update")
    ref2 = comment(store, client, finding_id="f1", owner="o", repo="r", number=7, body="status update")
    assert ref1 == ref2
    assert len([c for c in client.calls if c[0] == "create_issue_comment"]) == 1


def test_comment_with_different_content_posts_again() -> None:
    store, client = InMemoryRecordStore(), FakeGitHubClient()
    ref1 = comment(store, client, finding_id="f1", owner="o", repo="r", number=7, body="first update")
    ref2 = comment(store, client, finding_id="f1", owner="o", repo="r", number=7, body="second update")
    assert ref1.id != ref2.id
    assert len([c for c in client.calls if c[0] == "create_issue_comment"]) == 2


def test_comment_survives_a_crash_between_the_api_call_and_the_local_write() -> None:
    client = FakeGitHubClient()
    store_a = InMemoryRecordStore()
    ref1 = comment(store_a, client, finding_id="f1", owner="o", repo="r", number=7, body="status")

    store_b = InMemoryRecordStore()  # the local write never happened
    ref2 = comment(store_b, client, finding_id="f1", owner="o", repo="r", number=7, body="status")

    assert ref1 == ref2
    assert len([c for c in client.calls if c[0] == "create_issue_comment"]) == 1
    # Discovered via the remote marker scan.
    assert any(c[0] == "list_issue_comments" for c in client.calls)


def test_comment_ref_round_trips_through_dict() -> None:
    ref = CommentRef(id=1, url="https://x/1", target_number=7, body="hi")
    assert CommentRef.from_dict(ref.to_dict()) == ref


# --- the GitHubClient Protocol is exactly the safe verb set ------------------


def test_github_client_protocol_exposes_exactly_the_safe_verbs() -> None:
    members = {
        name for name, value in vars(GitHubClient).items()
        if not name.startswith("_") and callable(value)
    }
    assert members == {
        "find_pull_request_by_head",
        "create_pull_request",
        "list_issue_comments",
        "create_issue_comment",
        "find_issue_by_marker",
        "create_issue",
    }


def test_no_dangerous_verbs_anywhere_on_the_protocol() -> None:
    members = {name for name in vars(GitHubClient) if not name.startswith("_")}
    dangerous = ("delete", "merge", "close", "force")
    offenders = [m for m in members for d in dangerous if d in m.lower()]
    assert offenders == []


# --- RestGitHubClient: fails closed on missing config ------------------------


def test_rest_github_client_refuses_an_empty_token() -> None:
    with pytest.raises(ConfigurationError):
        RestGitHubClient("")


def test_rest_github_client_refuses_a_blank_token() -> None:
    with pytest.raises(ConfigurationError):
        RestGitHubClient("   ")


def test_rest_github_client_from_env_fails_closed_when_unset() -> None:
    with pytest.raises(ConfigurationError, match=GITHUB_TOKEN_ENV_VAR):
        RestGitHubClient.from_env(env={})


def test_rest_github_client_from_env_succeeds_when_set() -> None:
    client = RestGitHubClient.from_env(env={GITHUB_TOKEN_ENV_VAR: "ghp_realtoken"})
    assert isinstance(client, RestGitHubClient)


# --- MCP wiring ----------------------------------------------------------------


def test_build_github_tools_exposes_exactly_two_tools() -> None:
    tools = build_github_tools(InMemoryRecordStore(), FakeGitHubClient(), owner="o", repo="r")
    assert {t.name for t in tools} == {"create_draft_pr", "comment"}


def test_tool_input_schemas_reject_additional_properties() -> None:
    tools = build_github_tools(InMemoryRecordStore(), FakeGitHubClient(), owner="o", repo="r")
    for tool_def in tools:
        assert tool_def.input_schema["additionalProperties"] is False


def test_create_github_server_returns_a_valid_sdk_config() -> None:
    config = create_github_server(InMemoryRecordStore(), FakeGitHubClient(), owner="o", repo="r")
    assert config["type"] == "sdk"
    assert config["name"] == "github"
    assert config["instance"] is not None


def test_create_draft_pr_tool_handler_is_idempotent_end_to_end() -> None:
    store, client = InMemoryRecordStore(), FakeGitHubClient()
    tools = build_github_tools(store, client, owner="o", repo="r")
    handler = next(t.handler for t in tools if t.name == "create_draft_pr")

    async def run():
        out1 = await handler({"finding_id": "f1", "title": "t", "body": "b"})
        out2 = await handler({"finding_id": "f1", "title": "t", "body": "b"})
        return out1, out2

    out1, out2 = asyncio.run(run())
    assert out1 == out2
    assert out1.get("is_error") is not True
    assert len([c for c in client.calls if c[0] == "create_pull_request"]) == 1


def test_tool_handler_surfaces_a_guardrail_violation_as_is_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRAMAAN_KILLSWITCH", "1")
    tools = build_github_tools(InMemoryRecordStore(), FakeGitHubClient(), owner="o", repo="r")
    handler = next(t.handler for t in tools if t.name == "create_draft_pr")

    out = asyncio.run(handler({"finding_id": "f1", "title": "t", "body": "b"}))

    assert out["is_error"] is True
    assert "kill switch" in out["content"][0]["text"]
