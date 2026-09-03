"""`dojo_tools.py`: `get_finding`, `update_finding`, and the guardrail that there
is no `close_true_positive` verb, ever — enforced twice (the verb does not
exist; `update_finding` refuses any transition that would amount to one, even
through the `extra_fields` back door).
"""

from __future__ import annotations

import asyncio

import pytest

from pramaan.mcp.dojo_tools import (
    CLOSING_FIELDS,
    DOJO_BASE_URL_ENV_VAR,
    DOJO_TOKEN_ENV_VAR,
    DojoApiError,
    DojoClient,
    RestDojoClient,
    build_dojo_tools,
    create_dojo_server,
    get_finding,
    update_finding,
)
from pramaan.mcp.errors import ConfigurationError, GuardrailViolation, KillSwitchEngaged


class FakeDojoClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self._findings: dict[str, dict] = {
            "f1": {"id": 1, "unique_id_from_tool": "f1", "active": True},
        }

    def get_finding(self, finding_id: str) -> dict | None:
        self.calls.append(("get_finding", finding_id))
        return self._findings.get(finding_id)

    def update_finding(self, finding_id: str, fields) -> dict:
        self.calls.append(("update_finding", finding_id, dict(fields)))
        record = self._findings.setdefault(finding_id, {})
        record.update(fields)
        return dict(record)


def test_fake_client_satisfies_the_protocol() -> None:
    assert isinstance(FakeDojoClient(), DojoClient)


# --- get_finding ---------------------------------------------------------------


def test_get_finding_requires_finding_id() -> None:
    with pytest.raises(GuardrailViolation):
        get_finding(FakeDojoClient(), finding_id="")


def test_get_finding_returns_the_record() -> None:
    result = get_finding(FakeDojoClient(), finding_id="f1")
    assert result == {"id": 1, "unique_id_from_tool": "f1", "active": True}


def test_get_finding_returns_none_when_absent() -> None:
    assert get_finding(FakeDojoClient(), finding_id="does-not-exist") is None


# --- update_finding: the no-close-true-positive guardrail --------------------


def test_update_finding_refuses_to_close_a_true_positive() -> None:
    client = FakeDojoClient()
    with pytest.raises(GuardrailViolation, match="close_true_positive"):
        update_finding(client, finding_id="f1", verdict="true_positive", rationale="r", close=True)
    assert client.calls == []


def test_update_finding_refuses_to_close_on_needs_human() -> None:
    client = FakeDojoClient()
    with pytest.raises(GuardrailViolation):
        update_finding(client, finding_id="f1", verdict="needs_human", rationale="r", close=True)
    assert client.calls == []


@pytest.mark.parametrize("field_name", sorted(CLOSING_FIELDS))
def test_update_finding_refuses_every_closing_field_smuggled_via_extra_fields(field_name: str) -> None:
    """Not just `active`: every field in the closing denylist is checked, on a
    true positive, so a caller cannot achieve the same effect under a
    differently named field."""
    client = FakeDojoClient()
    with pytest.raises(GuardrailViolation, match="extra_fields"):
        update_finding(
            client, finding_id="f1", verdict="true_positive", rationale="r",
            extra_fields={field_name: False},
        )
    assert client.calls == []


def test_update_finding_refuses_smuggled_closing_fields_even_on_a_false_positive() -> None:
    """The denylist is unconditional, not just a true-positive guard: the only
    sanctioned closing path is `close=True`, never a raw field."""
    client = FakeDojoClient()
    with pytest.raises(GuardrailViolation):
        update_finding(
            client, finding_id="f1", verdict="false_positive", rationale="r",
            extra_fields={"active": False},
        )
    assert client.calls == []


def test_update_finding_allows_annotate_only_on_a_true_positive() -> None:
    client = FakeDojoClient()
    result = update_finding(client, finding_id="f1", verdict="true_positive", rationale="confirmed sqli")
    assert result["pramaan_verdict"] == "true_positive"
    assert "active" not in dict(client.calls[0][2])


def test_update_finding_allows_closing_a_false_positive() -> None:
    client = FakeDojoClient()
    update_finding(client, finding_id="f1", verdict="false_positive", rationale="not reachable", close=True)
    fields = client.calls[0][2]
    assert fields["active"] is False
    assert fields["false_p"] is True
    assert fields["pramaan_verdict"] == "false_positive"


def test_update_finding_requires_finding_id() -> None:
    with pytest.raises(GuardrailViolation):
        update_finding(FakeDojoClient(), finding_id="", verdict="false_positive", rationale="r")


def test_update_finding_requires_nonempty_rationale() -> None:
    with pytest.raises(GuardrailViolation):
        update_finding(FakeDojoClient(), finding_id="f1", verdict="false_positive", rationale="   ")


def test_update_finding_is_blocked_by_the_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRAMAAN_KILLSWITCH", "1")
    client = FakeDojoClient()
    with pytest.raises(KillSwitchEngaged):
        update_finding(client, finding_id="f1", verdict="false_positive", rationale="r")
    assert client.calls == []


def test_update_finding_is_idempotent_by_finding_id() -> None:
    """A state-setting PATCH, not a creation: calling it twice with the same
    verdict/rationale re-applies the same fields rather than creating a second
    resource, so no create-vs-adopt machinery is needed here the way it is for
    `create_draft_pr`."""
    client = FakeDojoClient()
    r1 = update_finding(client, finding_id="f1", verdict="false_positive", rationale="r", close=True)
    r2 = update_finding(client, finding_id="f1", verdict="false_positive", rationale="r", close=True)
    assert r1 == r2
    assert len(client.calls) == 2  # both calls run; both converge on the same state


# --- the DojoClient Protocol is exactly get + update, no close verb ----------


def test_dojo_client_protocol_exposes_exactly_two_verbs() -> None:
    members = {
        name for name, value in vars(DojoClient).items()
        if not name.startswith("_") and callable(value)
    }
    assert members == {"get_finding", "update_finding"}


def test_no_close_true_positive_or_delete_verb_anywhere_on_the_protocol() -> None:
    members = {name for name in vars(DojoClient) if not name.startswith("_")}
    assert "close_true_positive" not in members
    assert not any("delete" in m.lower() for m in members)


# --- RestDojoClient: fails closed on missing config --------------------------


def test_rest_dojo_client_refuses_empty_token() -> None:
    with pytest.raises(ConfigurationError):
        RestDojoClient("https://dojo.example.com", "")


def test_rest_dojo_client_refuses_empty_base_url() -> None:
    with pytest.raises(ConfigurationError):
        RestDojoClient("", "tok")


@pytest.mark.parametrize(
    "env",
    [
        {},
        {DOJO_TOKEN_ENV_VAR: "tok"},
        {DOJO_BASE_URL_ENV_VAR: "https://dojo.example.com"},
    ],
)
def test_rest_dojo_client_from_env_fails_closed_when_incomplete(env: dict) -> None:
    with pytest.raises(ConfigurationError):
        RestDojoClient.from_env(env=env)


def test_rest_dojo_client_from_env_succeeds_when_complete() -> None:
    client = RestDojoClient.from_env(
        env={DOJO_TOKEN_ENV_VAR: "tok", DOJO_BASE_URL_ENV_VAR: "https://dojo.example.com"}
    )
    assert isinstance(client, RestDojoClient)


# --- MCP wiring ----------------------------------------------------------------


def test_build_dojo_tools_exposes_exactly_two_tools() -> None:
    tools = build_dojo_tools(FakeDojoClient())
    assert {t.name for t in tools} == {"get_finding", "update_finding"}


def test_update_finding_tool_schema_has_no_extra_fields_backdoor() -> None:
    """The tool a model can call carries no `extra_fields` parameter at all —
    narrower than the Python function, so there is nothing for a model to be
    talked into passing that the denylist would then have to reject."""
    tools = build_dojo_tools(FakeDojoClient())
    schema = next(t.input_schema for t in tools if t.name == "update_finding")
    assert schema["additionalProperties"] is False
    assert "extra_fields" not in schema["properties"]
    assert set(schema["properties"]) == {"finding_id", "verdict", "rationale", "close"}


def test_create_dojo_server_returns_a_valid_sdk_config() -> None:
    config = create_dojo_server(FakeDojoClient())
    assert config["type"] == "sdk"
    assert config["name"] == "dojo"
    assert config["instance"] is not None


def test_get_finding_tool_returns_is_error_when_not_found() -> None:
    tools = build_dojo_tools(FakeDojoClient())
    handler = next(t.handler for t in tools if t.name == "get_finding")
    out = asyncio.run(handler({"finding_id": "nope"}))
    assert out["is_error"] is True


def test_update_finding_tool_returns_is_error_on_a_guardrail_violation() -> None:
    tools = build_dojo_tools(FakeDojoClient())
    handler = next(t.handler for t in tools if t.name == "update_finding")
    out = asyncio.run(
        handler({"finding_id": "f1", "verdict": "true_positive", "rationale": "r", "close": True})
    )
    assert out["is_error"] is True
    assert "close_true_positive" in out["content"][0]["text"]


def test_update_finding_tool_handler_succeeds_on_a_legitimate_call() -> None:
    client = FakeDojoClient()
    tools = build_dojo_tools(client)
    handler = next(t.handler for t in tools if t.name == "update_finding")
    out = asyncio.run(
        handler({"finding_id": "f1", "verdict": "false_positive", "rationale": "not reachable", "close": True})
    )
    assert out.get("is_error") is not True
    assert client.calls  # the client was actually invoked
