"""The kill switch: flag parsing, the direct raise, and the `PreToolUse` hook.

The hook tests call the hook coroutine directly with a synthetic `input_data`
dict, the same pattern `tests/test_hooks.py` uses for the triage lane's
`PostToolUse` hooks — there is no live CLI in this test suite, so the contract
under test is "the hook returns the documented dict shape", not "the CLI
actually stops".
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pramaan.agent.hooks import AuditLogger, iter_audit_records
from pramaan.mcp.errors import KillSwitchEngaged
from pramaan.mcp.killswitch import (
    KILLSWITCH_ENV_VAR,
    is_engaged,
    make_killswitch_hook,
    raise_if_engaged,
)

FROZEN = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)


def _clock() -> datetime:
    return FROZEN


def _pre_tool_use(tool_name: str = "mcp__github__create_draft_pr") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "sess-1",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/repo",
        "tool_name": tool_name,
        "tool_input": {"finding_id": "f1"},
        "tool_use_id": "toolu_1",
    }


# --- flag parsing ------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "0", "false", "False", "FALSE", "no", "No", "off", "OFF"])
def test_explicit_off_values_are_not_engaged(value: str) -> None:
    assert is_engaged(env={KILLSWITCH_ENV_VAR: value}) is False


def test_unset_is_not_engaged() -> None:
    assert is_engaged(env={}) is False


@pytest.mark.parametrize(
    "value", ["1", "true", "True", "yes", "on", "ON", "STOP", " 1 ", "please-stop", "banana"]
)
def test_anything_else_is_engaged(value: str) -> None:
    """Deliberately not an allowlist of "true-ish" strings: an unrecognised
    value fails towards stopping, which is the correct direction for a kill
    switch specifically (see the module docstring)."""
    assert is_engaged(env={KILLSWITCH_ENV_VAR: value}) is True


def test_is_engaged_reads_os_environ_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KILLSWITCH_ENV_VAR, "1")
    assert is_engaged() is True
    monkeypatch.setenv(KILLSWITCH_ENV_VAR, "0")
    assert is_engaged() is False


def test_custom_env_var_name_is_honoured() -> None:
    assert is_engaged(env_var="OTHER_FLAG", env={"OTHER_FLAG": "1"}) is True
    assert is_engaged(env_var="OTHER_FLAG", env={KILLSWITCH_ENV_VAR: "1"}) is False


# --- the direct raise ---------------------------------------------------------


def test_raise_if_engaged_raises_when_set() -> None:
    with pytest.raises(KillSwitchEngaged, match=KILLSWITCH_ENV_VAR):
        raise_if_engaged(env={KILLSWITCH_ENV_VAR: "1"})


def test_raise_if_engaged_is_silent_when_unset() -> None:
    raise_if_engaged(env={})  # must not raise


# --- the PreToolUse hook -------------------------------------------------------


async def test_hook_is_a_no_op_when_not_engaged() -> None:
    hook = make_killswitch_hook(env={KILLSWITCH_ENV_VAR: "0"})
    assert await hook(_pre_tool_use(), "toolu_1", None) == {}


async def test_hook_denies_and_stops_the_run_when_engaged() -> None:
    hook = make_killswitch_hook(env={KILLSWITCH_ENV_VAR: "1"})
    out = await hook(_pre_tool_use(), "toolu_1", None)

    assert out["continue_"] is False
    assert KILLSWITCH_ENV_VAR in out["stopReason"]
    specific = out["hookSpecificOutput"]
    assert specific["hookEventName"] == "PreToolUse"
    assert specific["permissionDecision"] == "deny"
    assert KILLSWITCH_ENV_VAR in specific["permissionDecisionReason"]


async def test_hook_names_the_tool_it_blocked() -> None:
    hook = make_killswitch_hook(env={KILLSWITCH_ENV_VAR: "1"})
    out = await hook(_pre_tool_use(tool_name="mcp__dojo__update_finding"), "toolu_1", None)
    assert "mcp__dojo__update_finding" in out["stopReason"]


async def test_hook_works_with_no_audit_logger_configured() -> None:
    hook = make_killswitch_hook(env={KILLSWITCH_ENV_VAR: "1"}, audit_logger=None)
    out = await hook(_pre_tool_use(), "toolu_1", None)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


async def test_hook_writes_an_audit_record_before_denying_and_the_chain_stays_intact(
    tmp_path,
) -> None:
    """"The audit log must survive the abort": the record is written, and the
    hash chain verifies, in the same call that produces the deny decision."""
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, run_id="r1", clock=_clock)
    hook = make_killswitch_hook(env={KILLSWITCH_ENV_VAR: "1"}, audit_logger=logger)

    await hook(_pre_tool_use(), "toolu_1", None)

    records = list(iter_audit_records(log))
    assert len(records) == 1
    assert records[0]["decision"] == "killswitch_abort"
    assert records[0]["tool_name"] == "mcp__github__create_draft_pr"
    assert records[0]["run_id"] == "r1"
    assert AuditLogger.verify(log) is True


async def test_hook_does_not_log_when_not_engaged(tmp_path) -> None:
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, clock=_clock)
    hook = make_killswitch_hook(env={KILLSWITCH_ENV_VAR: "0"}, audit_logger=logger)

    await hook(_pre_tool_use(), "toolu_1", None)

    assert list(iter_audit_records(log)) == []


async def test_flipping_the_flag_mid_run_blocks_the_very_next_call(tmp_path) -> None:
    """A single mutable env mapping simulates the flag flipping between two
    tool calls in the same run: the first call is allowed through, and the
    very next one — with nothing else changed — is denied."""
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, clock=_clock)
    env = {KILLSWITCH_ENV_VAR: "0"}
    hook = make_killswitch_hook(env=env, audit_logger=logger)

    first = await hook(_pre_tool_use(tool_name="mcp__github__create_draft_pr"), "toolu_1", None)
    assert first == {}

    env[KILLSWITCH_ENV_VAR] = "1"  # the operator flips it mid-run

    second = await hook(_pre_tool_use(tool_name="mcp__github__comment"), "toolu_2", None)
    assert second["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert len(list(iter_audit_records(log))) == 1
