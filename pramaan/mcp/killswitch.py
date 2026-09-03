"""Environment-flag kill switch, checked at two layers.

1. `make_killswitch_hook` builds a `PreToolUse` hook: wired into an agent's
   `ClaudeAgentOptions.hooks`, it denies the *next* tool call and stops the run
   the moment the flag is set, without waiting for the run to reach a natural
   end.
2. `raise_if_engaged` is called directly by every actuator function in
   `github_tools.py`, `dojo_tools.py` and `tickets/adapter.py`. This is
   deliberate duplication: it means a direct Python call — made outside any
   agent loop, e.g. from `shadow.py`'s live-mode dispatch, or from a script —
   is stopped even if no hook was ever wired in. The hook can only stop what the
   CLI routes through it; the direct check cannot be bypassed by skipping the
   agent harness.

Both read the same flag through `is_engaged`, so there is exactly one place that
decides what "engaged" means.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from pramaan.agent.hooks import AuditLogger
from pramaan.mcp.errors import KillSwitchEngaged

__all__ = ["KILLSWITCH_ENV_VAR", "is_engaged", "raise_if_engaged", "make_killswitch_hook"]

KILLSWITCH_ENV_VAR = "PRAMAAN_KILLSWITCH"

# Values that explicitly mean "off". Everything else — "1", "true", "STOP", a
# typo, an operator writing whatever came to mind at 3am — means "on". A kill
# switch is the one flag in this project where an unrecognised value should
# fail towards stopping rather than towards silently continuing; an allowlist
# of "true-ish" strings would fail the other, wrong, way.
_EXPLICIT_OFF = frozenset({"", "0", "false", "no", "off"})


def is_engaged(*, env_var: str = KILLSWITCH_ENV_VAR, env: Mapping[str, str] | None = None) -> bool:
    """True unless the flag is unset or holds an explicit "off" value.

    `env=` is a test seam; production callers omit it and this reads the real
    `os.environ`, which is the one piece of live, mutable-world state this
    otherwise-deterministic lane is allowed to consult on every call.
    """
    source = os.environ if env is None else env
    value = source.get(env_var, "")
    return value.strip().lower() not in _EXPLICIT_OFF


def raise_if_engaged(*, env_var: str = KILLSWITCH_ENV_VAR, env: Mapping[str, str] | None = None) -> None:
    if is_engaged(env_var=env_var, env=env):
        raise KillSwitchEngaged(
            f"kill switch engaged (${env_var} is set); no actuator call may proceed"
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_killswitch_hook(
    *,
    env_var: str = KILLSWITCH_ENV_VAR,
    audit_logger: AuditLogger | None = None,
    env: Mapping[str, str] | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> Callable[[dict[str, Any], str | None, Any], Awaitable[dict[str, Any]]]:
    """Build the `PreToolUse` hook.

    Checked on every tool call, so flipping the flag mid-run takes effect at the
    very next one. The audit record is written *before* the deny decision is
    returned, and writing it is the only side effect on this path other than
    the decision itself — so the log documenting why the run stopped survives
    the abort by construction, not by cleanup logic that could itself be skipped.

    Sets `continue_: False` in addition to `permissionDecision: "deny"`: denying
    only the one call would leave the model free to try a different tool next
    turn, and "abort" means the run stops, not that this particular call fails.
    """

    async def killswitch_check(
        input_data: dict[str, Any], tool_use_id: str | None, context: Any
    ) -> dict[str, Any]:
        if not is_engaged(env_var=env_var, env=env):
            return {}

        tool_name = input_data.get("tool_name", "<unknown tool>")
        reason = f"pramaan kill switch: ${env_var} is set; aborting before {tool_name!r} runs"

        if audit_logger is not None:
            audit_logger.append(
                {
                    "event": "PreToolUse",
                    "decision": "killswitch_abort",
                    "tool_name": input_data.get("tool_name"),
                    "tool_use_id": tool_use_id or input_data.get("tool_use_id"),
                    "session_id": input_data.get("session_id"),
                    "reason": reason,
                }
            )

        return {
            "continue_": False,
            "stopReason": reason,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            },
        }

    return killswitch_check
