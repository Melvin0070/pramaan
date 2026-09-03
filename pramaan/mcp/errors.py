"""Shared failure signal for the actuator lane.

One base class so an MCP tool handler, the shadow dispatcher, or a caller three
layers up can `except ActuatorError` and catch every guardrail failure this lane
raises without enumerating them — and without risking a bare `except Exception`
that would also swallow a real bug. Ground rule 7 (fail closed) means every one
of these is raised, never absorbed into a silent no-op that reports success.
"""

from __future__ import annotations

__all__ = ["ActuatorError", "ConfigurationError", "GuardrailViolation", "KillSwitchEngaged"]


class ActuatorError(Exception):
    """Base class for every failure this lane raises on purpose."""


class ConfigurationError(ActuatorError):
    """Missing or invalid configuration — e.g. no token. Never a silent no-op:
    a client built with no credentials must refuse to exist rather than construct
    successfully and no-op on its first real call while reporting success."""


class GuardrailViolation(ActuatorError):
    """A caller asked for a state transition this lane will never perform —
    closing a true-positive finding, acting with no `finding_id` to key on, or
    opening a PR without a passing proof bundle. The check lives in code, not in
    a docstring, so it fires the same way whether the caller is the model calling
    an MCP tool or trusted Python calling the underlying function directly."""


class KillSwitchEngaged(ActuatorError):
    """The environment kill switch is set. Raised by every actuator function in
    addition to the `PreToolUse` hook in `killswitch.py`, so a direct Python call
    is stopped even outside an agent run or if the hook is not wired in."""
