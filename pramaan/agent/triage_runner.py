"""The triage runner: one finding in, exactly one `Attempt` out.

Two rules shape everything here.

**Every call produces an Attempt.** A crash, a refusal, a budget abort and a
malformed object are all *recorded outcomes*, not exceptions to swallow or
retries to paper over. `schema_invalid` counts as a non-match in pass^k (D10), so
retrying one until it parses would inflate the consistency number this project
exists to make trustworthy. There is no retry in this module. There is no code
path that repairs model output to make it validate — in particular, D8's rejection
of `severity` / `ssvc_decision` / `recommended_action` by `additionalProperties:
false` is the schema working, and stripping those fields to force a pass would
delete the signal.

**The SDK sits behind a seam.** `query_fn` defaults to `claude_agent_sdk.query`
and is injectable, so all five statuses are unit-testable against fakes built
from the real SDK message dataclasses without spending a cent.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Mapping, Protocol, Sequence

from claude_agent_sdk.types import (
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    TextBlock,
)
from jsonschema import Draft202012Validator

from pramaan.agent.context import (
    DEFAULT_CONTEXT_CONFIG,
    CodeContext,
    ContextConfig,
)
from pramaan.agent.prompts import (
    TRIAGE_SYSTEM_PROMPT,
    build_user_turn,
    new_nonce,
    prompt_hash,
)
from pramaan.schemas import VERDICT_SCHEMA, Attempt, AttemptStatus, Finding

# --- the guardrails table, as constants so tests and the report quote one source

TRIAGE_ALLOWED_TOOLS: tuple[str, ...] = ("Read", "Grep", "Glob")
TRIAGE_DISALLOWED_TOOLS: tuple[str, ...] = (
    "Bash",
    "Write",
    "Edit",
    "WebFetch",
    "WebSearch",
)
TRIAGE_PERMISSION_MODE = "dontAsk"
TRIAGE_MAX_TURNS = 25
TRIAGE_MAX_BUDGET_USD = 0.50
TRIAGE_EFFORT = "medium"
DEFAULT_MODEL = "claude-sonnet-5"

_VALIDATOR = Draft202012Validator(VERDICT_SCHEMA)

# The API's own refusal signal, plus a text fallback for the case where the model
# declines in prose and emits no object at all.
_REFUSAL_STOP_REASONS = frozenset({"refusal", "stop_sequence_refusal"})
_REFUSAL_TEXT = re.compile(
    r"(?i)\b(?:i (?:can(?:'|no)?t|won'?t|am unable to|must decline)|"
    r"i'?m (?:not able|unable) to)\b[^.]{0,80}\b"
    r"(?:help|assist|comply|complete|continue|analy[sz]e|do that|provide)\b"
)
_BUDGET_MARKERS = ("max_budget", "budget_exceeded", "budget exceeded", "billing_error")
_TURN_MARKERS = ("max_turns", "max turns", "max_tokens")


class QueryFn(Protocol):
    """The seam. `claude_agent_sdk.query` satisfies this."""

    def __call__(
        self, *, prompt: str, options: ClaudeAgentOptions
    ) -> AsyncIterator[Any]: ...


def build_options(
    *,
    cwd: str | Path,
    model: str = DEFAULT_MODEL,
    effort: str = TRIAGE_EFFORT,
    hooks: Mapping[str, list[HookMatcher]] | None = None,
    mcp_servers: Mapping[str, Any] | None = None,
    extra_allowed_tools: Sequence[str] = (),
    skills: list[str] | None = None,
    max_turns: int = TRIAGE_MAX_TURNS,
    max_budget_usd: float = TRIAGE_MAX_BUDGET_USD,
) -> ClaudeAgentOptions:
    """The exact triage configuration.

    `setting_sources=[]` is the load-bearing field. The scanned repositories ship
    their own `CLAUDE.md`, `AGENTS.md` and `.claude/` — `razorpay-woocommerce`
    genuinely does — and every one of those is a file an attacker can add to via
    a pull request. Loading them would hand repository authors a direct channel
    into the triage agent's instructions. Empty list, not `None`: `None` means
    "SDK default", and the default is not empty.
    """
    overlap = set(extra_allowed_tools) & set(TRIAGE_DISALLOWED_TOOLS)
    if overlap:
        raise ValueError(
            f"refusing to allow tools that the triage guardrails deny: {sorted(overlap)}"
        )
    return ClaudeAgentOptions(
        model=model,
        effort=effort,  # type: ignore[arg-type]
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        allowed_tools=[*TRIAGE_ALLOWED_TOOLS, *extra_allowed_tools],
        disallowed_tools=list(TRIAGE_DISALLOWED_TOOLS),
        permission_mode=TRIAGE_PERMISSION_MODE,  # type: ignore[arg-type]
        setting_sources=[],
        skills=skills,
        mcp_servers=dict(mcp_servers or {}),
        hooks=dict(hooks or {}),  # type: ignore[arg-type]
        output_format={"type": "json_schema", "schema": VERDICT_SCHEMA},
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        cwd=str(cwd),
    )


# --- transcript collection -------------------------------------------------


@dataclass(slots=True)
class RunTrace:
    """What one SDK stream produced, normalised for classification."""

    text: str = ""
    result: ResultMessage | None = None
    api_models: tuple[str, ...] = ()
    assistant_error: str | None = None
    stop_reason: str | None = None
    exception: BaseException | None = None
    duration_s: float = 0.0


def _text_of(message: AssistantMessage) -> str:
    return "".join(
        b.text for b in message.content if isinstance(b, TextBlock)
    )


async def _collect(
    query_fn: QueryFn, prompt: str, options: ClaudeAgentOptions
) -> RunTrace:
    """Drain the stream. Never raises: a transport failure is an outcome to
    classify, and an exception escaping here would mean a finding with no row."""
    trace = RunTrace()
    started = time.monotonic()
    models: list[str] = []
    chunks: list[str] = []
    try:
        stream = query_fn(prompt=prompt, options=options)
        if inspect.isawaitable(stream):
            stream = await stream
        async for message in stream:
            if isinstance(message, AssistantMessage):
                chunks.append(_text_of(message))
                if message.model and message.model not in models:
                    models.append(message.model)
                if message.error:
                    trace.assistant_error = str(message.error)
                if message.stop_reason:
                    trace.stop_reason = message.stop_reason
            elif isinstance(message, ResultMessage):
                trace.result = message
    except BaseException as exc:  # noqa: BLE001 - deliberately total
        trace.exception = exc
        # A terminal ResultError carries the same payload the result frame did;
        # keep it so budget/turn classification still works after the raise.
        data = getattr(exc, "data", None)
        if trace.result is None and isinstance(data, dict):
            trace.result = _result_from_error_data(data)
    trace.text = "".join(chunks)
    trace.api_models = tuple(models)
    trace.duration_s = time.monotonic() - started
    return trace


def _result_from_error_data(data: Mapping[str, Any]) -> ResultMessage:
    return ResultMessage(
        subtype=str(data.get("subtype") or "error_during_execution"),
        duration_ms=int(data.get("duration_ms") or 0),
        duration_api_ms=int(data.get("duration_api_ms") or 0),
        is_error=True,
        num_turns=int(data.get("num_turns") or 0),
        session_id=str(data.get("session_id") or ""),
        stop_reason=data.get("stop_reason"),
        total_cost_usd=data.get("total_cost_usd"),
        result=data.get("result"),
        errors=data.get("errors"),
        api_error_status=data.get("api_error_status"),
        terminal_reason=data.get("terminal_reason"),
    )


# --- payload extraction ----------------------------------------------------


def first_json_object(text: str) -> tuple[dict[str, Any] | None, bool]:
    """Return `(object, looked_truncated)` for the first balanced `{...}`.

    `looked_truncated` distinguishes "the model was cut off mid-object" from "the
    model emitted something that is not a verdict" — the difference between D10's
    `truncated` and `schema_invalid`, which are counted separately.
    """
    start = text.find("{")
    if start == -1:
        return None, False
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1]), False
                except json.JSONDecodeError:
                    return None, False
    return None, True


def extract_payload(trace: RunTrace) -> tuple[dict[str, Any] | None, bool]:
    """Prefer the SDK's structured output; fall back to parsing the text."""
    result = trace.result
    if result is not None and isinstance(result.structured_output, dict):
        return result.structured_output, False
    candidates = [t for t in (getattr(result, "result", None), trace.text) if t]
    truncated = False
    for text in candidates:
        obj, looked_truncated = first_json_object(text)
        if obj is not None:
            return obj, False
        truncated = truncated or looked_truncated
    return None, truncated


# --- classification --------------------------------------------------------


def _haystack(trace: RunTrace) -> str:
    """Control-plane fields only.

    `ResultMessage.result` carries the model's own final text on a successful
    run, so including it unconditionally would classify a verdict whose rationale
    happens to discuss `max_budget` as a budget abort. It is only consulted when
    the CLI already flagged the run as an error, which is the case where it holds
    "API Error: ..." prose rather than model output.
    """
    r = trace.result
    parts = [
        trace.assistant_error or "",
        str(trace.exception) if trace.exception else "",
        type(trace.exception).__name__ if trace.exception else "",
    ]
    if r is not None:
        parts += [r.subtype or "", r.terminal_reason or "", r.stop_reason or ""]
        parts += list(r.errors or [])
        if r.is_error and isinstance(r.result, str):
            parts.append(r.result)
    return " ".join(parts).lower()


@dataclass(frozen=True, slots=True)
class Classification:
    status: AttemptStatus
    verdict: dict[str, Any] | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def classify(
    trace: RunTrace, *, expected_finding_id: str, max_turns: int = TRIAGE_MAX_TURNS
) -> Classification:
    """Map one run onto exactly one D10 status.

    Precedence is fixed and fail-closed: a run that was cut short is never
    reported as `valid` even if a complete-looking object turned up in the
    transcript, because a truncated run's object was produced under conditions we
    cannot vouch for.
    """
    haystack = _haystack(trace)
    result = trace.result

    if any(m in haystack for m in _BUDGET_MARKERS):
        return Classification(
            "budget_abort", error=_reason(trace) or "budget exhausted"
        )

    if any(m in haystack for m in _TURN_MARKERS):
        return Classification("truncated", error=_reason(trace) or "turn limit reached")

    if (trace.stop_reason or "") in _REFUSAL_STOP_REASONS or (
        result is not None and (result.stop_reason or "") in _REFUSAL_STOP_REASONS
    ):
        return Classification("refused", error=_reason(trace) or "model refused")

    payload, looked_truncated = extract_payload(trace)

    if payload is None:
        if _REFUSAL_TEXT.search(trace.text or ""):
            return Classification("refused", error="model declined in prose")
        if looked_truncated:
            return Classification("truncated", error="output cut off mid-object")
        if trace.exception is not None:
            return Classification(
                "truncated",
                error=f"{type(trace.exception).__name__}: {trace.exception}",
                metadata={"transport_error": True},
            )
        if trace.assistant_error:
            return Classification("truncated", error=trace.assistant_error)
        if result is not None and result.num_turns >= max_turns > 0:
            return Classification("truncated", error="turn limit reached, no object")
        return Classification("schema_invalid", error="no JSON object in output")

    errors = sorted(_VALIDATOR.iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        # D8: `severity` / `ssvc_decision` / `recommended_action` land here via
        # additionalProperties. That rejection is the schema doing its job.
        return Classification(
            "schema_invalid",
            verdict=payload,
            error="; ".join(f"{list(e.path)}: {e.message}" for e in errors[:5]),
            metadata={"schema_error_count": len(errors)},
        )

    if payload.get("finding_id") != expected_finding_id:
        # Not a schema failure in the jsonschema sense, but the object does not
        # describe the finding that was asked about. Recorded as schema_invalid
        # with a discriminator so the published schema-failure rate can separate
        # the two causes. Rewriting the id to make it match would be forgery.
        return Classification(
            "schema_invalid",
            verdict=payload,
            error=(
                f"finding_id mismatch: model returned "
                f"{payload.get('finding_id')!r}, expected {expected_finding_id!r}"
            ),
            metadata={"finding_id_mismatch": True},
        )

    return Classification("valid", verdict=payload)


def _reason(trace: RunTrace) -> str | None:
    r = trace.result
    if r is not None:
        for candidate in (r.terminal_reason, r.subtype, (r.errors or [None])[0]):
            if candidate:
                return str(candidate)
    if trace.assistant_error:
        return trace.assistant_error
    if trace.exception is not None:
        return f"{type(trace.exception).__name__}: {trace.exception}"
    return None


def system_fingerprint(trace: RunTrace) -> str | None:
    """D19: stamp what the provider actually served.

    The SDK exposes no `system_fingerprint`, so this composes the closest
    equivalents it does return — the resolved model id on each assistant message
    and the canonical model / provider from `model_usage`. A nightly pass^k that
    starts disagreeing with its own cached history can then be checked against
    this before anyone blames the prompt.
    """
    parts: list[str] = []
    if trace.api_models:
        parts.append("models=" + ",".join(trace.api_models))
    usage = getattr(trace.result, "model_usage", None) or {}
    if usage:
        parts.append("usage_models=" + ",".join(sorted(usage)))
        for key in sorted(usage):
            entry = usage[key]
            if isinstance(entry, Mapping):
                canonical = entry.get("canonicalModel")
                provider = entry.get("provider")
                if canonical:
                    parts.append(f"canonical={canonical}")
                if provider:
                    parts.append(f"provider={provider}")
                break
    return ";".join(parts) if parts else None


# --- the runner ------------------------------------------------------------


@dataclass(slots=True)
class TriageRunner:
    """Wraps `claude_agent_sdk.query`. One `run` call, one `Attempt` row."""

    cwd: str | Path
    query_fn: QueryFn | None = None
    model: str = DEFAULT_MODEL
    effort: str = TRIAGE_EFFORT
    max_turns: int = TRIAGE_MAX_TURNS
    max_budget_usd: float = TRIAGE_MAX_BUDGET_USD
    hooks: Mapping[str, list[HookMatcher]] | None = None
    mcp_servers: Mapping[str, Any] | None = None
    extra_allowed_tools: Sequence[str] = ()
    skills: list[str] | None = None

    def options(self) -> ClaudeAgentOptions:
        return build_options(
            cwd=self.cwd,
            model=self.model,
            effort=self.effort,
            hooks=self.hooks,
            mcp_servers=self.mcp_servers,
            extra_allowed_tools=self.extra_allowed_tools,
            skills=self.skills,
            max_turns=self.max_turns,
            max_budget_usd=self.max_budget_usd,
        )

    def _resolve_query_fn(self) -> QueryFn:
        if self.query_fn is not None:
            return self.query_fn
        from claude_agent_sdk import query  # imported late: no CLI needed for units

        return query  # type: ignore[return-value]

    async def run(
        self,
        finding: Finding,
        context: CodeContext,
        *,
        run_index: int = 0,
        run_epoch: str = "default",
        context_config: ContextConfig | str = DEFAULT_CONTEXT_CONFIG,
        extra_untrusted: Mapping[str, str] | None = None,
        nonce: str | None = None,
    ) -> Attempt:
        config_name = (
            str(context_config)
            if isinstance(context_config, ContextConfig)
            else context_config
        )
        if config_name != context.context_config:
            # The cache keys on this string (D13). Letting the two disagree would
            # file a w50 verdict under a w100 key.
            raise ValueError(
                f"context_config {config_name!r} does not match the assembled "
                f"context {context.context_config!r}"
            )

        turn_nonce = nonce or new_nonce()
        prompt, forgeries = build_user_turn(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            tool=finding.tool,
            path=finding.path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            severity_reported=finding.severity_reported,
            cwe=finding.cwe,
            message=finding.message,
            code_context=context.render(),
            nonce=turn_nonce,
            extra_untrusted=extra_untrusted,
        )

        options = self.options()
        trace = await _collect(self._resolve_query_fn(), prompt, options)
        outcome = classify(
            trace,
            expected_finding_id=finding.finding_id,
            max_turns=self.max_turns,
        )

        result = trace.result
        metadata: dict[str, Any] = {
            "nonce": turn_nonce,
            "delimiter_forgeries_in_prompt": forgeries,
            "requested_model": self.model,
            "api_models": list(trace.api_models),
            "result_subtype": getattr(result, "subtype", None),
            "terminal_reason": getattr(result, "terminal_reason", None),
            "session_id": getattr(result, "session_id", None),
            **outcome.metadata,
        }

        return Attempt(
            finding_id=finding.finding_id,
            # Cache key dimension (D13): the fingerprint, not the id, is what makes a
            # defect the same defect after an unrelated edit shifts its line number.
            fingerprint=finding.fingerprint,
            run_index=run_index,
            status=outcome.status,
            verdict=outcome.verdict if outcome.status == "valid" else None,
            raw_text=trace.text or getattr(result, "result", None),
            # Requested model, not the resolved one: this field is a verdict-cache
            # key dimension (D13) and has to be knowable before the call. What the
            # provider actually served is stamped on `system_fingerprint` (D19).
            model=self.model,
            effort=self.effort,
            context_config=config_name,
            prompt_hash=prompt_hash(),
            run_epoch=run_epoch,
            cost_usd=float(getattr(result, "total_cost_usd", None) or 0.0),
            duration_s=trace.duration_s,
            num_turns=int(getattr(result, "num_turns", 0) or 0),
            system_fingerprint=system_fingerprint(trace),
            error=outcome.error,
            metadata=metadata,
        )

    def run_sync(self, *args: Any, **kwargs: Any) -> Attempt:
        return asyncio.run(self.run(*args, **kwargs))


async def run_k(
    runner: TriageRunner,
    finding: Finding,
    context: CodeContext,
    *,
    k: int = 5,
    run_epoch: str = "default",
    context_config: ContextConfig | str = DEFAULT_CONTEXT_CONFIG,
) -> list[Attempt]:
    """k independent attempts for pass^k. Every attempt is kept, including the
    failed ones — dropping a `schema_invalid` here is exactly the inflation D10
    forbids."""
    return [
        await runner.run(
            finding,
            context,
            run_index=i,
            run_epoch=run_epoch,
            context_config=context_config,
        )
        for i in range(k)
    ]


__all__: Iterable[str] = (
    "Classification",
    "DEFAULT_MODEL",
    "QueryFn",
    "RunTrace",
    "TRIAGE_ALLOWED_TOOLS",
    "TRIAGE_DISALLOWED_TOOLS",
    "TRIAGE_EFFORT",
    "TRIAGE_MAX_BUDGET_USD",
    "TRIAGE_MAX_TURNS",
    "TRIAGE_PERMISSION_MODE",
    "TriageRunner",
    "build_options",
    "classify",
    "extract_payload",
    "first_json_object",
    "run_k",
    "system_fingerprint",
)
