"""Lane D — the triage agent harness.

This is the only lane where a model reads attacker-influenced text, so the
guardrails here are the product: `setting_sources=[]`, a read-only tool set, a
nonce-tagged untrusted-data envelope, PostToolUse redaction and a hash-chained
audit log.
"""

from pramaan.agent.context import (
    ABLATION_CONFIGS,
    DEFAULT_CONTEXT_CONFIG,
    CallerLookup,
    CallerSite,
    CodeContext,
    ContextConfig,
    ContextError,
    build_context,
    read_source,
)
from pramaan.agent.hooks import (
    AuditLogger,
    ScrubReport,
    build_triage_hooks,
    detect_injection,
    redact_secrets,
    sanitise_text,
    scrub,
)
from pramaan.agent.prompts import (
    SKILL_INDEX,
    TRIAGE_SYSTEM_PROMPT,
    UNTRUSTED_TAG,
    build_user_turn,
    close_marker,
    new_nonce,
    open_marker,
    prompt_hash,
    render_system_prompt,
)
from pramaan.agent.triage_runner import (
    TRIAGE_ALLOWED_TOOLS,
    TRIAGE_DISALLOWED_TOOLS,
    TriageRunner,
    build_options,
    classify,
    run_k,
)

__all__ = [
    "ABLATION_CONFIGS", "DEFAULT_CONTEXT_CONFIG", "CallerLookup", "CallerSite",
    "CodeContext", "ContextConfig", "ContextError", "build_context", "read_source",
    "AuditLogger", "ScrubReport", "build_triage_hooks", "detect_injection",
    "redact_secrets", "sanitise_text", "scrub",
    "SKILL_INDEX", "TRIAGE_SYSTEM_PROMPT", "UNTRUSTED_TAG", "build_user_turn",
    "close_marker", "new_nonce", "open_marker", "prompt_hash", "render_system_prompt",
    "TRIAGE_ALLOWED_TOOLS", "TRIAGE_DISALLOWED_TOOLS", "TriageRunner",
    "build_options", "classify", "run_k",
]
