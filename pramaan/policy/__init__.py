"""Lane B - the act-vs-escalate policy.

`engine.decide` is the only thing in this project allowed to say what happens to
a finding. `sensitive_paths.tag` is the deterministic half of the sensitivity
signal it consumes.
"""

from pramaan.policy.engine import (
    FIXER_ALLOWLIST,
    Decision,
    EscalateReason,
    PolicyRow,
    RecommendedAction,
    SsvcDecision,
    decide,
    decide_after_proof,
    effective_tags,
    normalise_cwe,
)
from pramaan.policy.sensitive_paths import (
    DEFAULT_CONFIG_PATH,
    KNOWN_TAGS,
    PathRule,
    SensitivePathConfigError,
    default_rules,
    explain,
    load_rules,
    normalise_path,
    tag,
)

__all__ = [
    "FIXER_ALLOWLIST", "Decision", "EscalateReason", "PolicyRow",
    "RecommendedAction", "SsvcDecision", "decide", "decide_after_proof",
    "effective_tags", "normalise_cwe",
    "DEFAULT_CONFIG_PATH", "KNOWN_TAGS", "PathRule", "SensitivePathConfigError",
    "default_rules", "explain", "load_rules", "normalise_path", "tag",
]
