"""Lane E — the four deterministic validators plus the cheating-patch detector.

No model runs in this package. Every result is reproducible from a tree, a diff
and a ruleset, which is what makes a proof bundle checkable by someone who does
not trust the harness that produced it.

Every validator answers with one of four outcomes and never with an exception.
`unavailable` is the one that matters: a validator that could not run has said
nothing, and `ValidatorResult.blocks_pr` treats "said nothing" the same as
"said no".
"""

from pramaan.validators.cheating import (
    CheatSignal,
    detect_cheating,
    validate_no_cheating,
)
from pramaan.validators.diff_scope import (
    DiffLine,
    DiffParseError,
    FileDiff,
    ScopeReport,
    analyse_scope,
    is_dependency_manifest,
    is_test_path,
    parse_unified_diff,
    validate_diff_scope,
)
from pramaan.validators.poc import PoCOutcome, PoCSpec, run_poc, validate_poc
from pramaan.validators.process import (
    CommandResult,
    CommandRunner,
    run_command,
    which,
)
from pramaan.validators.rescan import RescanOutcome, rescan, run_semgrep
from pramaan.validators.tests_validator import (
    SuiteCounts,
    SuiteSpec,
    detect_suite,
    run_suite,
    validate_tests,
)

__all__ = [
    "CheatSignal", "detect_cheating", "validate_no_cheating",
    "DiffLine", "DiffParseError", "FileDiff", "ScopeReport", "analyse_scope",
    "is_dependency_manifest", "is_test_path", "parse_unified_diff",
    "validate_diff_scope",
    "PoCOutcome", "PoCSpec", "run_poc", "validate_poc",
    "CommandResult", "CommandRunner", "run_command", "which",
    "RescanOutcome", "rescan", "run_semgrep",
    "SuiteCounts", "SuiteSpec", "detect_suite", "run_suite", "validate_tests",
]
