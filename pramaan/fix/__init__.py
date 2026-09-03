"""Lane E — the fixer agent and its guards.

The only agent in Pramaan that can write, so its containment is the safety
argument: a throwaway git worktree, an egress-free sandbox, a `PreToolUse` deny
hook that holds even under `bypassPermissions`, and `setting_sources=[]` so the
repository being fixed cannot write the fixer's instructions.
"""

from pramaan.fix.guards import (
    DENIED_BINARIES,
    DENIED_GIT_SUBCOMMANDS,
    SECRET_PATH_GLOBS,
    Denial,
    RegressionTestGate,
    check_bash,
    check_path,
    check_tool,
    has_regression_test,
    make_deny_hook,
    make_regression_test_hook,
    regression_test_validator,
)
from pramaan.fix.runner import (
    FIXER_ALLOWED_TOOLS,
    FIXER_DISALLOWED_TOOLS,
    FIXER_MAX_BUDGET_USD,
    FIXER_MAX_TURNS,
    FIXER_SANDBOX,
    FIXER_TASK_BUDGET,
    FixAttempt,
    FixRunner,
    GitWorktree,
    WorktreeError,
    build_fix_prompt,
    build_fixer_hooks,
    build_fixer_options,
    create_worktree,
)

__all__ = [
    "DENIED_BINARIES", "DENIED_GIT_SUBCOMMANDS", "SECRET_PATH_GLOBS", "Denial",
    "RegressionTestGate", "check_bash", "check_path", "check_tool",
    "has_regression_test", "make_deny_hook", "make_regression_test_hook",
    "regression_test_validator",
    "FIXER_ALLOWED_TOOLS", "FIXER_DISALLOWED_TOOLS", "FIXER_MAX_BUDGET_USD",
    "FIXER_MAX_TURNS", "FIXER_SANDBOX", "FIXER_TASK_BUDGET",
    "FixAttempt", "FixRunner", "GitWorktree", "WorktreeError",
    "build_fix_prompt", "build_fixer_hooks", "build_fixer_options", "create_worktree",
]
