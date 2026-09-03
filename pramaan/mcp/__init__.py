"""The actuator lane: in-process MCP tools and the guardrails around them.

This is the only code in the project that can change the outside world, so its
defining property is that it can do very little, idempotently. Four MCP tools
exist in total: `create_draft_pr` and `comment` (`github_tools.py`, mutating),
`get_finding` (`dojo_tools.py`, read-only) and `update_finding`
(`dojo_tools.py`, mutating). No delete, no merge, no close of a true positive,
no force-push, anywhere. `killswitch.py` can abort any of it before the next
tool call; `shadow.py` can run the whole decide-then-act path with every
verdict logged and nothing actually touched.
"""

from pramaan.mcp.dojo_tools import (
    CLOSING_FIELDS,
    DojoApiError,
    DojoClient,
    RestDojoClient,
    build_dojo_tools,
    create_dojo_server,
    get_finding,
    update_finding,
)
from pramaan.mcp.errors import (
    ActuatorError,
    ConfigurationError,
    GuardrailViolation,
    KillSwitchEngaged,
)
from pramaan.mcp.github_tools import (
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
from pramaan.mcp.killswitch import KILLSWITCH_ENV_VAR, is_engaged, make_killswitch_hook, raise_if_engaged
from pramaan.mcp.records import InMemoryRecordStore, JsonFileRecordStore, RecordStore
from pramaan.mcp.shadow import LIVE, SHADOW, Actuator, ActuatorMode, ShadowAction, ShadowRecorder

__all__ = [
    "CLOSING_FIELDS", "DojoApiError", "DojoClient", "RestDojoClient",
    "build_dojo_tools", "create_dojo_server", "get_finding", "update_finding",
    "ActuatorError", "ConfigurationError", "GuardrailViolation", "KillSwitchEngaged",
    "CommentRef", "GitHubApiError", "GitHubClient", "IssueRef",
    "PullRequestAlreadyExists", "PullRequestRef", "RestGitHubClient",
    "branch_name_for", "build_github_tools", "comment", "create_draft_pr",
    "create_github_server",
    "KILLSWITCH_ENV_VAR", "is_engaged", "make_killswitch_hook", "raise_if_engaged",
    "InMemoryRecordStore", "JsonFileRecordStore", "RecordStore",
    "LIVE", "SHADOW", "Actuator", "ActuatorMode", "ShadowAction", "ShadowRecorder",
]
