# Claude Agent SDK surface — probed, do not guess

Probed from installed `claude_agent_sdk` **0.2.152** on Python 3.12. Every fact below came from introspection of the installed package, not from memory.

## ClaudeAgentOptions fields (48)

| field | type | default |
|---|---|---|
| `tools` | `list[str] | ToolsPreset | None` | `None` |
| `allowed_tools` | `list[str]` | `<factory>` |
| `system_prompt` | `str | SystemPromptPreset | SystemPromptFile | None` | `None` |
| `mcp_servers` | `dict[str, McpStdioServerConfig | McpSSEServerConfig | McpHttpServerConfig | McpSdkServerConfig] | str | pathli` | `<factory>` |
| `strict_mcp_config` | `<class 'bool'>` | `False` |
| `permission_mode` | `Optional[Literal['default', 'acceptEdits', 'plan', 'bypassPermissions', 'dontAsk', 'auto']]` | `None` |
| `continue_conversation` | `<class 'bool'>` | `False` |
| `resume` | `str | None` | `None` |
| `session_id` | `str | None` | `None` |
| `max_turns` | `int | None` | `None` |
| `max_budget_usd` | `float | None` | `None` |
| `disallowed_tools` | `list[str]` | `<factory>` |
| `model` | `str | None` | `None` |
| `fallback_model` | `str | None` | `None` |
| `betas` | `list[Literal['context-1m-2025-08-07']]` | `<factory>` |
| `permission_prompt_tool_name` | `str | None` | `None` |
| `cwd` | `str | pathlib.Path | None` | `None` |
| `cli_path` | `str | pathlib.Path | None` | `None` |
| `settings` | `str | None` | `None` |
| `add_dirs` | `list[str | pathlib.Path]` | `<factory>` |
| `env` | `dict[str, str]` | `<factory>` |
| `extra_args` | `dict[str, str | None]` | `<factory>` |
| `max_buffer_size` | `int | None` | `None` |
| `debug_stderr` | `Any` | `<_io.TextIOWrapper name='<stderr>' mode='w' encoding='utf-8'>` |
| `stderr` | `collections.abc.Callable[[str], None] | None` | `None` |
| `can_use_tool` | `collections.abc.Callable[[str, dict[str, Any], ToolPermissionContext], collections.abc.Awaitable[PermissionRes` | `None` |
| `hooks` | `dict[Union[Literal['PreToolUse'], Literal['PostToolUse'], Literal['PostToolUseFailure'], Literal['UserPromptSu` | `None` |
| `user` | `str | None` | `None` |
| `include_partial_messages` | `<class 'bool'>` | `False` |
| `include_hook_events` | `<class 'bool'>` | `False` |
| `forward_subagent_text` | `<class 'bool'>` | `False` |
| `fork_session` | `<class 'bool'>` | `False` |
| `resume_session_at` | `str | None` | `None` |
| `resume_drops_turn` | `str | None` | `None` |
| `agents` | `dict[str, AgentDefinition] | None` | `None` |
| `setting_sources` | `list[Literal['user', 'project', 'local']] | None` | `None` |
| `skills` | `Union[list[str], Literal['all'], NoneType]` | `None` |
| `sandbox` | `SandboxSettings | None` | `None` |
| `plugins` | `list[SdkPluginConfig]` | `<factory>` |
| `max_thinking_tokens` | `int | None` | `None` |
| `thinking` | `ThinkingConfigAdaptive | ThinkingConfigEnabled | ThinkingConfigDisabled | None` | `None` |
| `effort` | `Optional[Literal['low', 'medium', 'high', 'xhigh', 'max']]` | `None` |
| `output_format` | `dict[str, Any] | None` | `None` |
| `enable_file_checkpointing` | `<class 'bool'>` | `False` |
| `session_store` | `SessionStore | None` | `None` |
| `session_store_flush` | `Literal['batched', 'eager']` | `batched` |
| `load_timeout_ms` | `<class 'int'>` | `60000` |
| `task_budget` | `TaskBudget | None` | `None` |

## Key type aliases

- `PermissionMode` = `Literal['default', 'acceptEdits', 'plan', 'bypassPermissions', 'dontAsk', 'auto']`
- `EffortLevel` = `Literal['low', 'medium', 'high', 'xhigh', 'max']`
- `SettingSource` = `Literal['user', 'project', 'local']`
- `SandboxNetworkConfig` = `<class 'claude_agent_sdk.types.SandboxNetworkConfig'>`
- `SdkBeta` = `Literal['context-1m-2025-08-07']`

## Dataclasses the lanes need

### `AgentDefinition`

- `description: <class 'str'>` = `REQUIRED`
- `prompt: <class 'str'>` = `REQUIRED`
- `tools: list[str] | None` = `None`
- `disallowedTools: list[str] | None` = `None`
- `model: str | None` = `None`
- `skills: list[str] | None` = `None`
- `memory: Optional[Literal['user', 'project', 'local']]` = `None`
- `mcpServers: list[str | dict[str, Any]] | None` = `None`
- `initialPrompt: str | None` = `None`
- `maxTurns: int | None` = `None`
- `background: bool | None` = `None`
- `effort: Union[Literal['low', 'medium', 'high', 'xhigh', 'max'], int, NoneType]` = `None`
- `permissionMode: Optional[Literal['default', 'acceptEdits', 'plan', 'bypassPermissions', 'dontAsk', 'auto']` = `None`

### `HookMatcher`

- `matcher: str | None` = `None`
- `hooks: list[collections.abc.Callable[[PreToolUseHookInput | PostToolUseHookInput | PostToolUseFai` = `<factory>`
- `timeout: float | None` = `None`

### SandboxSettings
NOT A DATACLASS: <class 'claude_agent_sdk.types.SandboxSettings'>

### TaskBudget
NOT A DATACLASS: <class 'claude_agent_sdk.types.TaskBudget'>

### ThinkingConfigEnabled
NOT A DATACLASS: <class 'claude_agent_sdk.types.ThinkingConfigEnabled'>

### McpSdkServerConfig
NOT A DATACLASS: <class 'claude_agent_sdk.types.McpSdkServerConfig'>

## Function signatures
```python
query(*, prompt: str | collections.abc.AsyncIterable[dict[str, typing.Any]], options: claude_agent_sdk.types.ClaudeAgentOptions | None = None, transport: claude_agent_sdk._internal.transport.Transport | None = None) -> collections.abc.AsyncIterator[claude_agent_sdk.types.UserMessage | claude_agent_sdk.types.AssistantMessage | claude_agent_sdk.types.SystemMessage | claude_agent_sdk.types.ResultMessage | claude_agent_sdk.types.StreamEvent | claude_agent_sdk.types.RateLimitEvent | claude_agent_sdk.types.ConversationResetMessage]

tool(name: str, description: str, input_schema: type | dict[str, typing.Any], annotations: mcp_types._types.ToolAnnotations | None = None) -> collections.abc.Callable[[collections.abc.Callable[[typing.Any], collections.abc.Awaitable[dict[str, typing.Any]]]], claude_agent_sdk.SdkMcpTool[typing.Any]]

create_sdk_mcp_server(name: str, version: str = '1.0.0', tools: list[claude_agent_sdk.SdkMcpTool[typing.Any]] | None = None) -> claude_agent_sdk.types.McpSdkServerConfig

fork_session(session_id: 'str', directory: 'str | None' = None, up_to_message_id: 'str | None' = None, title: 'str | None' = None) -> 'ForkSessionResult'

get_session_messages(session_id: 'str', directory: 'str | None' = None, limit: 'int | None' = None, offset: 'int' = 0) -> 'list[SessionMessage]'

```
## ClaudeSDKClient methods

`connect`, `disconnect`, `get_context_usage`, `get_mcp_status`, `get_server_info`, `interrupt`, `query`, `receive_messages`, `receive_response`, `reconnect_mcp_server`, `rewind_files`, `set_model`, `set_permission_mode`, `stop_task`, `toggle_mcp_server`

## Hook event names accepted in `hooks=`

`typing.Literal['PreToolUse']`, `typing.Literal['PostToolUse']`, `typing.Literal['PostToolUseFailure']`, `typing.Literal['UserPromptSubmit']`, `typing.Literal['Stop']`, `typing.Literal['SubagentStop']`, `typing.Literal['PreCompact']`, `typing.Literal['Notification']`, `typing.Literal['SubagentStart']`, `typing.Literal['PermissionRequest']`

## TypedDict shapes (probed)

### `SandboxSettings`

- `enabled: <class 'bool'>` (optional)
- `autoAllowBashIfSandboxed: <class 'bool'>` (optional)
- `excludedCommands: list[str]` (optional)
- `allowUnsandboxedCommands: <class 'bool'>` (optional)
- `network: <class 'SandboxNetworkConfig'>` (optional)
- `ignoreViolations: <class 'SandboxIgnoreViolations'>` (optional)
- `enableWeakerNestedSandbox: <class 'bool'>` (optional)

### `SandboxNetworkConfig`

- `allowedDomains: list[str]` (optional)
- `deniedDomains: list[str]` (optional)
- `allowManagedDomainsOnly: <class 'bool'>` (optional)
- `allowUnixSockets: list[str]` (optional)
- `allowAllUnixSockets: <class 'bool'>` (optional)
- `allowLocalBinding: <class 'bool'>` (optional)
- `allowMachLookup: list[str]` (optional)
- `httpProxyPort: <class 'int'>` (optional)
- `socksProxyPort: <class 'int'>` (optional)

### `TaskBudget`

- `total: <class 'int'>` (required)

### `ThinkingConfigEnabled`

- `type: Literal['enabled']` (required)
- `budget_tokens: <class 'int'>` (required)
- `display: Literal['summarized', 'omitted']` (optional)

### `McpSdkServerConfig`

- `type: Literal['sdk']` (required)
- `name: <class 'str'>` (required)
- `instance: Any` (required)

### `SandboxIgnoreViolations`

- `file: list[str]` (optional)
- `network: list[str]` (optional)

## `output_format` accepted shapes
```python
```

## Hook event literal
```python
not found
```

## `@tool` decorator + `create_sdk_mcp_server`
```python
tool(name: str, description: str, input_schema: type | dict[str, typing.Any], annotations: mcp_types._types.ToolAnnotations | None = None) -> collections.abc.Callable[[collections.abc.Callable[[typing.Any], collections.abc.Awaitable[dict[str, typing.Any]]]], claude_agent_sdk.SdkMcpTool[typing.Any]]

create_sdk_mcp_server(name: str, version: str = '1.0.0', tools: list[claude_agent_sdk.SdkMcpTool[typing.Any]] | None = None) -> claude_agent_sdk.types.McpSdkServerConfig

query(*, prompt: str | collections.abc.AsyncIterable[dict[str, typing.Any]], options: claude_agent_sdk.types.ClaudeAgentOptions | None = None, transport: claude_agent_sdk._internal.transport.Transport | None = None) -> collections.abc.AsyncIterator[claude_agent_sdk.types.UserMessage | claude_agent_sdk.types.AssistantMessage | claude_agent_sdk.types.SystemMessage | claude_agent_sdk.types.ResultMessage | claude_agent_sdk.types.StreamEvent | claude_agent_sdk.types.RateLimitEvent | claude_agent_sdk.types.ConversationResetMessage]

```

## Corrections to the two gaps above

`output_format` is **not** a TypedDict — it is `dict[str, Any] | None` (types.py:2309).
Pass the raw dict: `output_format={"type": "json_schema", "schema": VERDICT_SCHEMA}`.

`HookEvent` is a union of Literals, not a single Literal (types.py:263):

```python
HookEvent = Literal["PreToolUse"] | Literal["PostToolUse"] | Literal["PostToolUseFailure"] \
    | Literal["UserPromptSubmit"] | Literal["Stop"] | Literal["SubagentStop"] \
    | Literal["PreCompact"] | Literal["Notification"] | Literal["SubagentStart"] \
    | Literal["PermissionRequest"]
```

`hooks` is typed `dict[HookEvent, list[HookMatcher]]` (types.py:2128).

## Confirmed for T15 (D7 follow-up)

- `enable_file_checkpointing` — present. Use for fixer rollback.
- `task_budget: TaskBudget` — `{"total": int}`, a **turn/task count**, distinct from
  `max_budget_usd` (float, dollars). They are not redundant; use both on the fixer.
