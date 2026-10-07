from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from ..sandbox.tool_runtime import SandboxedToolHandler
from ..sandbox.types import SandboxExecutionRequest, SandboxToolPolicy
from ..types import ToolDefinition


@dataclass(frozen=True)
class WasmHttpAllowlist:
    host: str
    path_prefix: str
    methods: tuple[str, ...] = ("GET",)


@dataclass(frozen=True)
class WasmCredentialSpec:
    name: str
    secret_name: str
    location: str
    host_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IronClawWasmToolSpec:
    name: str
    command: str
    description: str
    actions: tuple[str, ...]
    http_allowlist: tuple[WasmHttpAllowlist, ...] = ()
    credentials: tuple[WasmCredentialSpec, ...] = ()
    secrets: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    requires_approval: bool = True
    requires_sanitization: bool = True

    def parameters_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": list(self.actions),
                    "description": "Operation to run inside the WASM tool.",
                },
                "params": {
                    "type": "object",
                    "description": "Action-specific parameters. The WASI wrapper validates this payload.",
                    "additionalProperties": True,
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        }

    def metadata(self) -> dict[str, Any]:
        return {
            "source": "ironclaw",
            "runtime": "wasm",
            "abi": "titanx-wasi-json-argv",
            "wasm_command": self.command,
            "capabilities": {
                "http_allowlist": [
                    {
                        "host": item.host,
                        "path_prefix": item.path_prefix,
                        "methods": list(item.methods),
                    }
                    for item in self.http_allowlist
                ],
                "credentials": [
                    {
                        "name": item.name,
                        "secret_name": item.secret_name,
                        "location": item.location,
                        "host_patterns": list(item.host_patterns),
                    }
                    for item in self.credentials
                ],
                "secrets": list(self.secrets),
            },
            "notes": list(self.notes),
        }


IRONCLAW_WASM_TOOLS: tuple[IronClawWasmToolSpec, ...] = (
    IronClawWasmToolSpec(
        name="github",
        command="github_tool",
        description=(
            "Manage GitHub repositories, issues, pull requests, search, branches, "
            "file reads/writes, releases, and workflow runs."
        ),
        actions=(
            "get_repo",
            "list_issues",
            "create_issue",
            "list_pull_requests",
            "create_pull_request",
            "search_code",
            "read_file",
            "create_or_update_file",
            "create_branch",
            "dispatch_workflow",
            "list_workflow_runs",
        ),
        http_allowlist=(
            WasmHttpAllowlist("api.github.com", "/", ("GET", "POST", "PUT", "DELETE")),
        ),
        credentials=(
            WasmCredentialSpec("github_token", "github_token", "bearer", ("api.github.com",)),
        ),
        secrets=("github_token", "github_*"),
        notes=(
            "Repository-scoped actions require owner and repo.",
            "File write actions require path and commit message.",
        ),
    ),
    IronClawWasmToolSpec(
        name="gmail",
        command="gmail_tool",
        description="Read, search, send, draft, and reply to Gmail messages and threads.",
        actions=("search", "read", "send", "draft", "reply", "delete"),
        http_allowlist=(WasmHttpAllowlist("gmail.googleapis.com", "/gmail/v1/", ("GET", "POST", "DELETE")),),
        credentials=(
            WasmCredentialSpec("google_oauth_token", "google_oauth_token", "bearer", ("gmail.googleapis.com",)),
        ),
        secrets=("google_oauth_token",),
    ),
    IronClawWasmToolSpec(
        name="google_calendar",
        command="google_calendar_tool",
        description="View, create, update, and delete Google Calendar events.",
        actions=("list_events", "get_event", "create_event", "update_event", "delete_event", "search_events"),
        http_allowlist=(WasmHttpAllowlist("www.googleapis.com", "/calendar/v3/", ("GET", "POST", "PUT", "DELETE")),),
        credentials=(
            WasmCredentialSpec("google_oauth_token", "google_oauth_token", "bearer", ("www.googleapis.com",)),
        ),
        secrets=("google_oauth_token",),
    ),
    IronClawWasmToolSpec(
        name="google_docs",
        command="google_docs_tool",
        description="Create, read, edit, and format Google Docs documents.",
        actions=("create_document", "get_document", "insert_text", "replace_text", "format_text", "batch_update"),
        http_allowlist=(WasmHttpAllowlist("docs.googleapis.com", "/v1/documents", ("GET", "POST")),),
        credentials=(
            WasmCredentialSpec("google_oauth_token", "google_oauth_token", "bearer", ("docs.googleapis.com",)),
        ),
        secrets=("google_oauth_token",),
    ),
    IronClawWasmToolSpec(
        name="google_drive",
        command="google_drive_tool",
        description="Search, access, upload, share, and organize Google Drive files and folders.",
        actions=("search", "get_file", "download", "upload", "share", "move", "delete"),
        http_allowlist=(
            WasmHttpAllowlist("www.googleapis.com", "/drive/v3/", ("GET", "POST", "PATCH", "DELETE")),
            WasmHttpAllowlist("www.googleapis.com", "/upload/drive/v3/", ("POST", "PATCH")),
        ),
        credentials=(
            WasmCredentialSpec("google_oauth_token", "google_oauth_token", "bearer", ("www.googleapis.com",)),
        ),
        secrets=("google_oauth_token",),
    ),
    IronClawWasmToolSpec(
        name="google_sheets",
        command="google_sheets_tool",
        description="Create, read, write, and format Google Sheets spreadsheets.",
        actions=("create_spreadsheet", "read_range", "write_range", "append_rows", "format_cells", "batch_update"),
        http_allowlist=(WasmHttpAllowlist("sheets.googleapis.com", "/v4/spreadsheets", ("GET", "POST", "PUT")),),
        credentials=(
            WasmCredentialSpec("google_oauth_token", "google_oauth_token", "bearer", ("sheets.googleapis.com",)),
        ),
        secrets=("google_oauth_token",),
    ),
    IronClawWasmToolSpec(
        name="google_slides",
        command="google_slides_tool",
        description="Create, read, edit, and format Google Slides presentations.",
        actions=("create_presentation", "get_presentation", "add_slide", "insert_text", "insert_image", "batch_update"),
        http_allowlist=(WasmHttpAllowlist("slides.googleapis.com", "/v1/presentations", ("GET", "POST")),),
        credentials=(
            WasmCredentialSpec("google_oauth_token", "google_oauth_token", "bearer", ("slides.googleapis.com",)),
        ),
        secrets=("google_oauth_token",),
    ),
    IronClawWasmToolSpec(
        name="slack",
        command="slack_tool",
        description="Send messages, list channels, read history, add reactions, and get Slack user information.",
        actions=("send_message", "list_channels", "read_history", "add_reaction", "get_user_info"),
        http_allowlist=(WasmHttpAllowlist("slack.com", "/api/", ("GET", "POST")),),
        credentials=(WasmCredentialSpec("slack_bot_token", "slack_bot_token", "bearer", ("slack.com",)),),
        secrets=("slack_bot_token",),
    ),
    IronClawWasmToolSpec(
        name="telegram_mtproto",
        command="telegram_tool",
        description="Read and send Telegram messages via a user account using MTProto.",
        actions=("list_chats", "read_history", "search_messages", "send_message", "forward_message", "delete_message"),
        http_allowlist=(WasmHttpAllowlist("*.web.telegram.org", "/apiw", ("GET", "POST")),),
        credentials=(
            WasmCredentialSpec("telegram_api_id", "telegram_api_id", "host_secret", ("*.web.telegram.org",)),
            WasmCredentialSpec("telegram_api_hash", "telegram_api_hash", "host_secret", ("*.web.telegram.org",)),
        ),
        secrets=("telegram_api_id", "telegram_api_hash"),
    ),
    IronClawWasmToolSpec(
        name="web_search",
        command="web_search_tool",
        description="Search the web using Brave Search and return titles, URLs, snippets, and dates.",
        actions=("search",),
        http_allowlist=(WasmHttpAllowlist("api.search.brave.com", "/res/v1/web/search", ("GET",)),),
        credentials=(
            WasmCredentialSpec("brave_api_key", "brave_api_key", "header:X-Subscription-Token", ("api.search.brave.com",)),
        ),
        secrets=("brave_api_key",),
    ),
    IronClawWasmToolSpec(
        name="llm_context",
        command="llm_context_tool",
        description="Fetch Brave Search LLM context content for grounding, RAG, and fact checking.",
        actions=("fetch_context",),
        http_allowlist=(WasmHttpAllowlist("api.search.brave.com", "/res/v1/llm/context", ("GET",)),),
        credentials=(
            WasmCredentialSpec("brave_api_key", "brave_api_key", "header:X-Subscription-Token", ("api.search.brave.com",)),
        ),
        secrets=("brave_api_key",),
    ),
    IronClawWasmToolSpec(
        name="composio",
        command="composio_tool",
        description="Connect to third-party apps through Composio actions and OAuth-linked accounts.",
        actions=("list", "execute", "connect", "connected_accounts"),
        http_allowlist=(WasmHttpAllowlist("backend.composio.dev", "/api/v3/", ("GET", "POST")),),
        credentials=(
            WasmCredentialSpec("composio_api_key", "composio_api_key", "header:X-API-Key", ("backend.composio.dev",)),
        ),
        secrets=("composio_api_key",),
    ),
)


def get_ironclaw_wasm_tool_specs(names: Iterable[str] | None = None) -> list[IronClawWasmToolSpec]:
    if names is None:
        return list(IRONCLAW_WASM_TOOLS)
    wanted = set(names)
    specs = [spec for spec in IRONCLAW_WASM_TOOLS if spec.name in wanted]
    missing = sorted(wanted - {spec.name for spec in specs})
    if missing:
        raise ValueError(f"Unknown IronClaw WASM tool(s): {', '.join(missing)}")
    return specs


def create_ironclaw_wasm_handlers(
    names: Iterable[str] | None = None,
    *,
    command_overrides: dict[str, str] | None = None,
) -> list[SandboxedToolHandler]:
    """Create TitanX handlers for IronClaw-inspired WASM tools.

    The handler ABI is intentionally simple: TitanX executes a registered WASI
    command and passes one JSON argv payload:

        {"tool": "<name>", "action": "<action>", "params": {...}}

    A real WASM module must be compiled as a TitanX-compatible WASI wrapper that
    reads this payload from argv[1] and writes JSON/text to stdout.
    """

    overrides = command_overrides or {}
    handlers: list[SandboxedToolHandler] = []
    for spec in get_ironclaw_wasm_tool_specs(names):
        command = overrides.get(spec.name, spec.command)

        def request_fn(
            params: dict[str, Any],
            *,
            tool_spec: IronClawWasmToolSpec = spec,
            wasm_command: str = command,
        ) -> SandboxExecutionRequest:
            payload = {
                "tool": tool_spec.name,
                "action": params.get("action"),
                "params": params.get("params", {}),
            }
            return SandboxExecutionRequest(
                command=wasm_command,
                args=[json.dumps(payload, ensure_ascii=False, separators=(",", ":"))],
            )

        handlers.append(
            SandboxedToolHandler(
                definition=ToolDefinition(
                    name=spec.name,
                    description=spec.description,
                    parameters=spec.parameters_schema(),
                    requires_approval=spec.requires_approval,
                    requires_sanitization=spec.requires_sanitization,
                    metadata=spec.metadata(),
                ),
                request_fn=request_fn,
                policy=SandboxToolPolicy(preferred_backend="wasm", risk_level="low"),
            )
        )
    return handlers
