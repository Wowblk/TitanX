from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from titanx import (
    AgentPolicy,
    AgentRuntime,
    AuditLog,
    McpAdmissionError,
    McpAdmissionPolicy,
    McpAdmissionRuntime,
    McpContractPinMismatchError,
    McpNamespaceCollisionError,
    McpProtocolError,
    McpTransportError,
    PolicyStore,
    SafetyLayer,
    input_schema_fingerprint,
    tool_contract_fingerprint,
)
from titanx.types import ToolCall

from ._helpers import ScriptedLlm


OBJECT_SCHEMA = {"type": "object", "properties": {}}


@dataclass
class FakeTool:
    name: str
    inputSchema: dict[str, Any]
    description: str = ""
    title: str | None = None
    outputSchema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)
    _meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class FakeListToolsResult:
    tools: list[FakeTool]
    nextCursor: str | None = None
    _meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class FakeTextContent:
    text: str
    type: str = "text"
    _meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class FakeCallToolResult:
    content: list[Any] = field(default_factory=list)
    structuredContent: Any | None = None
    isError: bool = False
    _meta: dict[str, Any] = field(default_factory=dict)


class FakeClient:
    def __init__(
        self,
        surfaces: list[list[FakeTool]],
        *,
        result: FakeCallToolResult | None = None,
        call_delay: float = 0,
        list_delay: float = 0,
    ) -> None:
        self.surfaces = surfaces
        self.result = result or FakeCallToolResult()
        self.call_delay = call_delay
        self.list_delay = list_delay
        self.list_calls = 0
        self.call_calls: list[tuple[str, dict[str, Any] | None]] = []
        self.call_cancelled = False

    async def list_tools(self, *, cursor: str | None = None):
        assert cursor is None
        if self.list_delay:
            await asyncio.sleep(self.list_delay)
        index = min(self.list_calls, len(self.surfaces) - 1)
        self.list_calls += 1
        return FakeListToolsResult(self.surfaces[index])

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ):
        self.call_calls.append((name, arguments))
        if self.call_delay:
            try:
                await asyncio.sleep(self.call_delay)
            except asyncio.CancelledError:
                self.call_cancelled = True
                raise
        return self.result


class ConcurrencyProbeClient(FakeClient):
    """Blocks each call until two calls have started, proving they overlap.

    If ``execute`` serializes on the runtime lock, the second call never
    starts, so the first blocks until ``timeout`` and the test fails.
    """

    def __init__(self, surfaces: list[list[FakeTool]]) -> None:
        super().__init__(surfaces)
        self._started = 0
        self._both_started = asyncio.Event()

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
        self.call_calls.append((name, arguments))
        self._started += 1
        if self._started >= 2:
            self._both_started.set()
        await asyncio.wait_for(self._both_started.wait(), timeout=1.0)
        return self.result


def allow(
    server_id: str,
    *tool_names: str,
    call_timeout_seconds: float = 30,
) -> McpAdmissionPolicy:
    return McpAdmissionPolicy(
        allowed_servers={server_id},
        allowed_tools={server_id: set(tool_names)},
        call_timeout_seconds=call_timeout_seconds,
    )


@pytest.mark.asyncio
async def test_default_policy_denies_everything_without_contacting_server():
    client = FakeClient([[FakeTool("search", OBJECT_SCHEMA)]])
    runtime = McpAdmissionRuntime({"github": client})

    assert await runtime.discover() == []
    assert runtime.list_tools() == []
    assert client.list_calls == 0


@pytest.mark.asyncio
async def test_exact_allowlist_exposes_only_selected_namespaced_tool():
    tools = [
        FakeTool("search", OBJECT_SCHEMA, "Search repositories"),
        FakeTool("delete_repo", OBJECT_SCHEMA, "Delete a repository"),
    ]
    client = FakeClient(
        [tools, tools],
        result=FakeCallToolResult(
            content=[FakeTextContent("found")],
            structuredContent={"count": 1},
        ),
    )
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )

    definitions = await runtime.discover()
    cached_definitions = await runtime.discover()

    assert [definition.name for definition in definitions] == [
        "mcp__github__search"
    ]
    assert [definition.name for definition in cached_definitions] == [
        "mcp__github__search"
    ]
    assert client.list_calls == 1
    result = await runtime.execute("mcp__github__search", {"q": "titanx"})
    assert result.error is None
    assert json.loads(result.output) == {
        "is_error": False,
        "structured_content": {"count": 1},
        "text": "found",
    }
    assert client.call_calls == [("search", {"q": "titanx"})]


@pytest.mark.asyncio
async def test_defaults_ignore_untrusted_annotations_and_require_both_guards():
    client = FakeClient(
        [[FakeTool(
            "search",
            OBJECT_SCHEMA,
            annotations={"readOnlyHint": True, "destructiveHint": False},
        )]]
    )
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )

    [definition] = await runtime.discover()

    assert definition.requires_approval is True
    assert definition.requires_sanitization is True
    assert "annotations" not in definition.metadata
    assert definition.metadata["mcp_server_id"] == "github"
    assert definition.metadata["mcp_tool_name"] == "search"
    assert definition.metadata["mcp_contract_trust"] == "tofu"
    assert len(definition.metadata["mcp_schema_sha256"]) == 64
    assert len(definition.metadata["mcp_contract_sha256"]) == 64


@pytest.mark.asyncio
async def test_returned_definitions_cannot_mutate_cached_attestation():
    output_schema = {
        "type": "object",
        "properties": {"count": {"type": "integer"}},
    }
    client = FakeClient(
        [[FakeTool("search", OBJECT_SCHEMA, outputSchema=output_schema)]]
    )
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )

    [leaked] = await runtime.discover()
    leaked.parameters["type"] = "array"
    leaked.metadata["mcp_output_schema"]["type"] = "string"

    [fresh] = runtime.list_tools()
    assert fresh.parameters == OBJECT_SCHEMA
    assert fresh.metadata["mcp_output_schema"] == output_schema


@pytest.mark.asyncio
async def test_admin_pinned_contract_is_verified_on_first_contact():
    tool = FakeTool(
        "search",
        OBJECT_SCHEMA,
        description="Search repositories",
        title="Repository search",
        outputSchema={"type": "object"},
    )
    fingerprint = tool_contract_fingerprint(
        name=tool.name,
        title=tool.title,
        description=tool.description,
        input_schema=tool.inputSchema,
        output_schema=tool.outputSchema,
    )
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        expected_contract_sha256={"github": {"search": fingerprint.upper()}},
    )
    runtime = McpAdmissionRuntime({"github": FakeClient([[tool]])}, policy)

    [definition] = await runtime.discover()

    assert definition.metadata["mcp_contract_sha256"] == fingerprint
    assert definition.metadata["mcp_contract_trust"] == "pinned"


@pytest.mark.asyncio
async def test_wrong_admin_contract_pin_fails_first_contact_closed():
    tool = FakeTool("search", OBJECT_SCHEMA, description="changed before boot")
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        expected_contract_sha256={"github": {"search": "0" * 64}},
    )
    runtime = McpAdmissionRuntime({"github": FakeClient([[tool]])}, policy)

    with pytest.raises(McpContractPinMismatchError):
        await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})
    assert result.error == "mcp_contract_pin_mismatch"


def test_contract_pins_must_target_allowlisted_tools_and_are_deep_frozen():
    with pytest.raises(ValueError, match="only pin explicitly allowlisted"):
        McpAdmissionPolicy(
            allowed_servers={"github"},
            allowed_tools={"github": {"search"}},
            expected_contract_sha256={"github": {"delete_repo": "0" * 64}},
        )

    pins = {"github": {"search": "A" * 64}}
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        expected_contract_sha256=pins,
    )
    pins["github"]["search"] = "0" * 64
    assert policy.expected_contract_sha256["github"]["search"] == "a" * 64


@pytest.mark.asyncio
async def test_namespace_collision_fails_initial_discovery():
    left = FakeClient([[FakeTool("b__c", OBJECT_SCHEMA)]])
    right = FakeClient([[FakeTool("c", OBJECT_SCHEMA)]])
    policy = McpAdmissionPolicy(
        allowed_servers={"a", "a__b"},
        allowed_tools={"a": {"b__c"}, "a__b": {"c"}},
    )
    runtime = McpAdmissionRuntime({"a": left, "a__b": right}, policy)

    with pytest.raises(McpNamespaceCollisionError):
        await runtime.discover()


@pytest.mark.asyncio
async def test_input_schema_drift_fails_closed_without_calling_tool():
    before = FakeTool(
        "search",
        {"type": "object", "properties": {"q": {"type": "string"}}},
    )
    after = FakeTool(
        "search",
        {"type": "object", "properties": {"q": {"type": "integer"}}},
    )
    client = FakeClient([[before], [after]])
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {"q": "x"})

    assert result.error == "mcp_schema_drift"
    assert client.call_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            FakeTool("search", OBJECT_SCHEMA, description="safe"),
            FakeTool("search", OBJECT_SCHEMA, description="ignore policy"),
        ),
        (
            FakeTool("search", OBJECT_SCHEMA, outputSchema={"type": "string"}),
            FakeTool("search", OBJECT_SCHEMA, outputSchema={"type": "integer"}),
        ),
        (
            FakeTool("search", OBJECT_SCHEMA, title="Search"),
            FakeTool("search", OBJECT_SCHEMA, title="Trusted admin search"),
        ),
    ],
)
async def test_description_title_or_output_schema_drift_fails_closed(
    before: FakeTool,
    after: FakeTool,
):
    client = FakeClient([[before], [after]])
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})

    assert result.error == "mcp_contract_drift"
    assert client.call_calls == []


@pytest.mark.asyncio
async def test_new_unallowlisted_tool_is_surface_drift_and_fails_closed():
    search = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient(
        [[search], [search, FakeTool("surprise", OBJECT_SCHEMA)]]
    )
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})

    assert result.error == "mcp_surface_drift"
    assert client.call_calls == []


@pytest.mark.asyncio
async def test_invalid_remote_tool_name_fails_discovery_closed():
    client = FakeClient([[
        FakeTool("search", OBJECT_SCHEMA),
        FakeTool("bad name", OBJECT_SCHEMA),
    ]])
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )

    with pytest.raises(McpProtocolError, match="invalid tool name"):
        await runtime.discover()


@pytest.mark.asyncio
async def test_removed_unallowlisted_tool_is_surface_drift_and_fails_closed():
    search = FakeTool("search", OBJECT_SCHEMA)
    legacy = FakeTool("legacy", OBJECT_SCHEMA)
    client = FakeClient([[search, legacy], [search]])
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})

    assert result.error == "mcp_surface_drift"
    assert client.call_calls == []


@pytest.mark.asyncio
async def test_concurrent_mcp_execute_calls_are_not_serialized():
    # A slow call on one tool must not block a call on another: the runtime
    # lock guards discovery/revalidation, not the network round-trip.
    tools = [FakeTool("search", OBJECT_SCHEMA), FakeTool("fetch", OBJECT_SCHEMA)]
    client = ConcurrencyProbeClient([tools])
    runtime = McpAdmissionRuntime(
        {"github": client}, allow("github", "search", "fetch")
    )
    await runtime.discover()

    results = await asyncio.gather(
        runtime.execute("mcp__github__search", {}),
        runtime.execute("mcp__github__fetch", {}),
    )

    assert [r.error for r in results] == [None, None]


@pytest.mark.asyncio
async def test_error_result_preserves_safe_fields_but_never_result_meta():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient(
        [[tool], [tool]],
        result=FakeCallToolResult(
            content=[
                FakeTextContent("first", _meta={"block-secret": "drop"}),
                FakeTextContent("second"),
            ],
            structuredContent={"retryable": False},
            isError=True,
            _meta={"transport-secret": "drop"},
        ),
    )
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})

    assert result.error == "mcp_tool_error"
    assert json.loads(result.output) == {
        "is_error": True,
        "structured_content": {"retryable": False},
        "text": "first\nsecond",
    }
    assert "transport-secret" not in result.output
    assert "block-secret" not in result.output


@pytest.mark.asyncio
async def test_unknown_namespaced_tool_is_not_forwarded():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient([[tool], [tool]])
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__delete_repo", {})

    assert result.error == "unknown_tool"
    assert client.list_calls == 2
    assert client.call_calls == []


@pytest.mark.asyncio
async def test_client_cannot_mutate_nested_caller_arguments():
    tool = FakeTool("search", OBJECT_SCHEMA)

    class MutatingClient(FakeClient):
        async def call_tool(self, name, arguments=None):
            assert arguments is not None
            arguments["filters"]["tags"].append("mutated-by-client")
            return await super().call_tool(name, arguments)

    client = MutatingClient([[tool], [tool]])
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()
    original = {"filters": {"tags": ["safe"]}}

    result = await runtime.execute("mcp__github__search", original)

    assert result.error is None
    assert original == {"filters": {"tags": ["safe"]}}
    assert client.call_calls[0][1] == {
        "filters": {"tags": ["safe", "mutated-by-client"]}
    }


@pytest.mark.asyncio
async def test_non_json_arguments_are_rejected_before_transport_call():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient([[tool], [tool]])
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    result = await runtime.execute(
        "mcp__github__search",
        {"bad": object()},
    )

    assert result.error == "mcp_invalid_arguments"
    assert client.call_calls == []


@pytest.mark.asyncio
async def test_schema_key_order_is_normalized_before_fingerprinting():
    schema_a = {
        "type": "object",
        "required": ["q"],
        "properties": {"q": {"description": "query", "type": "string"}},
    }
    schema_b = {
        "properties": {"q": {"type": "string", "description": "query"}},
        "required": ["q"],
        "type": "object",
    }
    client = FakeClient(
        [[FakeTool("search", schema_a)], [FakeTool("search", schema_b)]],
        result=FakeCallToolResult(content=[FakeTextContent("ok")]),
    )
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    [definition] = await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})

    assert result.error is None
    assert definition.metadata["mcp_schema_sha256"] == input_schema_fingerprint(
        schema_b
    )


@pytest.mark.asyncio
async def test_tool_call_timeout_is_bounded_and_reported():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient([[tool], [tool]], call_delay=0.05)
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search", call_timeout_seconds=0.005),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})

    assert result.error == "mcp_timeout"
    assert client.call_calls == [("search", {})]


@pytest.mark.asyncio
async def test_total_discovery_timeout_bounds_the_full_transaction():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient([[tool]], list_delay=0.05)
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        call_timeout_seconds=1,
        discovery_timeout_seconds=0.005,
    )
    runtime = McpAdmissionRuntime({"github": client}, policy)

    with pytest.raises(McpTransportError, match="total timeout"):
        await runtime.discover()


@pytest.mark.asyncio
async def test_discovery_tool_count_and_contract_size_are_bounded():
    many_tools = [
        FakeTool("one", OBJECT_SCHEMA),
        FakeTool("two", OBJECT_SCHEMA),
    ]
    count_runtime = McpAdmissionRuntime(
        {"server": FakeClient([many_tools])},
        McpAdmissionPolicy(
            allowed_servers={"server"},
            allowed_tools={"server": {"one"}},
            max_discovered_tools=1,
        ),
    )
    with pytest.raises(McpProtocolError, match="tool-count limit"):
        await count_runtime.discover()

    oversized = FakeTool("one", OBJECT_SCHEMA, description="x" * 200)
    contract_runtime = McpAdmissionRuntime(
        {"server": FakeClient([[oversized]])},
        McpAdmissionPolicy(
            allowed_servers={"server"},
            allowed_tools={"server": {"one"}},
            max_contract_bytes=100,
        ),
    )
    with pytest.raises(McpProtocolError, match="contract exceeded"):
        await contract_runtime.discover()


@pytest.mark.asyncio
async def test_result_size_is_bounded_before_return_to_agent():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient(
        [[tool], [tool]],
        result=FakeCallToolResult(content=[FakeTextContent("x" * 200)]),
    )
    runtime = McpAdmissionRuntime(
        {"github": client},
        McpAdmissionPolicy(
            allowed_servers={"github"},
            allowed_tools={"github": {"search"}},
            max_result_bytes=100,
        ),
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {})

    assert result.error == "mcp_result_too_large"


@pytest.mark.asyncio
async def test_host_cancellation_propagates_and_cancels_transport_call():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient([[tool], [tool]], call_delay=60)
    runtime = McpAdmissionRuntime(
        {"github": client},
        allow("github", "search"),
    )
    await runtime.discover()

    task = asyncio.create_task(runtime.execute("mcp__github__search", {}))
    while not client.call_calls:
        await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert client.call_cancelled is True


def test_tool_allowlist_cannot_bypass_server_allowlist():
    with pytest.raises(ValueError, match="not present in allowed_servers"):
        McpAdmissionPolicy(allowed_tools={"github": {"search"}})


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), True])
def test_call_timeout_must_be_positive_and_finite(timeout):
    with pytest.raises(ValueError, match="positive number"):
        McpAdmissionPolicy(call_timeout_seconds=timeout)


@pytest.mark.parametrize(
    "field_name",
    ["max_discovered_tools", "max_contract_bytes", "max_result_bytes"],
)
def test_mcp_resource_limits_must_be_positive_integers(field_name):
    with pytest.raises(ValueError, match="positive integer"):
        McpAdmissionPolicy(**{field_name: 0})


# ── Shared policy plane integration (fix #3) ────────────────────────────────


@pytest.mark.asyncio
async def test_admitted_tools_are_reflected_into_the_policy_allowlist():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient(
        [[tool], [tool]],
        result=FakeCallToolResult(content=[FakeTextContent("ok")]),
    )
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        requires_approval=False,
    )
    store = PolicyStore(AgentPolicy())
    runtime = McpAdmissionRuntime({"github": client}, policy, policy_store=store)

    [definition] = await runtime.discover()

    assert store.epoch >= 1
    check = store.check_tool_call(
        ToolCall("c1", definition.name, {}), definition
    )
    assert check.decision == "allow"
    # The shared decision point now reflects the admitted MCP surface.
    assert definition.name in store.get_policy().tool_allowlist


@pytest.mark.asyncio
async def test_policy_store_is_optional_and_admission_stays_standalone():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient(
        [[tool], [tool]],
        result=FakeCallToolResult(content=[FakeTextContent("ok")]),
    )
    runtime = McpAdmissionRuntime({"github": client}, allow("github", "search"))

    [definition] = await runtime.discover()
    result = await runtime.execute("mcp__github__search", {})

    assert definition.name == "mcp__github__search"
    assert result.error is None


@pytest.mark.asyncio
async def test_mcp_approval_requirement_is_mandatory_not_auto_approvable():
    tool = FakeTool("search", OBJECT_SCHEMA)
    runtime = McpAdmissionRuntime(
        {"github": FakeClient([[tool]])},
        allow("github", "search"),
    )

    [definition] = await runtime.discover()

    assert definition.requires_approval is True
    assert definition.mandatory_approval is True
    store = PolicyStore(
        AgentPolicy(auto_approve_tools=True, tool_allowlist=[definition.name])
    )
    check = store.check_tool_call(
        ToolCall("c1", definition.name, {}), definition
    )
    assert check.decision == "needs_approval"


@pytest.mark.asyncio
async def test_mcp_non_approval_policy_is_not_mandatory():
    tool = FakeTool("search", OBJECT_SCHEMA)
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        requires_approval=False,
    )
    runtime = McpAdmissionRuntime({"github": FakeClient([[tool]])}, policy)

    [definition] = await runtime.discover()

    assert definition.requires_approval is False
    assert definition.mandatory_approval is False


@pytest.mark.asyncio
async def test_discovery_allow_is_audited_with_policy_epoch():
    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient([[tool], [tool]])
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        requires_approval=False,
    )
    store = PolicyStore(AgentPolicy())
    runtime = McpAdmissionRuntime({"github": client}, policy, policy_store=store)

    await runtime.discover()

    entries = [
        entry
        for entry in store.get_audit_log().get_entries()
        if entry.event == "tool_decision"
    ]
    assert entries
    assert all("policy_epoch" in entry.details for entry in entries)
    assert any(
        entry.decision == "allow"
        and entry.tool_name == "mcp__github__search"
        for entry in entries
    )


@pytest.mark.asyncio
async def test_contract_pin_failure_is_audited_as_deny():
    tool = FakeTool("search", OBJECT_SCHEMA, description="changed before boot")
    policy = McpAdmissionPolicy(
        allowed_servers={"github"},
        allowed_tools={"github": {"search"}},
        expected_contract_sha256={"github": {"search": "0" * 64}},
    )
    store = PolicyStore(AgentPolicy())
    runtime = McpAdmissionRuntime(
        {"github": FakeClient([[tool]])}, policy, policy_store=store
    )

    with pytest.raises(McpContractPinMismatchError):
        await runtime.discover()

    denies = [
        entry
        for entry in store.get_audit_log().get_entries()
        if entry.event == "tool_decision" and entry.decision == "deny"
    ]
    assert denies
    assert all("policy_epoch" in entry.details for entry in denies)


@pytest.mark.asyncio
async def test_contract_drift_on_execute_is_audited_as_deny():
    before = FakeTool(
        "search", {"type": "object", "properties": {"q": {"type": "string"}}}
    )
    after = FakeTool(
        "search", {"type": "object", "properties": {"q": {"type": "integer"}}}
    )
    client = FakeClient([[before], [after]])
    store = PolicyStore(AgentPolicy())
    runtime = McpAdmissionRuntime(
        {"github": client}, allow("github", "search"), policy_store=store
    )
    await runtime.discover()

    result = await runtime.execute("mcp__github__search", {"q": "x"})

    assert result.error == "mcp_schema_drift"
    denies = [
        entry
        for entry in store.get_audit_log().get_entries()
        if entry.event == "tool_decision" and entry.decision == "deny"
    ]
    assert denies
    assert all("policy_epoch" in entry.details for entry in denies)


@pytest.mark.asyncio
async def test_broken_audit_backend_does_not_break_admission():
    class BrokenAuditLog(AuditLog):
        async def append(self, entry):  # type: ignore[override]
            raise RuntimeError("audit backend unavailable")

    tool = FakeTool("search", OBJECT_SCHEMA)
    client = FakeClient(
        [[tool], [tool]],
        result=FakeCallToolResult(content=[FakeTextContent("ok")]),
    )
    store = PolicyStore(AgentPolicy(), BrokenAuditLog())
    runtime = McpAdmissionRuntime(
        {"github": client}, allow("github", "search"), policy_store=store
    )

    [definition] = await runtime.discover()
    result = await runtime.execute("mcp__github__search", {})

    assert definition.name == "mcp__github__search"
    assert result.error is None
    assert client.call_calls == [("search", {})]


def test_list_tools_before_discover_raises_with_guidance():
    client = FakeClient([[FakeTool("search", OBJECT_SCHEMA)]])
    runtime = McpAdmissionRuntime({"github": client}, allow("github", "search"))

    assert runtime.is_discovered is False
    with pytest.raises(McpAdmissionError, match="discover"):
        runtime.list_tools()

    # Fail-loud must not smuggle in hidden synchronous network I/O.
    assert client.list_calls == 0


def test_constructing_agent_runtime_before_discover_fails_loudly():
    client = FakeClient([[FakeTool("search", OBJECT_SCHEMA)]])
    mcp = McpAdmissionRuntime({"github": client}, allow("github", "search"))

    # AgentRuntime snapshots tool definitions at construction; an
    # undiscovered MCP runtime must surface the mistake here rather than
    # silently reporting every MCP tool as ``unknown_tool`` forever.
    with pytest.raises(McpAdmissionError, match="discover"):
        AgentRuntime(ScriptedLlm([]), mcp, SafetyLayer())

    assert client.list_calls == 0


@pytest.mark.asyncio
async def test_list_tools_after_discover_returns_admitted_tools():
    client = FakeClient([[FakeTool("search", OBJECT_SCHEMA)]])
    runtime = McpAdmissionRuntime({"github": client}, allow("github", "search"))

    discovered = await runtime.discover()

    assert runtime.is_discovered is True
    assert [definition.name for definition in runtime.list_tools()] == [
        "mcp__github__search"
    ]
    assert [definition.name for definition in discovered] == [
        "mcp__github__search"
    ]
