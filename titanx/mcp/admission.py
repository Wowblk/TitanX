"""Deny-by-default admission layer for Model Context Protocol tools.

This module deliberately depends only on TitanX and the Python standard
library.  An official ``mcp.ClientSession`` can be passed directly because the
adapter boundary is structural: anything with compatible ``list_tools`` and
``call_tool`` coroutines satisfies :class:`McpClientLike`.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ..types import ToolDefinition, ToolExecutionResult, ToolRuntime

if TYPE_CHECKING:
    from ..policy.policy_store import PolicyStore


_MISSING = object()
_MAX_DISCOVERY_PAGES = 100


class McpAdmissionError(RuntimeError):
    """Base class for MCP admission and contract-verification failures."""


class McpProtocolError(McpAdmissionError):
    """Raised when an MCP peer returns an unsupported object shape."""


class McpTransportError(McpAdmissionError):
    """Raised when discovery cannot communicate with an MCP peer."""


class McpAllowlistMismatchError(McpAdmissionError):
    """Raised when an explicitly allowlisted tool is not advertised."""


class McpNamespaceCollisionError(McpAdmissionError):
    """Raised when two admitted tools produce the same TitanX tool name."""


class McpSurfaceDriftError(McpAdmissionError):
    """Raised when a server adds or removes a tool after admission."""


class McpSchemaDriftError(McpAdmissionError):
    """Raised when an admitted tool changes its input schema after admission."""


class McpContractDriftError(McpAdmissionError):
    """Raised when an admitted tool changes its model-visible contract."""


class McpContractPinMismatchError(McpContractDriftError):
    """Raised when first contact does not match an administrator's pin."""


@runtime_checkable
class McpClientLike(Protocol):
    """Transport-independent subset implemented by official MCP sessions.

    The concrete return types intentionally remain ``Any``.  TitanX reads the
    official SDK's object attributes (``tools``, ``inputSchema``, ``content``,
    ``structuredContent``, and ``isError``), while also accepting equivalent
    mapping-shaped values from other transports and test doubles.
    """

    async def list_tools(self, *, cursor: str | None = None) -> Any:
        ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        ...


@dataclass(frozen=True)
class McpAdmissionPolicy:
    """Exact server-and-tool allowlist for MCP admission.

    Both layers must match.  Merely allowing a server does not expose any of
    its tools, and mentioning tools for a server that is not itself allowed is
    rejected as a configuration error.  The zero-argument policy therefore
    admits nothing.
    """

    allowed_servers: frozenset[str] = field(default_factory=frozenset)
    allowed_tools: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # Optional administrator-approved full-contract hashes, keyed by
    # server/tool.  An allowlisted tool without a pin uses a process-local
    # trust-on-first-use baseline; a pinned tool is verified on first contact
    # as well as on every later revalidation.
    expected_contract_sha256: Mapping[str, Mapping[str, str]] = field(
        default_factory=dict
    )
    requires_approval: bool = True
    requires_sanitization: bool = True
    call_timeout_seconds: float = 30.0
    discovery_timeout_seconds: float = 30.0
    max_discovered_tools: int = 1_000
    max_contract_bytes: int = 1_000_000
    max_result_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if isinstance(self.allowed_servers, str):
            raise ValueError("allowed_servers must be a collection of names")
        servers = frozenset(self.allowed_servers)
        for server_id in servers:
            _validate_name(server_id, "server id")

        tools: dict[str, frozenset[str]] = {}
        for server_id, names in self.allowed_tools.items():
            _validate_name(server_id, "server id")
            if isinstance(names, str):
                raise ValueError(
                    f"allowed_tools[{server_id!r}] must be a collection of names"
                )
            frozen_names = frozenset(names)
            for name in frozen_names:
                _validate_name(name, "tool name")
            tools[server_id] = frozen_names

        orphan_servers = sorted(set(tools) - servers)
        if orphan_servers:
            joined = ", ".join(repr(server) for server in orphan_servers)
            raise ValueError(
                "allowed_tools contains server ids that are not present in "
                f"allowed_servers: {joined}"
            )

        pins: dict[str, Mapping[str, str]] = {}
        for server_id, server_pins in self.expected_contract_sha256.items():
            _validate_name(server_id, "server id")
            if server_id not in servers:
                raise ValueError(
                    "expected_contract_sha256 contains server ids that are "
                    f"not present in allowed_servers: {server_id!r}"
                )
            if not isinstance(server_pins, Mapping):
                raise ValueError(
                    f"expected_contract_sha256[{server_id!r}] must be a mapping"
                )
            normalized_server_pins: dict[str, str] = {}
            for tool_name, fingerprint in server_pins.items():
                _validate_name(tool_name, "tool name")
                if tool_name not in tools.get(server_id, frozenset()):
                    raise ValueError(
                        "expected_contract_sha256 may only pin explicitly "
                        f"allowlisted tools: {server_id!r}/{tool_name!r}"
                    )
                normalized_server_pins[tool_name] = _normalize_sha256_pin(
                    fingerprint,
                    f"{server_id}/{tool_name}",
                )
            pins[server_id] = MappingProxyType(normalized_server_pins)

        if not isinstance(self.requires_approval, bool):
            raise ValueError("requires_approval must be a boolean")
        if not isinstance(self.requires_sanitization, bool):
            raise ValueError("requires_sanitization must be a boolean")

        normalized_timeouts: dict[str, float] = {}
        for field_name in ("call_timeout_seconds", "discovery_timeout_seconds"):
            timeout = getattr(self, field_name)
            if (
                isinstance(timeout, bool)
                or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout)
                or timeout <= 0
            ):
                raise ValueError(f"{field_name} must be a positive number")
            normalized_timeouts[field_name] = float(timeout)

        for field_name in (
            "max_discovered_tools",
            "max_contract_bytes",
            "max_result_bytes",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")

        object.__setattr__(self, "allowed_servers", servers)
        object.__setattr__(self, "allowed_tools", MappingProxyType(tools))
        object.__setattr__(
            self,
            "expected_contract_sha256",
            MappingProxyType(pins),
        )
        for field_name, timeout in normalized_timeouts.items():
            object.__setattr__(self, field_name, timeout)

    def admits(self, server_id: str, tool_name: str) -> bool:
        """Return whether both exact allowlist layers admit a tool."""

        return (
            server_id in self.allowed_servers
            and tool_name in self.allowed_tools.get(server_id, frozenset())
        )


@dataclass(frozen=True)
class McpNormalizedResult:
    """Safe subset extracted from an MCP ``CallToolResult``.

    Result-level ``_meta`` is never read or serialized.  TitanX's string-only
    ``ToolExecutionResult`` receives a deterministic JSON envelope so text,
    structured content, and the MCP error bit all survive the adapter boundary.
    """

    text: str
    structured_content: Any | None
    is_error: bool

    def to_output(self) -> str:
        return _canonical_json(
            {
                "is_error": self.is_error,
                "structured_content": self.structured_content,
                "text": self.text,
            }
        )


@dataclass(frozen=True)
class _Binding:
    server_id: str
    remote_name: str


@dataclass(frozen=True)
class _DiscoverySnapshot:
    surface: frozenset[tuple[str, str]]
    input_schema_fingerprints: Mapping[tuple[str, str], str]
    contract_fingerprints: Mapping[tuple[str, str], str]
    definitions: tuple[ToolDefinition, ...]
    bindings: Mapping[str, _Binding]
    missing_allowed: frozenset[tuple[str, str]]


def normalize_input_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic, JSON-compatible copy of an MCP input schema."""

    if not isinstance(schema, Mapping):
        raise McpProtocolError("MCP tool inputSchema must be a mapping")
    normalized = _normalize_json_value(schema, path="inputSchema")
    # The root was checked above, so this cast is guaranteed by construction.
    return dict(normalized)


def input_schema_fingerprint(schema: Mapping[str, Any]) -> str:
    """Compute the SHA-256 digest of a normalized MCP input schema."""

    normalized = normalize_input_schema(schema)
    canonical = _canonical_json(normalized).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def tool_contract_fingerprint(
    *,
    name: str,
    title: str | None,
    description: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any] | None,
) -> str:
    """Fingerprint every MCP contract field TitanX may expose or enforce."""

    contract = {
        "description": description,
        "inputSchema": normalize_input_schema(input_schema),
        "name": name,
        "outputSchema": (
            normalize_input_schema(output_schema)
            if output_schema is not None
            else None
        ),
        "title": title,
    }
    return hashlib.sha256(_canonical_json(contract).encode("utf-8")).hexdigest()


def extract_mcp_result(result: Any) -> McpNormalizedResult:
    """Extract only text, structured content, and ``isError`` from a result."""

    raw_is_error = _read_field(result, "isError", "is_error", default=False)
    if not isinstance(raw_is_error, bool):
        raise McpProtocolError("MCP result isError must be a boolean")

    raw_content = _read_field(result, "content", default=[])
    if raw_content is None:
        raw_content = []
    if not isinstance(raw_content, Sequence) or isinstance(
        raw_content, (str, bytes, bytearray)
    ):
        raise McpProtocolError("MCP result content must be a sequence")

    text_parts: list[str] = []
    for index, block in enumerate(raw_content):
        block_type = _read_field(block, "type", default=None)
        if block_type != "text":
            # TitanX's core result type is text-only.  Non-text MCP content is
            # deliberately not model-dumped because doing so would also copy
            # transport metadata into the LLM-visible result.
            continue
        block_text = _read_field(block, "text", default=_MISSING)
        if not isinstance(block_text, str):
            raise McpProtocolError(
                f"MCP text content at index {index} must contain string text"
            )
        text_parts.append(block_text)

    structured = _read_field(
        result,
        "structuredContent",
        "structured_content",
        default=None,
    )
    if structured is not None:
        structured = _normalize_json_value(
            structured,
            path="structuredContent",
        )

    return McpNormalizedResult(
        text="\n".join(text_parts),
        structured_content=structured,
        is_error=raw_is_error,
    )


class McpAdmissionRuntime(ToolRuntime):
    """Expose explicitly admitted MCP tools through TitanX ``ToolRuntime``.

    Call :meth:`discover` once before handing this runtime to an agent so its
    synchronous :meth:`list_tools` method can return the cached definitions.
    By default, every :meth:`execute` re-lists the full advertised surface of
    every participating server and refuses the call if any tool was added or
    removed, or if an admitted model-visible contract changed.
    """

    def __init__(
        self,
        clients: Mapping[str, McpClientLike],
        policy: McpAdmissionPolicy | None = None,
        *,
        revalidate_on_execute: bool = True,
        policy_store: PolicyStore | None = None,
    ) -> None:
        self._clients = dict(clients)
        for server_id in self._clients:
            _validate_name(server_id, "server id")
        self._policy = policy or McpAdmissionPolicy()
        self._revalidate_on_execute = revalidate_on_execute
        # Optional bridge into the shared authorisation plane. When supplied,
        # admitted tools are reflected onto the policy allowlist so
        # ``PolicyStore.check_tool_call`` is the single decision point, and MCP
        # admission decisions join the store's audit trail and epoch. ``None``
        # (the default) preserves fully standalone operation.
        self._policy_store = policy_store
        self._snapshot: _DiscoverySnapshot | None = None
        self._lock = asyncio.Lock()

    @property
    def is_discovered(self) -> bool:
        return self._snapshot is not None

    async def discover(self) -> list[ToolDefinition]:
        """Verify optional pins, capture a baseline, and cache definitions."""

        async with self._lock:
            if self._snapshot is None:
                try:
                    snapshot = await self._capture_snapshot_bounded()
                    self._raise_for_missing_allowed(snapshot)
                except McpAdmissionError as exc:
                    await self._audit_admission(
                        "deny", tool_name=None, reason=str(exc),
                        details={"error": type(exc).__name__},
                    )
                    raise
                await self._activate(snapshot)
                self._snapshot = snapshot
            return self._clone_definitions(self._snapshot.definitions)

    async def verify_surface(self) -> None:
        """Re-list servers and raise if the cached contract baseline drifted."""

        async with self._lock:
            if self._snapshot is None:
                try:
                    snapshot = await self._capture_snapshot_bounded()
                    self._raise_for_missing_allowed(snapshot)
                except McpAdmissionError as exc:
                    await self._audit_admission(
                        "deny", tool_name=None, reason=str(exc),
                        details={"error": type(exc).__name__},
                    )
                    raise
                await self._activate(snapshot)
                self._snapshot = snapshot
                return
            try:
                current = await self._capture_snapshot_bounded()
                self._assert_unchanged(self._snapshot, current)
            except McpAdmissionError as exc:
                await self._audit_admission(
                    "deny", tool_name=None, reason=str(exc),
                    details={"error": type(exc).__name__},
                )
                raise

    def list_tools(self) -> list[ToolDefinition]:
        """Return admitted definitions cached by :meth:`discover`.

        Raises:
            McpAdmissionError: if :meth:`discover` has not completed. An empty
                list would be indistinguishable from "the allowlist admitted no
                tools", so an undiscovered runtime fails loudly instead of
                silently exposing zero MCP tools. A synchronous caller still
                never triggers hidden network I/O — it must ``await
                discover()`` first.
        """

        if self._snapshot is None:
            raise McpAdmissionError(
                "McpAdmissionRuntime.list_tools() was called before discover(); "
                "await McpAdmissionRuntime.discover() once before handing this "
                "runtime to an AgentRuntime, otherwise MCP tools would be "
                "silently reported as unknown_tool."
            )
        return self._clone_definitions(self._snapshot.definitions)

    async def execute(
        self,
        name: str,
        params: dict[str, Any],
    ) -> ToolExecutionResult:
        async with self._lock:
            newly_discovered = False
            if self._snapshot is None:
                try:
                    snapshot = await self._capture_snapshot_bounded()
                    self._raise_for_missing_allowed(snapshot)
                except McpAdmissionError as exc:
                    await self._audit_admission(
                        "deny", tool_name=name, reason=str(exc),
                        details={"error": type(exc).__name__},
                    )
                    return self._admission_failure(exc)
                await self._activate(snapshot)
                self._snapshot = snapshot
                newly_discovered = True

            if self._revalidate_on_execute and not newly_discovered:
                try:
                    current = await self._capture_snapshot_bounded()
                    self._assert_unchanged(self._snapshot, current)
                except McpAdmissionError as exc:
                    await self._audit_admission(
                        "deny", tool_name=name, reason=str(exc),
                        details={"error": type(exc).__name__},
                    )
                    return self._admission_failure(exc)

            binding = self._snapshot.bindings.get(name)
            if binding is None:
                return ToolExecutionResult(
                    output=f"Unknown MCP tool: {name}",
                    error="unknown_tool",
                )

            client = self._clients[binding.server_id]
            remote_name = binding.remote_name

        # The lock guards discovery/revalidation and the binding lookup, not
        # the network round-trip. Holding it across ``call_tool`` serialized
        # every MCP tool on this runtime, so one slow (or hung-until-timeout)
        # server stalled the rest. ``binding``/``client`` are captured above;
        # everything below is pure or awaits only the remote call.
        try:
            # The structural client boundary is not assumed to be
            # well-behaved.  A shallow ``dict(params)`` would still let a
            # client mutate nested lists/dicts that belong to AgentState.
            arguments = _normalize_json_value(params, path="arguments")
        except McpProtocolError as exc:
            return ToolExecutionResult(
                output=f"Invalid MCP tool arguments: {exc}",
                error="mcp_invalid_arguments",
            )
        try:
            raw_result = await asyncio.wait_for(
                client.call_tool(
                    remote_name,
                    arguments=arguments,
                ),
                timeout=self._policy.call_timeout_seconds,
            )
        except TimeoutError:
            return ToolExecutionResult(
                output=(
                    "MCP tool call exceeded "
                    f"{self._policy.call_timeout_seconds:g} seconds"
                ),
                error="mcp_timeout",
            )
        except asyncio.CancelledError:
            # Cancellation belongs to the host/runtime lifecycle.  The
            # AgentRuntime closes the tool-call protocol and advances its
            # cursor, so swallowing it here would corrupt resume semantics.
            raise
        except Exception as exc:
            return ToolExecutionResult(
                output=(
                    "MCP tool call failed before a valid result was "
                    f"received ({type(exc).__name__})"
                ),
                error="mcp_transport_error",
            )

        try:
            normalized = extract_mcp_result(raw_result)
        except McpProtocolError as exc:
            return ToolExecutionResult(
                output=f"Invalid MCP tool result: {exc}",
                error="mcp_invalid_result",
            )

        normalized_output = normalized.to_output()
        if len(normalized_output.encode("utf-8")) > self._policy.max_result_bytes:
            return ToolExecutionResult(
                output="MCP tool result exceeded the configured size limit",
                error="mcp_result_too_large",
            )

        return ToolExecutionResult(
            output=normalized_output,
            error="mcp_tool_error" if normalized.is_error else None,
        )

    async def _capture_snapshot_bounded(self) -> _DiscoverySnapshot:
        """Bound the whole discovery transaction, not only each page.

        Per-page timeouts alone allow a malicious peer to hold the shared MCP
        lock for ``pages * timeout``.  One outer deadline constrains the full
        revalidation and cancels the in-flight transport coroutine on expiry.
        """
        try:
            return await asyncio.wait_for(
                self._capture_snapshot(),
                timeout=self._policy.discovery_timeout_seconds,
            )
        except TimeoutError as exc:
            raise McpTransportError(
                "MCP tool discovery exceeded the total timeout"
            ) from exc

    async def _capture_snapshot(self) -> _DiscoverySnapshot:
        surface: set[tuple[str, str]] = set()
        input_schema_fingerprints: dict[tuple[str, str], str] = {}
        contract_fingerprints: dict[tuple[str, str], str] = {}
        definitions: list[ToolDefinition] = []
        bindings: dict[str, _Binding] = {}
        namespace_origins: dict[str, tuple[str, str]] = {}
        missing_allowed: set[tuple[str, str]] = set()

        for server_id in sorted(self._policy.allowed_servers):
            allowed_names = self._policy.allowed_tools.get(
                server_id,
                frozenset(),
            )
            # A server allowlist entry alone grants nothing and does not even
            # trigger network discovery.  Tools must be explicitly enumerated.
            if not allowed_names:
                continue

            client = self._clients.get(server_id)
            if client is None:
                raise McpAllowlistMismatchError(
                    f"allowlisted MCP server {server_id!r} has no client"
                )

            remote_tools = await self._list_all_tools(server_id, client)
            if len(surface) + len(remote_tools) > self._policy.max_discovered_tools:
                raise McpProtocolError(
                    "MCP discovery exceeded the configured tool-count limit"
                )
            advertised_names: set[str] = set()
            for remote_tool in remote_tools:
                remote_name = _read_field(remote_tool, "name", default=_MISSING)
                if not isinstance(remote_name, str) or not remote_name:
                    raise McpProtocolError(
                        f"MCP server {server_id!r} advertised a tool without a name"
                    )
                try:
                    _validate_name(remote_name, "tool name")
                except ValueError as exc:
                    raise McpProtocolError(
                        f"MCP server {server_id!r} advertised an invalid tool name"
                    ) from exc

                origin = (server_id, remote_name)
                if remote_name in advertised_names:
                    raise McpProtocolError(
                        f"MCP server {server_id!r} advertised duplicate tool "
                        f"{remote_name!r}"
                    )
                advertised_names.add(remote_name)
                surface.add(origin)

                if remote_name not in allowed_names:
                    continue

                raw_schema = _read_field(
                    remote_tool,
                    "inputSchema",
                    "input_schema",
                    default=_MISSING,
                )
                if raw_schema is _MISSING:
                    raise McpProtocolError(
                        f"MCP tool {server_id!r}/{remote_name!r} has no inputSchema"
                    )
                normalized_schema = normalize_input_schema(raw_schema)
                schema_fingerprint = input_schema_fingerprint(normalized_schema)
                input_schema_fingerprints[origin] = schema_fingerprint

                description = _read_field(
                    remote_tool,
                    "description",
                    default="",
                )
                if description is None:
                    description = ""
                if not isinstance(description, str):
                    raise McpProtocolError(
                        f"MCP tool {server_id!r}/{remote_name!r} has a "
                        "non-string description"
                    )

                title = _read_field(remote_tool, "title", default=None)
                if title is not None and not isinstance(title, str):
                    raise McpProtocolError(
                        f"MCP tool {server_id!r}/{remote_name!r} has a "
                        "non-string title"
                    )

                raw_output_schema = _read_field(
                    remote_tool,
                    "outputSchema",
                    "output_schema",
                    default=None,
                )
                normalized_output_schema = (
                    normalize_input_schema(raw_output_schema)
                    if raw_output_schema is not None
                    else None
                )
                normalized_contract = {
                    "description": description,
                    "inputSchema": normalized_schema,
                    "name": remote_name,
                    "outputSchema": normalized_output_schema,
                    "title": title,
                }
                encoded_contract = _canonical_json(normalized_contract).encode(
                    "utf-8"
                )
                if len(encoded_contract) > self._policy.max_contract_bytes:
                    raise McpProtocolError(
                        "MCP tool contract exceeded the configured size limit: "
                        f"{server_id!r}/{remote_name!r}"
                    )
                contract_fingerprint = hashlib.sha256(
                    encoded_contract
                ).hexdigest()
                expected_fingerprint = self._policy.expected_contract_sha256.get(
                    server_id,
                    {},
                ).get(remote_name)
                if expected_fingerprint is not None and not hmac.compare_digest(
                    expected_fingerprint,
                    contract_fingerprint,
                ):
                    raise McpContractPinMismatchError(
                        "MCP tool contract did not match the configured SHA-256 "
                        f"pin: {server_id!r}/{remote_name!r}"
                    )
                contract_fingerprints[origin] = contract_fingerprint

                namespaced_name = _namespaced_name(server_id, remote_name)
                previous = namespace_origins.get(namespaced_name)
                if previous is not None and previous != origin:
                    raise McpNamespaceCollisionError(
                        f"MCP namespace collision for {namespaced_name!r}: "
                        f"{previous!r} and {origin!r}"
                    )
                namespace_origins[namespaced_name] = origin
                bindings[namespaced_name] = _Binding(
                    server_id=server_id,
                    remote_name=remote_name,
                )
                definitions.append(
                    ToolDefinition(
                        name=namespaced_name,
                        description=description,
                        parameters=normalized_schema,
                        requires_approval=self._policy.requires_approval,
                        requires_sanitization=self._policy.requires_sanitization,
                        # MCP's own approval requirement must not be waivable
                        # by the coarse host-level auto_approve_tools switch.
                        mandatory_approval=self._policy.requires_approval,
                        metadata={
                            "source": "mcp",
                            "mcp_server_id": server_id,
                            "mcp_tool_name": remote_name,
                            "mcp_title": title,
                            "mcp_output_schema": normalized_output_schema,
                            "mcp_schema_sha256": schema_fingerprint,
                            "mcp_contract_sha256": contract_fingerprint,
                            "mcp_contract_trust": (
                                "pinned"
                                if expected_fingerprint is not None
                                else "tofu"
                            ),
                        },
                    )
                )

            missing_allowed.update(
                (server_id, tool_name)
                for tool_name in allowed_names - advertised_names
            )

        definitions.sort(key=lambda definition: definition.name)
        return _DiscoverySnapshot(
            surface=frozenset(surface),
            input_schema_fingerprints=MappingProxyType(
                input_schema_fingerprints
            ),
            contract_fingerprints=MappingProxyType(contract_fingerprints),
            definitions=tuple(definitions),
            bindings=MappingProxyType(bindings),
            missing_allowed=frozenset(missing_allowed),
        )

    async def _list_all_tools(
        self,
        server_id: str,
        client: McpClientLike,
    ) -> list[Any]:
        collected: list[Any] = []
        seen_cursors: set[str] = set()
        cursor: str | None = None

        for page_index in range(_MAX_DISCOVERY_PAGES):
            try:
                if page_index == 0:
                    page = await asyncio.wait_for(
                        client.list_tools(),
                        timeout=self._policy.call_timeout_seconds,
                    )
                else:
                    page = await asyncio.wait_for(
                        client.list_tools(cursor=cursor),
                        timeout=self._policy.call_timeout_seconds,
                    )
            except Exception as exc:
                raise McpTransportError(
                    f"failed to list tools from MCP server {server_id!r} "
                    f"({type(exc).__name__})"
                ) from exc

            tools = _read_field(page, "tools", default=_MISSING)
            if not isinstance(tools, Sequence) or isinstance(
                tools, (str, bytes, bytearray)
            ):
                raise McpProtocolError(
                    f"MCP server {server_id!r} returned an invalid tools page"
                )
            if len(collected) + len(tools) > self._policy.max_discovered_tools:
                raise McpProtocolError(
                    "MCP discovery exceeded the configured tool-count limit"
                )
            collected.extend(tools)

            raw_cursor = _read_field(
                page,
                "nextCursor",
                "next_cursor",
                default=None,
            )
            if raw_cursor is None or raw_cursor == "":
                return collected
            if not isinstance(raw_cursor, str):
                raise McpProtocolError(
                    f"MCP server {server_id!r} returned a non-string cursor"
                )
            if raw_cursor in seen_cursors:
                raise McpProtocolError(
                    f"MCP server {server_id!r} repeated discovery cursor"
                )
            seen_cursors.add(raw_cursor)
            cursor = raw_cursor

        raise McpProtocolError(
            f"MCP server {server_id!r} exceeded {_MAX_DISCOVERY_PAGES} "
            "tool-list pages"
        )

    @staticmethod
    def _raise_for_missing_allowed(snapshot: _DiscoverySnapshot) -> None:
        if not snapshot.missing_allowed:
            return
        rendered = ", ".join(
            f"{server_id}/{tool_name}"
            for server_id, tool_name in sorted(snapshot.missing_allowed)
        )
        raise McpAllowlistMismatchError(
            f"allowlisted MCP tools were not advertised: {rendered}"
        )

    @staticmethod
    def _assert_unchanged(
        expected: _DiscoverySnapshot,
        current: _DiscoverySnapshot,
    ) -> None:
        if current.surface != expected.surface:
            added = sorted(current.surface - expected.surface)
            removed = sorted(expected.surface - current.surface)
            raise McpSurfaceDriftError(
                "MCP tool surface changed after admission "
                f"(added={added!r}, removed={removed!r})"
            )

        changed = sorted(
            origin
            for origin, fingerprint in expected.input_schema_fingerprints.items()
            if current.input_schema_fingerprints.get(origin) != fingerprint
        )
        if changed:
            raise McpSchemaDriftError(
                f"MCP input schema changed after admission: {changed!r}"
            )

        contract_changed = sorted(
            origin
            for origin, fingerprint in expected.contract_fingerprints.items()
            if current.contract_fingerprints.get(origin) != fingerprint
        )
        if contract_changed:
            raise McpContractDriftError(
                f"MCP tool contract changed after admission: {contract_changed!r}"
            )

    @staticmethod
    def _admission_failure(exc: McpAdmissionError) -> ToolExecutionResult:
        if isinstance(exc, McpContractPinMismatchError):
            error = "mcp_contract_pin_mismatch"
        elif isinstance(exc, McpSchemaDriftError):
            error = "mcp_schema_drift"
        elif isinstance(exc, McpContractDriftError):
            error = "mcp_contract_drift"
        elif isinstance(exc, McpSurfaceDriftError):
            error = "mcp_surface_drift"
        elif isinstance(exc, McpTransportError):
            error = "mcp_discovery_error"
        else:
            error = "mcp_admission_error"
        return ToolExecutionResult(
            output=f"MCP execution refused: {exc}",
            error=error,
        )

    async def _activate(self, snapshot: _DiscoverySnapshot) -> None:
        """Reflect admitted tools into the shared policy plane and audit allows.

        Registration goes through the validated, audited ``allow_tools``
        mutation rather than touching policy internals, so a wired store keeps
        a single decision point at ``PolicyStore.check_tool_call``. Both the
        registration and the audit writes are best-effort: a broken store or
        audit backend must never break MCP admission.
        """
        store = self._policy_store
        if store is not None:
            try:
                await store.allow_tools(
                    [definition.name for definition in snapshot.definitions],
                    reason="MCP admission",
                    actor="host",
                )
            except Exception:
                pass
        for definition in snapshot.definitions:
            metadata = definition.metadata
            await self._audit_admission(
                "allow",
                tool_name=definition.name,
                reason="MCP tool admitted",
                details={
                    "source": "mcp",
                    "mcp_server_id": metadata.get("mcp_server_id"),
                    "mcp_tool_name": metadata.get("mcp_tool_name"),
                    "mcp_contract_trust": metadata.get("mcp_contract_trust"),
                },
            )

    async def _audit_admission(
        self,
        decision: str,
        *,
        tool_name: str | None,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record an admission decision on the shared audit trail (best-effort).

        Never raises: the append is wrapped so an audit backend failure cannot
        break admission or silently change the decision. ``policy_epoch`` ties
        the record to the exact policy revision that was in force.
        """
        store = self._policy_store
        if store is None:
            return
        merged: dict[str, Any] = {"policy_epoch": store.epoch}
        if details:
            merged.update(details)
        try:
            from ..policy.types import AuditEntry
            await store.get_audit_log().append(AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event="tool_decision",
                actor="host",
                reason=reason,
                tool_name=tool_name,
                decision=decision,  # type: ignore[arg-type]
                details=merged,
            ))
        except Exception:
            pass

    @staticmethod
    def _clone_definitions(
        definitions: tuple[ToolDefinition, ...],
    ) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name=definition.name,
                description=definition.description,
                parameters=_normalize_json_value(
                    definition.parameters,
                    path="parameters",
                ),
                requires_approval=definition.requires_approval,
                requires_sanitization=definition.requires_sanitization,
                mandatory_approval=definition.mandatory_approval,
                metadata=_normalize_json_value(
                    definition.metadata,
                    path="metadata",
                ),
            )
            for definition in definitions
        ]


def _validate_name(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"MCP {label} must be a non-empty string")
    if len(value) > 128:
        raise ValueError(f"MCP {label} must be at most 128 characters")
    if any(
        not (
            character.isascii()
            and (character.isalnum() or character in "_.-")
        )
        for character in value
    ):
        raise ValueError(
            f"MCP {label} may contain only ASCII letters, digits, '_', '-', or '.'"
        )


def _normalize_sha256_pin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"contract SHA-256 pin for {label} must be a string")
    normalized = value.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(
            f"contract SHA-256 pin for {label} must be exactly 64 hex characters"
        )
    return normalized


def _namespaced_name(server_id: str, tool_name: str) -> str:
    return f"mcp__{server_id}__{tool_name}"


def _read_field(
    value: Any,
    *names: str,
    default: Any = _MISSING,
) -> Any:
    if isinstance(value, Mapping):
        for name in names:
            if name in value:
                return value[name]
    else:
        for name in names:
            try:
                return getattr(value, name)
            except AttributeError:
                continue
    if default is _MISSING:
        joined = "/".join(names)
        raise McpProtocolError(f"MCP object is missing required field {joined}")
    return default


def _normalize_json_value(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        if any(not isinstance(key, str) for key in value):
            raise McpProtocolError(f"{path} contains a non-string key")
        for key in sorted(value):
            normalized[key] = _normalize_json_value(
                value[key],
                path=f"{path}.{key}",
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return [
            _normalize_json_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise McpProtocolError(f"{path} contains a non-finite number")
        return value
    raise McpProtocolError(
        f"{path} contains non-JSON value of type {type(value).__name__}"
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


__all__ = [
    "McpAdmissionError",
    "McpAdmissionPolicy",
    "McpAdmissionRuntime",
    "McpAllowlistMismatchError",
    "McpClientLike",
    "McpContractPinMismatchError",
    "McpContractDriftError",
    "McpNamespaceCollisionError",
    "McpNormalizedResult",
    "McpProtocolError",
    "McpSchemaDriftError",
    "McpSurfaceDriftError",
    "McpTransportError",
    "extract_mcp_result",
    "input_schema_fingerprint",
    "normalize_input_schema",
    "tool_contract_fingerprint",
]
