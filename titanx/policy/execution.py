"""Operation-bound authorization for one runtime on one asyncio event loop.

The host owns this guard. Model-visible state is never an approval source.
This is an in-process admission boundary, not a durable execution ledger or
an isolation mechanism for untrusted Python plugins.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Literal
from uuid import uuid4

from jsonschema import Draft202012Validator
from jsonschema.validators import validator_for
from referencing import Registry

from .policy_store import PolicyStore
from .types import PolicyCheckResult
from ..types import AgentConfig, PendingApproval, ToolCall, ToolDefinition


class ExecutionAuthorizationError(ValueError):
    """A stable, non-sensitive denial reason; never includes argument values."""


@dataclass(frozen=True)
class ExecutionGuardOptions:
    approval_ttl_seconds: float = 300.0
    max_argument_bytes: int = 1_000_000
    max_json_depth: int = 32
    max_json_nodes: int = 10_000

    def __post_init__(self) -> None:
        ttl = self.approval_ttl_seconds
        if type(ttl) not in (int, float) or not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("approval_ttl_seconds must be finite and positive")
        for name in ("max_argument_bytes", "max_json_depth", "max_json_nodes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ToolIntent:
    execution_id: str
    run_id: str
    batch_id: str
    ordinal: int
    identity: tuple[str, str, str, str]
    tool_call_id: str
    tool_name: str
    contract_digest: str
    arguments_digest: str
    policy_epoch: int
    arguments_json: str = field(repr=False)

    def arguments(self) -> dict[str, Any]:
        """Return a fresh dispatch/UI copy of the approved JSON value."""
        return json.loads(self.arguments_json)


@dataclass(frozen=True)
class ApprovalGrant:
    intent: ToolIntent
    actor: str
    expires_at: float
    status: Literal["approved", "consumed", "revoked"] = "approved"


class ExecutionGuard:
    """Bind each approved tool call to the run that authorised it.

    Identity is **not** authenticated here. The ``(thread_id, session_id,
    user_id, channel)`` tuple is read verbatim from the host-supplied
    ``AgentConfig``; this guard only uses it to *bind* an approval to a run
    and to detect a mid-run identity change (``identity_changed``) — an
    anti-replay/consistency check, not caller authentication. Authenticating
    and authorising the caller, and populating those ``AgentConfig`` fields
    from trusted state, is the host's responsibility.
    """

    def __init__(
        self, policy_store: PolicyStore, tools: list[ToolDefinition],
        options: ExecutionGuardOptions | None = None, *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.options = options or ExecutionGuardOptions()
        self._policy = policy_store
        self._clock = clock
        self._contracts: dict[str, str] = {}
        self._validators: dict[str, Any] = {}
        for tool in tools:
            if not isinstance(tool.name, str) or not tool.name or tool.name in self._contracts:
                raise ValueError("tool names must be nonempty and unique")
            if type(tool.requires_approval) is not bool or type(tool.requires_sanitization) is not bool:
                raise ValueError("tool approval and sanitization flags must be boolean")
            contract = self._contract(tool)
            schema = json.loads(contract)["parameters"]
            cls = validator_for(schema, default=Draft202012Validator)
            if isinstance(schema, dict) and "$schema" in schema:
                cls = validator_for(schema, default=None)
                if cls is None:
                    raise ValueError("unsupported JSON Schema dialect")
            cls.check_schema(schema)
            # Registry() has no retrieval callback: validation must never
            # fetch a remote schema or read files while checking arguments.
            self._validators[tool.name] = cls(schema, registry=Registry())
            self._contracts[tool.name] = contract
        self._identity: tuple[str, str, str, str] | None = None
        self._run_id = ""
        self._batch_id = ""
        self._intents: dict[int, ToolIntent] = {}
        self._grants: dict[str, ApprovalGrant] = {}
        self._admitted: set[str] = set()
        self._pending: ToolIntent | None = None

    def _json(self, value: Any) -> str:
        remaining = self.options.max_json_nodes
        text_bytes = 0

        def visit(item: Any, depth: int) -> None:
            nonlocal remaining, text_bytes
            remaining -= 1
            if remaining < 0 or depth > self.options.max_json_depth:
                raise ExecutionAuthorizationError("json_structure_limit")
            if type(item) is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ExecutionAuthorizationError("invalid_json_key")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            elif type(item) is list:
                for child in item:
                    visit(child, depth + 1)
            elif type(item) is str:
                text_bytes += len(item.encode("utf-8"))
                if text_bytes > self.options.max_argument_bytes:
                    raise ExecutionAuthorizationError("json_size_limit")
            elif type(item) is float:
                if not math.isfinite(item):
                    raise ExecutionAuthorizationError("invalid_json_number")
            elif item is not None and type(item) not in (bool, int):
                raise ExecutionAuthorizationError("invalid_json_value")

        try:
            visit(value, 0)
            result = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False)
            if len(result.encode("utf-8")) > self.options.max_argument_bytes:
                raise ExecutionAuthorizationError("json_size_limit")
            return result
        except ExecutionAuthorizationError:
            raise
        except (ValueError, TypeError, RecursionError):
            raise ExecutionAuthorizationError("invalid_json_value") from None

    def _contract(self, tool: ToolDefinition) -> str:
        return self._json({
            "name": tool.name, "description": tool.description,
            "parameters": tool.parameters, "requires_approval": tool.requires_approval,
            "requires_sanitization": tool.requires_sanitization,
            "mandatory_approval": tool.mandatory_approval, "metadata": tool.metadata,
        })

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _binding(config: AgentConfig) -> tuple[str, str, str, str]:
        return config.thread_id, config.session_id, config.user_id, config.channel

    def start_run(self, config: AgentConfig) -> None:
        self._identity = self._binding(config)
        self._run_id = str(uuid4())
        self.start_batch()

    def start_batch(self) -> None:
        self._batch_id = str(uuid4())
        self._intents.clear()
        self._grants.clear()
        self._admitted.clear()
        self._pending = None

    def revoke_pending(self) -> None:
        if self._pending is not None:
            self._revoke(self._pending.execution_id)
        self._pending = None

    def _revoke(self, execution_id: str) -> None:
        grant = self._grants.get(execution_id)
        if grant is not None and grant.status == "approved":
            self._grants[execution_id] = replace(grant, status="revoked")

    def revoke_approval(self, execution_id: str) -> str:
        grant = self._grants.get(execution_id)
        if grant is None:
            raise ExecutionAuthorizationError("unknown_approval")
        if execution_id in self._admitted:
            raise ExecutionAuthorizationError("operation_already_admitted")
        self._revoke(execution_id)
        return grant.intent.tool_call_id

    def original_call(self, ordinal: int) -> ToolCall | None:
        intent = self._intents.get(ordinal)
        if intent is None:
            return None
        return ToolCall(intent.tool_call_id, intent.tool_name, intent.arguments())

    def definition(self, name: str) -> ToolDefinition | None:
        if not isinstance(name, str):
            return None
        contract = self._contracts.get(name)
        return ToolDefinition(**json.loads(contract)) if contract is not None else None

    def _check_contract(self, name: str, current: list[ToolDefinition]) -> None:
        matches = [tool for tool in current if tool.name == name]
        if len(matches) != 1 or self._contract(matches[0]) != self._contracts.get(name):
            raise ExecutionAuthorizationError("tool_contract_changed")

    def _check_operation(self, intent: ToolIntent, call: ToolCall, ordinal: int,
                         config: AgentConfig, current: list[ToolDefinition]) -> None:
        if self._binding(config) != intent.identity or self._identity != intent.identity:
            raise ExecutionAuthorizationError("identity_changed")
        if (intent.run_id != self._run_id or intent.batch_id != self._batch_id
                or ordinal != intent.ordinal or call.id != intent.tool_call_id
                or call.name != intent.tool_name or self._json(call.args) != intent.arguments_json):
            raise ExecutionAuthorizationError("operation_changed")
        self._check_contract(intent.tool_name, current)
        self._check_contract(intent.tool_name, list(config.available_tools))

    def prepare(self, call: ToolCall, ordinal: int, config: AgentConfig,
                current: list[ToolDefinition]) -> ToolIntent:
        if (type(call.args) is not dict or not isinstance(call.id, str) or not call.id
                or not isinstance(call.name, str) or not call.name):
            raise ExecutionAuthorizationError("invalid_tool_call")
        if self._identity != self._binding(config):
            raise ExecutionAuthorizationError("identity_changed")
        if call.name not in self._contracts:
            raise ExecutionAuthorizationError("unknown_tool")
        arguments = self._json(call.args)
        self._check_contract(call.name, current)
        self._check_contract(call.name, list(config.available_tools))
        try:
            self._validators[call.name].validate(json.loads(arguments))
        except Exception:
            raise ExecutionAuthorizationError("invalid_tool_schema_arguments") from None
        intent = self._intents.get(ordinal)
        if intent is not None:
            self._check_operation(intent, call, ordinal, config, current)
            if intent.execution_id in self._admitted:
                raise ExecutionAuthorizationError("operation_already_admitted")
            grant = self._grants.get(intent.execution_id)
            expired = grant is not None and self._clock() >= grant.expires_at
            revoked = grant is not None and grant.status == "revoked"
            if intent.policy_epoch != self._policy.epoch or expired or revoked:
                self._revoke(intent.execution_id)
                intent = replace(intent, execution_id=str(uuid4()), policy_epoch=self._policy.epoch)
        else:
            intent = ToolIntent(
                execution_id=str(uuid4()), run_id=self._run_id, batch_id=self._batch_id,
                ordinal=ordinal, identity=self._identity, tool_call_id=call.id, tool_name=call.name,
                contract_digest=self._digest(self._contracts[call.name]),
                arguments_digest=self._digest(arguments), arguments_json=arguments,
                policy_epoch=self._policy.epoch,
            )
        self._intents[ordinal] = intent
        return intent

    def decision(self, intent: ToolIntent) -> PolicyCheckResult:
        call = ToolCall(intent.tool_call_id, intent.tool_name, intent.arguments())
        check = self._policy.check_tool_call(call, self.definition(intent.tool_name))
        if check.decision != "needs_approval":
            return check
        grant = self._grants.get(intent.execution_id)
        if (grant is not None and grant.intent == intent and grant.status == "approved"
                and self._clock() < grant.expires_at):
            return PolicyCheckResult("allow", "operation-bound host approval")
        self._revoke(intent.execution_id)
        return check

    def request_approval(self, intent: ToolIntent) -> PendingApproval:
        self._pending = intent
        return PendingApproval(
            tool_name=intent.tool_name, tool_call_id=intent.tool_call_id,
            parameters=intent.arguments(), requires_always=True,
            execution_id=intent.execution_id,
        )

    def approve(self, pending: PendingApproval, *, execution_id: str | None = None,
                actor: str = "host") -> None:
        intent = self._pending
        if (intent is None or pending.execution_id != intent.execution_id
                or (execution_id is not None and execution_id != intent.execution_id)
                or pending.tool_name != intent.tool_name or pending.tool_call_id != intent.tool_call_id
                or self._json(pending.parameters) != intent.arguments_json):
            raise ExecutionAuthorizationError("approval_request_changed")
        if intent.execution_id in self._admitted:
            raise ExecutionAuthorizationError("operation_already_admitted")
        self._grants[intent.execution_id] = ApprovalGrant(
            intent=intent, actor=actor,
            expires_at=self._clock() + self.options.approval_ttl_seconds,
        )
        self._pending = None

    def admit(self, intent: ToolIntent, call: ToolCall, ordinal: int,
              config: AgentConfig, current: list[ToolDefinition]) -> dict[str, Any]:
        """Revalidate and claim once, synchronously with no await/callback gap.

        Runtime calls this after awaited observers/audit and immediately before
        ToolRuntime.execute. PolicyStore mutations also publish epoch without
        awaiting, so these operations serialize on the same event loop.
        """
        self._check_operation(intent, call, ordinal, config, current)
        if self._intents.get(ordinal) != intent or intent.policy_epoch != self._policy.epoch:
            raise ExecutionAuthorizationError("authorization_stale")
        if intent.execution_id in self._admitted:
            raise ExecutionAuthorizationError("operation_already_admitted")
        if self.decision(intent).decision != "allow":
            raise ExecutionAuthorizationError("authorization_not_valid")
        args = intent.arguments()
        self._admitted.add(intent.execution_id)
        grant = self._grants.get(intent.execution_id)
        if grant is not None and grant.status == "approved":
            self._grants[intent.execution_id] = replace(grant, status="consumed")
        return args

    def audit_details(self, ordinal: int) -> dict[str, Any]:
        intent = self._intents.get(ordinal)
        if intent is None:
            return {}
        grant = self._grants.get(intent.execution_id)
        thread_id, session_id, user_id, channel = intent.identity
        return {
            "execution_id": intent.execution_id, "run_id": intent.run_id,
            "batch_id": intent.batch_id, "ordinal": intent.ordinal,
            "policy_epoch": intent.policy_epoch,
            "approval_status": grant.status if grant else None,
            # TXS-11: link every decision/execution record to the host
            # identity+session and to the exact tool contract it authorized,
            # so an audit reader can attribute the call without joining
            # against mutable runtime state or the live tool catalog.
            "thread_id": thread_id, "session_id": session_id,
            "user_id": user_id, "channel": channel,
            "contract_digest": intent.contract_digest,
        }
