from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class AgentPolicy:
    allowed_write_paths: list[str] = field(default_factory=list)
    auto_approve_tools: bool = False
    max_iterations: int = 10


@dataclass
class PolicySnapshot:
    id: str
    created_at: str
    policy: AgentPolicy
    reason: str


@dataclass
class AuditEntry:
    timestamp: str
    event: Literal["policy_change", "break_glass_activated", "break_glass_expired", "rollback"]
    actor: Literal["host", "system"]
    before: AgentPolicy
    after: AgentPolicy
    reason: str
    snapshot_id: str | None = None


@dataclass
class BreakGlassSession:
    activated_at: str
    expires_at: str
    original_snapshot_id: str


class ReadonlyPolicyView:
    def get_policy(self) -> AgentPolicy:
        raise NotImplementedError
