from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


@dataclass
class MemoryEntry:
    id: str
    session_id: str
    content: str
    role: str
    created_at: datetime
    embedding: list[float] | None = None


@dataclass
class ScoredMemory(MemoryEntry):
    score: float = 0.0
    source: Literal["vector", "fts"] = "fts"


@dataclass
class JobEntry:
    id: str
    session_id: str
    status: Literal["pending", "running", "completed", "failed"]
    type: str
    created_at: datetime
    updated_at: datetime
    payload: Any = None
    result: Any = None
    error: str | None = None


@dataclass
class LogEntry:
    id: str
    timestamp: datetime
    event: str
    actor: str
    session_id: str | None = None
    data: Any = None


class StorageBackend:
    async def initialize(self) -> None:
        raise NotImplementedError

    async def save_memory(self, session_id: str, content: str, role: str, embedding: list[float] | None = None) -> MemoryEntry:
        raise NotImplementedError

    async def search_by_vector(self, embedding: list[float], session_id: str | None = None, limit: int = 10) -> list[ScoredMemory]:
        raise NotImplementedError

    async def search_by_fts(self, query: str, session_id: str | None = None, limit: int = 10) -> list[ScoredMemory]:
        raise NotImplementedError

    async def list_memories(self, session_id: str, limit: int = 50) -> list[MemoryEntry]:
        raise NotImplementedError

    async def save_job(self, session_id: str, type: str, status: str = "pending", payload: Any = None) -> JobEntry:
        raise NotImplementedError

    async def update_job(self, id: str, status: str | None = None, result: Any = None, error: str | None = None) -> None:
        raise NotImplementedError

    async def list_jobs(self, session_id: str | None = None) -> list[JobEntry]:
        raise NotImplementedError

    async def save_log(self, timestamp: datetime, event: str, actor: str, session_id: str | None = None, data: Any = None) -> None:
        raise NotImplementedError

    async def list_logs(self, session_id: str | None = None, limit: int = 100) -> list[LogEntry]:
        raise NotImplementedError
