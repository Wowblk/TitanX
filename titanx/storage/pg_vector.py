from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .types import JobEntry, LogEntry, MemoryEntry, ScoredMemory, StorageBackend


class PgVectorBackend(StorageBackend):
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool = None
        self._has_vector = False

    async def initialize(self) -> None:
        import asyncpg
        self._pool = await asyncpg.create_pool(self._dsn)
        async with self._pool.acquire() as conn:
            try:
                await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                self._has_vector = True
            except Exception:
                self._has_vector = False

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    embedding TEXT
                )
            """)

            if self._has_vector:
                try:
                    await conn.execute("ALTER TABLE memories ADD COLUMN IF NOT EXISTS embedding_vec vector(1536)")
                    await conn.execute("""
                        CREATE INDEX IF NOT EXISTS memories_vec_idx
                        ON memories USING ivfflat (embedding_vec vector_cosine_ops)
                    """)
                except Exception:
                    pass

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    type TEXT NOT NULL,
                    payload JSONB,
                    result JSONB,
                    error TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    session_id TEXT,
                    data JSONB
                )
            """)

    async def save_memory(self, session_id: str, content: str, role: str, embedding: list[float] | None = None) -> MemoryEntry:
        assert self._pool
        id_ = str(uuid4())
        embedding_json = json.dumps(embedding) if embedding else None
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO memories (id, session_id, content, role, embedding) VALUES ($1, $2, $3, $4, $5)",
                id_, session_id, content, role, embedding_json,
            )
            if self._has_vector and embedding:
                vec_str = f"[{','.join(str(x) for x in embedding)}]"
                try:
                    await conn.execute(
                        "UPDATE memories SET embedding_vec = $1::vector WHERE id = $2",
                        vec_str, id_,
                    )
                except Exception:
                    pass
        return MemoryEntry(id=id_, session_id=session_id, content=content, role=role,
                           created_at=datetime.now(timezone.utc), embedding=embedding)

    async def search_by_vector(self, embedding: list[float], session_id: str | None = None, limit: int = 10) -> list[ScoredMemory]:
        if not self._has_vector:
            return []
        assert self._pool
        vec_str = f"[{','.join(str(x) for x in embedding)}]"
        where = "AND session_id = $3" if session_id else ""
        params: list[Any] = [vec_str, limit]
        if session_id:
            params.append(session_id)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT *, 1 - (embedding_vec <=> $1::vector) AS score
                    FROM memories
                    WHERE embedding_vec IS NOT NULL {where}
                    ORDER BY embedding_vec <=> $1::vector
                    LIMIT $2""",
                *params,
            )
        return [self._row_to_scored(r, float(r["score"]), "vector") for r in rows]

    async def search_by_fts(self, query: str, session_id: str | None = None, limit: int = 10) -> list[ScoredMemory]:
        assert self._pool
        where = "AND session_id = $3" if session_id else ""
        params: list[Any] = [query, limit]
        if session_id:
            params.append(session_id)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT *,
                       ts_rank(to_tsvector('english', content), plainto_tsquery('english', $1)) AS score
                    FROM memories
                    WHERE to_tsvector('english', content) @@ plainto_tsquery('english', $1) {where}
                    ORDER BY score DESC
                    LIMIT $2""",
                *params,
            )
        return [self._row_to_scored(r, float(r["score"]), "fts") for r in rows]

    async def list_memories(self, session_id: str, limit: int = 50) -> list[MemoryEntry]:
        assert self._pool
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM memories WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2",
                session_id, limit,
            )
        return [self._row_to_memory(r) for r in rows]

    async def save_job(self, session_id: str, type: str, status: str = "pending", payload: Any = None) -> JobEntry:
        assert self._pool
        id_ = str(uuid4())
        now = datetime.now(timezone.utc)
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO jobs (id, session_id, status, type, payload) VALUES ($1, $2, $3, $4, $5)",
                id_, session_id, status, type, json.dumps(payload) if payload is not None else None,
            )
        return JobEntry(id=id_, session_id=session_id, status=status, type=type,
                        created_at=now, updated_at=now, payload=payload)

    async def update_job(self, id: str, status: str | None = None, result: Any = None, error: str | None = None) -> None:
        assert self._pool
        sets = ["updated_at = NOW()"]
        params: list[Any] = []
        i = 1
        if status is not None:
            sets.append(f"status = ${i}"); params.append(status); i += 1
        if result is not None:
            sets.append(f"result = ${i}"); params.append(json.dumps(result)); i += 1
        if error is not None:
            sets.append(f"error = ${i}"); params.append(error); i += 1
        params.append(id)
        async with self._pool.acquire() as conn:
            await conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ${i}", *params)

    async def list_jobs(self, session_id: str | None = None) -> list[JobEntry]:
        assert self._pool
        async with self._pool.acquire() as conn:
            if session_id:
                rows = await conn.fetch("SELECT * FROM jobs WHERE session_id = $1 ORDER BY created_at DESC", session_id)
            else:
                rows = await conn.fetch("SELECT * FROM jobs ORDER BY created_at DESC")
        return [self._row_to_job(r) for r in rows]

    async def save_log(self, timestamp: datetime, event: str, actor: str, session_id: str | None = None, data: Any = None) -> None:
        assert self._pool
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_logs (id, timestamp, event, actor, session_id, data) VALUES ($1, $2, $3, $4, $5, $6)",
                str(uuid4()), timestamp, event, actor, session_id, json.dumps(data) if data is not None else None,
            )

    async def list_logs(self, session_id: str | None = None, limit: int = 100) -> list[LogEntry]:
        assert self._pool
        async with self._pool.acquire() as conn:
            if session_id:
                rows = await conn.fetch(
                    "SELECT * FROM audit_logs WHERE session_id = $1 ORDER BY timestamp DESC LIMIT $2",
                    session_id, limit,
                )
            else:
                rows = await conn.fetch("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT $1", limit)
        return [LogEntry(id=r["id"], timestamp=r["timestamp"], event=r["event"],
                         actor=r["actor"], session_id=r["session_id"], data=r["data"]) for r in rows]

    def _row_to_scored(self, r: Any, score: float, source: str) -> ScoredMemory:
        m = self._row_to_memory(r)
        return ScoredMemory(**m.__dict__, score=score, source=source)

    def _row_to_memory(self, r: Any) -> MemoryEntry:
        emb = json.loads(r["embedding"]) if r["embedding"] else None
        return MemoryEntry(
            id=r["id"], session_id=r["session_id"], content=r["content"],
            role=r["role"], created_at=r["created_at"], embedding=emb,
        )

    def _row_to_job(self, r: Any) -> JobEntry:
        return JobEntry(
            id=r["id"], session_id=r["session_id"], status=r["status"],
            type=r["type"], payload=r["payload"], result=r["result"],
            error=r["error"], created_at=r["created_at"], updated_at=r["updated_at"],
        )
