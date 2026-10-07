from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .types import JobEntry, LogEntry, MemoryEntry, ScoredMemory, StorageBackend


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na * nb else 0.0


class LibSQLBackend(StorageBackend):
    def __init__(self, url: str, auth_token: str | None = None) -> None:
        self._url = url
        self._auth_token = auth_token
        self._client = None
        self._has_fts = False

    async def initialize(self) -> None:
        from libsql_client import create_client
        self._client = create_client(url=self._url, auth_token=self._auth_token)

        await self._client.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                content TEXT NOT NULL,
                role TEXT NOT NULL,
                embedding TEXT,
                created_at TEXT NOT NULL
            )
        """)

        try:
            await self._client.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts
                USING fts5(content, content=memories, content_rowid=rowid)
            """)
            self._has_fts = True
        except Exception:
            self._has_fts = False

        await self._client.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                type TEXT NOT NULL,
                payload TEXT,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        await self._client.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                actor TEXT NOT NULL,
                session_id TEXT,
                data TEXT
            )
        """)

    async def save_memory(self, session_id: str, content: str, role: str, embedding: list[float] | None = None) -> MemoryEntry:
        id_ = str(uuid4())
        now = datetime.now(timezone.utc)
        emb_str = json.dumps(embedding) if embedding else None
        await self._client.execute(
            "INSERT INTO memories (id, session_id, content, role, embedding, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            [id_, session_id, content, role, emb_str, now.isoformat()],
        )
        if self._has_fts:
            try:
                await self._client.execute(
                    "INSERT INTO memories_fts(rowid, content) SELECT rowid, content FROM memories WHERE id = ?",
                    [id_],
                )
            except Exception:
                pass
        return MemoryEntry(id=id_, session_id=session_id, content=content, role=role,
                           created_at=now, embedding=embedding)

    async def search_by_vector(self, embedding: list[float], session_id: str | None = None, limit: int = 10) -> list[ScoredMemory]:
        where = "WHERE session_id = ?" if session_id else ""
        params = [session_id] if session_id else []
        rs = await self._client.execute(f"SELECT * FROM memories {where}", params)
        results: list[tuple[float, MemoryEntry]] = []
        for row in rs.rows:
            emb_str = row[4]
            if not emb_str:
                continue
            emb = json.loads(emb_str)
            score = _cosine(embedding, emb)
            results.append((score, self._row_to_memory(row)))
        results.sort(key=lambda x: x[0], reverse=True)
        return [ScoredMemory(**m.__dict__, score=s, source="vector") for s, m in results[:limit]]

    async def search_by_fts(self, query: str, session_id: str | None = None, limit: int = 10) -> list[ScoredMemory]:
        if self._has_fts:
            try:
                where = "AND m.session_id = ?" if session_id else ""
                params: list[Any] = [query]
                if session_id:
                    params.append(session_id)
                params.append(limit)
                rs = await self._client.execute(
                    f"""SELECT m.*, rank AS score FROM memories m
                        JOIN memories_fts ON memories_fts.rowid = m.rowid
                        WHERE memories_fts MATCH ? {where}
                        ORDER BY rank LIMIT ?""",
                    params,
                )
                return [
                    ScoredMemory(**self._row_to_memory(r).__dict__, score=abs(float(r[-1])), source="fts")
                    for r in rs.rows
                ]
            except Exception:
                pass

        # Fallback: LIKE search
        pattern = f"%{query}%"
        where2 = "AND session_id = ?" if session_id else ""
        params2: list[Any] = [pattern]
        if session_id:
            params2.append(session_id)
        params2.append(limit)
        rs = await self._client.execute(
            f"SELECT * FROM memories WHERE content LIKE ? {where2} ORDER BY created_at DESC LIMIT ?",
            params2,
        )
        return [ScoredMemory(**self._row_to_memory(r).__dict__, score=0.5, source="fts") for r in rs.rows]

    async def list_memories(self, session_id: str, limit: int = 50) -> list[MemoryEntry]:
        rs = await self._client.execute(
            "SELECT * FROM memories WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
            [session_id, limit],
        )
        return [self._row_to_memory(r) for r in rs.rows]

    async def save_job(self, session_id: str, type: str, status: str = "pending", payload: Any = None) -> JobEntry:
        id_ = str(uuid4())
        now = datetime.now(timezone.utc)
        await self._client.execute(
            "INSERT INTO jobs (id, session_id, status, type, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [id_, session_id, status, type, json.dumps(payload) if payload is not None else None,
             now.isoformat(), now.isoformat()],
        )
        return JobEntry(id=id_, session_id=session_id, status=status, type=type,
                        created_at=now, updated_at=now, payload=payload)

    async def update_job(self, id: str, status: str | None = None, result: Any = None, error: str | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        sets = ["updated_at = ?"]
        params: list[Any] = [now]
        if status is not None:
            sets.append("status = ?"); params.append(status)
        if result is not None:
            sets.append("result = ?"); params.append(json.dumps(result))
        if error is not None:
            sets.append("error = ?"); params.append(error)
        params.append(id)
        await self._client.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", params)

    async def list_jobs(self, session_id: str | None = None) -> list[JobEntry]:
        if session_id:
            rs = await self._client.execute("SELECT * FROM jobs WHERE session_id = ? ORDER BY created_at DESC", [session_id])
        else:
            rs = await self._client.execute("SELECT * FROM jobs ORDER BY created_at DESC")
        return [self._row_to_job(r) for r in rs.rows]

    async def save_log(self, timestamp: datetime, event: str, actor: str, session_id: str | None = None, data: Any = None) -> None:
        await self._client.execute(
            "INSERT INTO audit_logs (id, timestamp, event, actor, session_id, data) VALUES (?, ?, ?, ?, ?, ?)",
            [str(uuid4()), timestamp.isoformat(), event, actor, session_id, json.dumps(data) if data is not None else None],
        )

    async def list_logs(self, session_id: str | None = None, limit: int = 100) -> list[LogEntry]:
        if session_id:
            rs = await self._client.execute("SELECT * FROM audit_logs WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?", [session_id, limit])
        else:
            rs = await self._client.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", [limit])
        return [
            LogEntry(id=r[0], timestamp=datetime.fromisoformat(r[1]), event=r[2],
                     actor=r[3], session_id=r[4], data=json.loads(r[5]) if r[5] else None)
            for r in rs.rows
        ]

    def _row_to_memory(self, r: Any) -> MemoryEntry:
        emb = json.loads(r[4]) if r[4] else None
        return MemoryEntry(
            id=r[0], session_id=r[1], content=r[2], role=r[3],
            created_at=datetime.fromisoformat(r[5]), embedding=emb,
        )

    def _row_to_job(self, r: Any) -> JobEntry:
        return JobEntry(
            id=r[0], session_id=r[1], status=r[2], type=r[3],
            payload=json.loads(r[4]) if r[4] else None,
            result=json.loads(r[5]) if r[5] else None,
            error=r[6],
            created_at=datetime.fromisoformat(r[7]),
            updated_at=datetime.fromisoformat(r[8]),
        )
