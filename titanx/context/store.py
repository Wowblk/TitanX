"""Session-scoped canonical transcripts, content pages and compaction lineage."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..types import Message, TaskState


@dataclass(frozen=True)
class ContentPage:
    id: str
    content: str
    offset: int
    next_offset: int | None
    total_chars: int


class ContextStoreClosedError(sqlite3.ProgrammingError):
    """Raised when an operation targets a store that has been closed.

    Subclasses ``sqlite3.ProgrammingError`` (with a matching message) so hosts
    that already catch the underlying driver error keep working, while callers
    that want to distinguish "the store is shutting down" from a genuine schema
    error can catch this type instead.
    """


class ContextStore:
    """Implementations must commit writes before returning and isolate sessions.

    Existing message IDs are immutable: archiving an offloaded model view must
    never replace its original canonical message. All reads use an explicit
    host-provided session ID, never one supplied by a model tool argument.

    This is the complete interface a host implements to back context
    management. Lifecycle/cleanup operations (``list_compactions``,
    ``delete_session``, ``close``) belong here too: the runtime's teardown
    contract and the gateway's session eviction call them through this
    interface, so a store that omits them cannot be driven correctly.
    """

    async def archive(self, session_id: str, messages: list[Message]) -> None:
        raise NotImplementedError

    async def put_artifact(self, session_id: str, content: str) -> str:
        raise NotImplementedError

    async def read(self, session_id: str, kind: str, id: str, offset: int = 0, limit: int = 4000) -> ContentPage:
        raise NotImplementedError

    async def search(self, session_id: str, query: str, after: int = 0, limit: int = 10) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def commit_compaction(self, session_id: str, originals: list[Message], replacement: list[Message], record: dict) -> None:
        raise NotImplementedError

    async def list_compactions(self, session_id: str) -> list[dict]:
        raise NotImplementedError

    async def save_task(self, session_id: str, task: TaskState) -> None:
        raise NotImplementedError

    async def load_task(self, session_id: str) -> TaskState | None:
        raise NotImplementedError

    async def delete_session(self, session_id: str) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


class SQLiteContextStore(ContextStore):
    """Durable local store, with bounded paging and literal substring search.

    SQLite operations run off the event loop. A file-backed store opens a
    dedicated connection per operation (WAL mode + a busy timeout), so a
    cancelled or timed-out caller's still-running worker cannot block reads of
    other sessions behind a process-wide lock: at worst it holds a SQLite
    write lock, and WAL readers keep reading the last committed snapshot. A
    ``:memory:`` database is per-connection, so that path keeps one shared
    connection serialized by a threading lock.

    Each write is transactional and idempotent; cancellation never commits a
    partial batch. Because the worker owns its connection, cancelling the
    awaiting coroutine leaves no wedged lock behind. ``close`` is idempotent
    and, once it has run, every later operation fails fast with
    ``ContextStoreClosedError`` (a ``sqlite3.ProgrammingError`` subclass).
    Operations already in flight on their own connection finish and close it.
    Own and close this store at host/application scope, not once per runtime.
    """

    # Mirrors sqlite3's own message so existing ``sqlite3.ProgrammingError``
    # handlers keep matching while callers can catch ContextStoreClosedError.
    _CLOSED_MESSAGE = "Cannot operate on a closed database."

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS messages (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL,
            id TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(session, id));
        CREATE INDEX IF NOT EXISTS messages_session_seq ON messages(session, seq);
        CREATE TABLE IF NOT EXISTS artifacts (
            session TEXT NOT NULL, id TEXT NOT NULL, content TEXT NOT NULL,
            PRIMARY KEY(session, id));
        CREATE TABLE IF NOT EXISTS compactions (
            session TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY(session, id));
        CREATE TABLE IF NOT EXISTS tasks (
            session TEXT PRIMARY KEY, payload TEXT NOT NULL);
    """

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._path = str(path)
        self._shared_conn: sqlite3.Connection | None = None
        if self._path == ":memory:":
            self._shared_conn = self._connect()
            self._init_schema(self._shared_conn)
            return
        # New transcript files are private to the host account. Do not
        # silently change permissions on an existing application database.
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        conn = self._connect()
        try:
            # WAL lets readers proceed against the last committed snapshot
            # while a writer is busy; it is a property of the database file,
            # so set it once. Must run outside any transaction.
            conn.execute("PRAGMA journal_mode=WAL")
            self._init_schema(conn)
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        # Wait for a competing writer instead of failing immediately. Reads
        # never queue behind this: WAL readers are only briefly blocked by a
        # checkpoint.
        conn.execute("PRAGMA busy_timeout=5000")
        # SQLite's built-in text length/substr stop at NUL. Tool output can
        # contain it, so page using Python's Unicode character semantics.
        conn.create_function("text_length", 1, len)
        conn.create_function("text_page", 3, lambda value, offset, size: value[offset:offset + size])
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(self._SCHEMA)

    async def _run(self, fn):
        if self._closed:
            raise ContextStoreClosedError(self._CLOSED_MESSAGE)
        if self._shared_conn is not None:
            return await asyncio.to_thread(self._run_shared, fn)
        return await asyncio.to_thread(self._run_isolated, fn)

    def _run_shared(self, fn):
        with self._lock:
            # Re-check under the lock so a worker that was queued before
            # close() and resumes after it cannot fall through onto a
            # closed connection (surfacing a raw driver error instead of a
            # consistent, catchable signal).
            if self._closed:
                raise ContextStoreClosedError(self._CLOSED_MESSAGE)
            with self._shared_conn:
                return fn(self._shared_conn)

    def _run_isolated(self, fn):
        # Re-check on the worker: close() may have run while this call was
        # waiting for a thread. A connection opened after close still must not
        # serve the operation.
        if self._closed:
            raise ContextStoreClosedError(self._CLOSED_MESSAGE)
        conn = self._connect()
        try:
            with conn:
                return fn(conn)
        finally:
            conn.close()

    @staticmethod
    def _rows(session_id: str, messages: list[Message]) -> list[tuple[str, str, str]]:
        return [(session_id, m.id, json.dumps(asdict(m), ensure_ascii=False, separators=(",", ":"))) for m in messages]

    @staticmethod
    def _archive(conn, rows):
        conn.executemany("INSERT OR IGNORE INTO messages(session,id,payload) VALUES(?,?,?)", rows)

    async def archive(self, session_id, messages):
        rows = self._rows(session_id, messages)
        await self._run(lambda conn: self._archive(conn, rows))

    async def put_artifact(self, session_id, content):
        id = "artifact_" + hashlib.sha256(content.encode("utf-8")).hexdigest()
        await self._run(lambda conn: conn.execute(
            "INSERT OR IGNORE INTO artifacts(session,id,content) VALUES(?,?,?)", (session_id, id, content)))
        return id

    async def read(self, session_id, kind, id, offset=0, limit=4000):
        if kind not in ("message", "artifact"):
            raise ValueError("kind must be message or artifact")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 16000:
            raise ValueError("invalid content page bounds")
        table, column = ("messages", "payload") if kind == "message" else ("artifacts", "content")
        row = await self._run(lambda conn: conn.execute(
            f"SELECT text_page({column},?,?), text_length({column}) FROM {table} WHERE session=? AND id=?",
            (offset, limit, session_id, id)).fetchone())
        if row is None:
            raise LookupError("content not found in this session")
        content, total = row
        end = min(offset + len(content), total)
        return ContentPage(id, content, offset, end if end < total else None, total)

    async def search(self, session_id, query, after=0, limit=10):
        if not isinstance(query, str) or not query or len(query) > 256:
            raise ValueError("query must contain 1 to 256 characters")
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("invalid search bounds")
        rows = await self._run(lambda conn: conn.execute(
            "SELECT seq,id,max(0,instr(payload,?)-81),substr(payload,max(1,instr(payload,?)-80),240) "
            "FROM messages WHERE session=? AND seq>? AND instr(payload,?)>0 ORDER BY seq LIMIT ?",
            (query, query, session_id, after, query, limit)).fetchall())
        return [dict(cursor=seq, message_id=id, offset=offset, preview=preview) for seq, id, offset, preview in rows]

    async def commit_compaction(self, session_id, originals, replacement, record):
        rows = self._rows(session_id, [*originals, *replacement])
        payload = json.dumps(record, ensure_ascii=False)
        def commit(conn):
            self._archive(conn, rows)
            conn.execute("INSERT OR IGNORE INTO compactions(session,id,payload) VALUES(?,?,?)",
                         (session_id, record["id"], payload))
        await self._run(commit)

    async def list_compactions(self, session_id: str) -> list[dict]:
        rows = await self._run(lambda conn: conn.execute(
            "SELECT payload FROM compactions WHERE session=? ORDER BY rowid", (session_id,)).fetchall())
        return [json.loads(row[0]) for row in rows]

    async def save_task(self, session_id, task):
        payload = json.dumps(asdict(task), ensure_ascii=False)
        await self._run(lambda conn: conn.execute(
            "INSERT INTO tasks(session,payload) VALUES(?,?) ON CONFLICT(session) DO UPDATE SET payload=excluded.payload",
            (session_id, payload)))

    async def load_task(self, session_id):
        row = await self._run(lambda conn: conn.execute("SELECT payload FROM tasks WHERE session=?", (session_id,)).fetchone())
        return TaskState(**json.loads(row[0])) if row else None

    async def delete_session(self, session_id: str) -> None:
        def delete(conn):
            for table in ("messages", "artifacts", "compactions", "tasks"):
                conn.execute(f"DELETE FROM {table} WHERE session=?", (session_id,))
        await self._run(delete)

    async def close(self) -> None:
        if self._closed:
            return
        def close():
            with self._lock:
                # Idempotent under concurrency: whichever worker gets the lock
                # first closes once; the rest observe the flag and return.
                if self._closed:
                    return
                self._closed = True
                # Only the shared (``:memory:``) connection outlives an
                # operation. File-backed operations own and close their own
                # connections, so there is nothing to tear down here.
                if self._shared_conn is not None:
                    self._shared_conn.close()
        await asyncio.to_thread(close)
