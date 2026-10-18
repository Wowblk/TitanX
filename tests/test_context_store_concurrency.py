"""A blocked or cancelled write must not stall reads of other sessions.

``ContextManager._wait`` wraps store calls in ``asyncio.wait_for``, which
cancels the awaiting coroutine but not the worker thread. With one shared
connection behind a process-wide lock, a write stuck in SQLite's busy-wait
holds that lock for its full busy timeout, so every read — of every other
session, on already-committed data — queues behind it.

These tests pin the public behaviour: a healthy session stays readable while
another session's write is blocked, and a ``:memory:`` store keeps working
unchanged.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3

from titanx import SQLiteContextStore
from titanx.types import UserMessage


async def test_blocked_write_does_not_block_reads_of_committed_data(tmp_path):
    path = tmp_path / "context.sqlite"
    store = SQLiteContextStore(path)
    seeded = UserMessage(role="user", content="already committed")
    await store.archive("session-a", [seeded])

    # A second connection holds a write lock so the store's own write has to
    # busy-wait. Readers can still read during a RESERVED lock; only a shared
    # Python lock would serialize them behind the blocked writer.
    blocker = sqlite3.connect(path)
    blocker.execute("BEGIN IMMEDIATE")
    blocker.execute("INSERT INTO tasks(session,payload) VALUES('blocker','{}')")
    write = asyncio.create_task(
        store.archive("session-b", [UserMessage(role="user", content="slow")])
    )
    try:
        # Let the archive reach its worker thread and block on the write lock.
        await asyncio.sleep(0.1)
        assert not write.done()

        page = await asyncio.wait_for(
            store.read("session-a", "message", seeded.id), timeout=0.5
        )
        assert json.loads(page.content)["content"] == "already committed"
    finally:
        blocker.rollback()
        blocker.close()
        await write

    await store.close()


async def test_memory_store_still_supports_the_full_lifecycle():
    # ``:memory:`` databases are per-connection, so this path necessarily keeps
    # one shared connection. Guard that the file-backed redesign did not break
    # it.
    store = SQLiteContextStore(":memory:")
    message = UserMessage(role="user", content="ephemeral")
    await store.archive("session", [message])

    page = await store.read("session", "message", message.id)
    assert json.loads(page.content)["content"] == "ephemeral"

    await store.close()
