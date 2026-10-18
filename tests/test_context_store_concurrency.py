"""A blocked or cancelled write must not stall reads of other sessions.

``ContextManager._wait`` wraps store calls in ``asyncio.wait_for``, which
cancels the awaiting coroutine but not the worker thread. With one shared
connection behind a process-wide lock, a write stuck in SQLite's busy-wait
holds that lock for its full busy timeout, so every read — of every other
session, on already-committed data — queues behind it.

These tests pin the public behaviour: a healthy session stays readable while
another session's write is blocked, a cancelled write leaves no wedged lock,
``close`` still acts as a write barrier, and a ``:memory:`` store keeps
working unchanged.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3

import pytest

from titanx import SQLiteContextStore
from titanx.types import UserMessage


def _block_writes(path):
    """Hold SQLite's write lock so the store's next write has to busy-wait."""
    blocker = sqlite3.connect(path)
    blocker.execute("BEGIN IMMEDIATE")
    blocker.execute("INSERT INTO tasks(session,payload) VALUES('blocker','{}')")
    return blocker


def _release(blocker) -> None:
    blocker.rollback()
    blocker.close()


async def test_blocked_write_does_not_block_reads_of_committed_data(tmp_path):
    path = tmp_path / "context.sqlite"
    store = SQLiteContextStore(path)
    seeded = UserMessage(role="user", content="already committed")
    await store.archive("session-a", [seeded])

    # Readers can still read during a RESERVED lock; only a shared Python lock
    # would serialize them behind the blocked writer.
    blocker = _block_writes(path)
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
        _release(blocker)
        await asyncio.wait_for(write, timeout=5)

    await store.close()


async def test_cancelled_write_does_not_wedge_reads_or_close(tmp_path):
    # The shape of ContextManager._wait: the caller times out and the awaiting
    # coroutine is cancelled while its worker thread is still blocked. The
    # store must stay readable and close() must drain (not orphan) that worker.
    path = tmp_path / "context.sqlite"
    store = SQLiteContextStore(path)
    seeded = UserMessage(role="user", content="already committed")
    late = UserMessage(role="user", content="eventually committed")
    await store.archive("session-a", [seeded])

    blocker = _block_writes(path)
    try:
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(store.archive("session-b", [late]), timeout=0.2)

        page = await asyncio.wait_for(
            store.read("session-a", "message", seeded.id), timeout=0.5
        )
        assert json.loads(page.content)["content"] == "already committed"
    finally:
        _release(blocker)

    # close() waits for the still-running worker, so its write is durable by
    # the time close returns.
    await asyncio.wait_for(store.close(), timeout=5)
    reopened = SQLiteContextStore(path)
    try:
        page = await reopened.read("session-b", "message", late.id)
        assert json.loads(page.content)["content"] == "eventually committed"
    finally:
        await reopened.close()


async def test_close_waits_for_an_in_flight_write(tmp_path):
    # close() is the host's quiescence point. An operation that started before
    # it must either finish before close returns or fail closed; it must not
    # commit after the host believes the store is shut down.
    path = tmp_path / "context.sqlite"
    store = SQLiteContextStore(path)
    message = UserMessage(role="user", content="in flight")
    blocker = _block_writes(path)
    write = asyncio.create_task(store.archive("session", [message]))
    try:
        await asyncio.sleep(0.1)
        assert not write.done()

        close_task = asyncio.create_task(store.close())
        await asyncio.sleep(0.1)
        assert not close_task.done(), "close returned while a write was in flight"
    finally:
        _release(blocker)

    await asyncio.wait_for(write, timeout=5)
    await asyncio.wait_for(close_task, timeout=5)

    reopened = SQLiteContextStore(path)
    try:
        page = await reopened.read("session", "message", message.id)
        assert json.loads(page.content)["content"] == "in flight"
    finally:
        await reopened.close()


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
