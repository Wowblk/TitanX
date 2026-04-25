"""Append-only audit log with bounded memory and crash-resilient writes.

This module is the **canonical audit pipeline** for TitanX. Anything
that needs to record a policy change, a tool decision, or a tool
invocation goes through ``AuditLog.append``. The legacy
``StorageBackend.save_log`` family still exists for backward
compatibility but should be wired in as a ``secondary_sink`` of an
``AuditLog`` instance rather than written to directly — otherwise you
end up with two unreconciled audit streams (Q20).

Architecture
============

The log keeps two parallel views of the audit stream:

1. An in-memory ``deque(maxlen=N)`` ring buffer, updated **synchronously**
   inside ``append`` so callers see the entry immediately via
   ``get_entries`` without waiting for disk IO.
2. A persistent JSONL file, written by a single background **writer
   coroutine** that consumes from an ``asyncio.Queue``. A single writer
   guarantees lines are not interleaved (the historical bug allowed
   concurrent ``aiofiles.write`` calls to slice each other's payload
   when entries exceeded ``PIPE_BUF``).

The writer holds a long-lived file handle for the lifetime of the
``AuditLog``, replacing the historical "open + write + close on every
append" pattern that turned every tool invocation into multiple syscalls.

Crash resilience is configurable via ``fsync_policy``:

- ``"never"`` — let the OS page cache decide. Highest throughput, but a
  power loss / OOM-kill can lose minutes of audit. Acceptable in dev.
- ``"every"`` — fsync after every entry. Strict-audit mode for
  regulatory/forensic deployments.
- ``"interval"`` (default) — fsync every ``fsync_interval_entries``
  records or every ``fsync_interval_seconds`` of wall time, whichever
  comes first. Sane production default: a steady stream still survives
  ``kill -9`` within ~1 s, and a quiet log doesn't spin in idle fsyncs.

Secondary sinks
===============

``secondary_sink`` lets a host fan out every audit entry to a second
destination — typically a relational store (libsql / Postgres) so the
log is queryable by ``session_id`` / ``timestamp`` / ``event``. The
sink runs synchronously inside ``append`` so failures are surfaced
through the same warning channel as disk-write failures and never raise
into the caller. JSONL on disk remains the durable record; the
secondary sink is a convenience for analytics, NOT a replacement.

Lazy start
==========

The writer task is started lazily on the first persistent ``append``
call. This keeps ``AuditLog()`` cheap and constructible outside an event
loop. Callers that care about clean shutdown should ``await
log.aclose()`` (or use ``async with``) so the queue is drained and the
final fsync happens. Without ``aclose``, Python's normal task teardown
will close the file handle but may lose the last ~1 s of in-flight
entries.

Failure modes
=============

If file IO fails (disk full, NFS dropout, permission), the writer logs a
single warning to stderr and continues to drain the queue without
writing — the in-memory ring is unaffected so the host still observes
events via ``get_entries``. This is closer to syslog semantics than to
"raise into the caller", which would otherwise turn every audit failure
into a ``PolicyStore.set`` failure.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import sys
from collections import deque
from dataclasses import asdict
from datetime import date, datetime
from typing import Awaitable, Callable, Literal

import aiofiles

from .types import AuditEntry


# Optional fan-out hook. Receives each AuditEntry after it lands in the
# in-memory ring buffer; runs serially with append() so the host's view
# stays consistent. May be sync or async; failures are warned-and-swallowed.
SecondarySink = Callable[[AuditEntry], "Awaitable[None] | None"]


FsyncPolicy = Literal["never", "every", "interval"]

# JSONL schema version embedded in every record so future format changes
# can be detected by parsers without breaking on old files. Bump this
# whenever the serialised shape changes incompatibly (renamed fields,
# removed fields, type changes — adding optional fields is compatible).
AUDIT_SCHEMA_VERSION = 1


def _safe_default(obj: object) -> object:
    """JSON encoder fallback for values that ``json.dumps`` rejects.

    The ``details`` field on ``AuditEntry`` is ``dict[str, Any]`` — hosts
    can put anything in there. Without a ``default``, a single
    ``set`` / ``bytes`` / ``datetime`` / ``Path`` value blows up the entire
    audit append, which used to propagate into ``PolicyStore.set`` and
    abort policy changes for an unrelated reason. This encoder converts
    common offenders to JSON-friendly forms; anything genuinely
    unencodable falls back to ``repr`` so the audit still survives,
    even if its payload is lossy.
    """
    if isinstance(obj, (set, frozenset)):
        # Sort for deterministic output (helps log diffing).
        return sorted(obj, key=str)
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return repr(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if hasattr(obj, "__fspath__"):
        return os.fspath(obj)
    return repr(obj)


_STOP_SENTINEL: object = object()


class AuditLog:
    def __init__(
        self,
        log_path: str | None = None,
        *,
        max_in_memory: int = 10_000,
        fsync_policy: FsyncPolicy = "interval",
        fsync_interval_entries: int = 50,
        fsync_interval_seconds: float = 1.0,
        schema_version: int = AUDIT_SCHEMA_VERSION,
        secondary_sink: SecondarySink | None = None,
    ) -> None:
        # Treat the empty string as "not configured by mistake" — the
        # historical falsy check silently swallowed it, leaving callers
        # confused about why their audit file was empty.
        if log_path is not None and log_path == "":
            raise ValueError(
                "log_path must be a non-empty path or None (not '')"
            )
        if fsync_policy not in ("never", "every", "interval"):
            raise ValueError(f"unknown fsync_policy: {fsync_policy!r}")

        self._entries: deque[AuditEntry] = deque(maxlen=max_in_memory)
        self._log_path = log_path
        self._max_in_memory = max_in_memory
        self._fsync_policy: FsyncPolicy = fsync_policy
        self._fsync_interval_entries = max(1, fsync_interval_entries)
        self._fsync_interval_seconds = max(0.0, fsync_interval_seconds)
        self._schema_version = schema_version

        self._queue: asyncio.Queue | None = None
        self._writer_task: asyncio.Task | None = None
        self._fh = None
        self._start_lock = asyncio.Lock()
        self._closed = False
        self._io_disabled = False  # set True after persistent file IO failure
        self._secondary_sink: SecondarySink | None = secondary_sink
        self._secondary_disabled = False  # set True after sink raises

    async def append(self, entry: AuditEntry) -> None:
        if self._closed:
            raise RuntimeError("AuditLog is closed")
        # Update the in-memory ring synchronously so ``get_entries``
        # always reflects the post-call state. The disk write is decoupled
        # via the queue and can lag without affecting host visibility.
        self._entries.append(entry)

        # Secondary sink fan-out. Runs before the queue enqueue so a
        # slow sink gets at most one entry's worth of backpressure
        # against the host (the queue absorbs the rest). Failures are
        # warned-and-swallowed; we permanently disable the sink after
        # one failure so a broken DB can't pin the writer in retry
        # loops on every audit append.
        if self._secondary_sink is not None and not self._secondary_disabled:
            try:
                result = self._secondary_sink(entry)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                self._secondary_disabled = True
                self._warn(
                    f"audit secondary_sink raised: {exc!r}; disabling sink — "
                    f"JSONL log on {self._log_path!r} remains active"
                )

        if self._log_path is None or self._io_disabled:
            return
        await self._ensure_writer()
        assert self._queue is not None
        await self._queue.put(entry)

    def get_entries(self) -> list[AuditEntry]:
        """Return a snapshot of the in-memory ring buffer.

        The returned list is a fresh copy so the caller can iterate
        without worrying about concurrent ``append`` calls mutating the
        underlying deque mid-iteration. Note: in-memory entries past the
        ``max_in_memory`` window are dropped from this view but **remain
        on disk** (if a ``log_path`` was configured) — the disk file is
        the durable record.
        """
        return list(self._entries)

    async def flush(self) -> None:
        """Force every queued entry to be written and fsynced to disk.

        Useful before a forensic snapshot or graceful shutdown. Returns
        once the writer has drained the queue and the OS confirms the
        bytes are on stable storage. Cheap when ``log_path`` is None.
        """
        if self._log_path is None or self._writer_task is None:
            return
        # Drain marker: enqueue a barrier and wait for it to flush.
        barrier = asyncio.Event()
        await self._queue.put(("__flush__", barrier))  # type: ignore[arg-type]
        await barrier.wait()

    async def aclose(self) -> None:
        """Drain the queue, fsync, and stop the writer task."""
        if self._closed:
            return
        self._closed = True
        if self._writer_task is None or self._queue is None:
            return
        await self._queue.put(_STOP_SENTINEL)
        try:
            await self._writer_task
        except Exception:
            pass

    async def __aenter__(self) -> "AuditLog":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # ── internal ────────────────────────────────────────────────────────

    async def _ensure_writer(self) -> None:
        # Fast path: writer already running.
        if self._writer_task and not self._writer_task.done():
            return
        async with self._start_lock:
            if self._writer_task and not self._writer_task.done():
                return
            self._queue = asyncio.Queue()
            self._writer_task = asyncio.create_task(self._writer_loop())

    async def _writer_loop(self) -> None:
        try:
            await self._open_file()
        except Exception as exc:
            self._io_disabled = True
            self._warn(f"audit log open failed: {exc!r}; continuing in-memory-only")
            return

        pending = 0
        try:
            while True:
                try:
                    item = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=self._fsync_interval_seconds or None,
                    )
                except asyncio.TimeoutError:
                    # Idle wakeup: flush whatever's pending in the page
                    # cache so a ``kill -9`` doesn't lose the last
                    # entries during quiet periods.
                    if pending and self._fsync_policy == "interval":
                        await self._do_fsync()
                        pending = 0
                    continue

                if item is _STOP_SENTINEL:
                    if pending:
                        await self._do_fsync()
                    return

                # Explicit flush barrier — drain everything we've already
                # queued, fsync, then signal the waiter.
                if isinstance(item, tuple) and len(item) == 2 and item[0] == "__flush__":
                    barrier: asyncio.Event = item[1]
                    if pending:
                        await self._do_fsync()
                        pending = 0
                    barrier.set()
                    continue

                try:
                    await self._write_line(item)
                    pending += 1
                except Exception as exc:
                    # Per-entry write failure: drop this entry on the
                    # disk side, log to stderr, keep the writer alive.
                    # In-memory copy is already preserved via append.
                    self._warn(f"audit log write failed: {exc!r}")
                    continue

                if self._fsync_policy == "every":
                    await self._do_fsync()
                    pending = 0
                elif (
                    self._fsync_policy == "interval"
                    and pending >= self._fsync_interval_entries
                ):
                    await self._do_fsync()
                    pending = 0
        finally:
            await self._close_file()

    async def _open_file(self) -> None:
        path = self._log_path
        assert path is not None
        dirname = os.path.dirname(path)
        if dirname:
            # Run blocking syscalls in a worker thread so the event loop
            # isn't pinned during slow filesystems (NFS, fuse, EBS cold).
            await asyncio.to_thread(os.makedirs, dirname, exist_ok=True)
        self._fh = await aiofiles.open(path, mode="a", encoding="utf-8")

    async def _close_file(self) -> None:
        if self._fh is None:
            return
        try:
            await self._fh.flush()
        except Exception:
            pass
        try:
            await self._fh.close()
        except Exception:
            pass
        self._fh = None

    async def _write_line(self, entry: AuditEntry) -> None:
        assert self._fh is not None
        record = {"schema": self._schema_version, **asdict(entry)}
        line = json.dumps(record, default=_safe_default, ensure_ascii=False) + "\n"
        await self._fh.write(line)

    async def _do_fsync(self) -> None:
        if self._fh is None:
            return
        try:
            await self._fh.flush()
        except Exception:
            return
        # aiofiles wraps a real file object; .fileno() is sync and cheap.
        try:
            fileno = self._fh.fileno()
        except Exception:
            return
        try:
            await asyncio.to_thread(os.fsync, fileno)
        except OSError:
            # ENOSYS / EINVAL on some special files (e.g. /dev/null,
            # tmpfs in some kernels). Not a corruption; just skip.
            pass

    @staticmethod
    def _warn(msg: str) -> None:
        # Stderr instead of ``logging`` to keep AuditLog free of cyclic
        # dependencies on user-configured log handlers.
        try:
            print(f"[titanx.audit] WARNING: {msg}", file=sys.stderr, flush=True)
        except Exception:
            pass
