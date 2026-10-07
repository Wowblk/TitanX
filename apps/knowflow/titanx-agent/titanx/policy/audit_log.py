from __future__ import annotations

import json
import os

import aiofiles

from .types import AuditEntry
from dataclasses import asdict


class AuditLog:
    def __init__(self, log_path: str | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._log_path = log_path
        self._dir_ensured = False

    async def append(self, entry: AuditEntry) -> None:
        self._entries.append(entry)
        if self._log_path:
            if not self._dir_ensured:
                os.makedirs(os.path.dirname(self._log_path), exist_ok=True)
                self._dir_ensured = True
            async with aiofiles.open(self._log_path, "a") as f:
                await f.write(json.dumps(asdict(entry)) + "\n")

    def get_entries(self) -> list[AuditEntry]:
        return list(self._entries)
