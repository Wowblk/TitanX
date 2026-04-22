from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..types import Message


class CompactionStrategy:
    async def summarize(self, messages: list[Message]) -> str:
        raise NotImplementedError


@dataclass
class CompactionOptions:
    token_budget: int
    max_ptl_retries: int = 3
    max_consecutive_failures: int = 3


@dataclass
class CompactionTracking:
    consecutive_failures: int = 0


@dataclass
class CompactionResult:
    summary: str
    messages_retained: int
    ptl_attempts: int
