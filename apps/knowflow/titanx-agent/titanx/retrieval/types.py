from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..storage.types import MemoryEntry


class EmbeddingProvider:
    async def embed(self, text: str) -> list[float]:
        raise NotImplementedError


@dataclass
class RetrievalResult:
    entry: MemoryEntry
    score: float
    source: Literal["vector", "fts", "hybrid"]


@dataclass
class HybridRetrievalOptions:
    limit: int = 10
    session_id: str | None = None
    vector_weight: float = 0.7
    decay_rate: float = 0.01
    mmr_lambda: float = 0.5
