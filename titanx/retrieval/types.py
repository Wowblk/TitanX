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
    """Tunables for ``HybridRetriever.search``.

    ``fusion`` selects how vector and FTS lists are combined:

    - ``"rrf"`` (default): Reciprocal Rank Fusion — a *rank-based* combiner
      that ignores the absolute scale of either list. ``vector_weight`` is
      applied as a per-list multiplier on the RRF contribution; the dial
      is fairly weak here because RRF's top-of-list is already only ~1/61
      apart. **If you want ``vector_weight=0.7`` to actually mean "70 %
      vector, 30 % FTS", use ``"weighted"``.** This was the historical
      semantic mismatch fixed in Q10.
    - ``"weighted"``: each list is min-max normalised to [0, 1] then
      linearly combined as ``vector_weight·vec + (1−vector_weight)·fts``.
      Items absent from one list contribute 0 from that side. This is
      the score-based combiner most callers actually want when they touch
      ``vector_weight``.

    ``vector_weight`` ranges over [0, 1]; values outside the range are
    clamped (defensive — RRF math goes negative otherwise).

    ``decay_rate`` is the per-day exponential decay coefficient applied
    after fusion. A typical recency-aware setting is 0.01 (≈ 1 % decay
    per day, half-life ~70 days). Set to 0 to disable.

    ``mmr_lambda`` ranges over [0, 1]; 1.0 means pure relevance, 0.0
    means pure diversity. The fix in Q10 made this dial actually
    meaningful — historically the MMR scale mismatch made values below
    ~0.95 indistinguishable from 0.

    ``max_fetch`` caps the number of candidates pulled from each
    underlying ranker before fusion. MMR is O(N²·D) in pure Python; with
    1536-dim embeddings (OpenAI ada) and ``limit=100``, an unbounded
    fetch can spend 1–2 s in the rerank loop alone. Default 200 keeps
    the worst case under ~50 ms per query.
    """

    limit: int = 10
    session_id: str | None = None
    vector_weight: float = 0.7
    decay_rate: float = 0.01
    mmr_lambda: float = 0.5
    fusion: Literal["rrf", "weighted"] = "rrf"
    max_fetch: int = 200
