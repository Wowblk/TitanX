from __future__ import annotations

from ..storage.types import StorageBackend
from .mmr import apply_time_decay, mmr_rerank
from .types import EmbeddingProvider, HybridRetrievalOptions, RetrievalResult


def _normalize(results: list[RetrievalResult]) -> list[RetrievalResult]:
    if not results:
        return results
    max_score = max(r.score for r in results)
    if max_score == 0:
        return results
    return [RetrievalResult(entry=r.entry, score=r.score / max_score, source=r.source) for r in results]


def _rrf_merge(
    vec_results: list[RetrievalResult],
    fts_results: list[RetrievalResult],
    vector_weight: float,
    k: int = 60,
) -> list[RetrievalResult]:
    scores: dict[str, dict] = {}

    def add_list(lst: list[RetrievalResult], weight: float) -> None:
        for rank, r in enumerate(lst):
            entry_id = r.entry.id
            contribution = weight * (1 / (k + rank + 1))
            if entry_id in scores:
                scores[entry_id]["score"] += contribution
                scores[entry_id]["result"] = RetrievalResult(entry=r.entry, score=0.0, source="hybrid")
            else:
                scores[entry_id] = {"result": RetrievalResult(entry=r.entry, score=0.0, source="hybrid"), "score": contribution}

    add_list(vec_results, vector_weight)
    add_list(fts_results, 1 - vector_weight)

    merged = sorted(scores.values(), key=lambda x: x["score"], reverse=True)
    return [RetrievalResult(entry=v["result"].entry, score=v["score"], source="hybrid") for v in merged]


class HybridRetriever:
    def __init__(self, storage: StorageBackend, embedding: EmbeddingProvider | None = None) -> None:
        self._storage = storage
        self._embedding = embedding

    async def search(self, query: str, options: HybridRetrievalOptions | None = None) -> list[RetrievalResult]:
        opts = options or HybridRetrievalOptions()
        fetch_limit = opts.limit * 3

        fts_raw = await self._storage.search_by_fts(query, opts.session_id, fetch_limit)
        fts_results = _normalize([
            RetrievalResult(entry=m, score=m.score, source="fts") for m in fts_raw
        ])

        if self._embedding:
            try:
                query_emb = await self._embedding.embed(query)
                vec_raw = await self._storage.search_by_vector(query_emb, opts.session_id, fetch_limit)
                vec_results = _normalize([
                    RetrievalResult(entry=m, score=m.score, source="vector") for m in vec_raw
                ])
                combined = _rrf_merge(vec_results, fts_results, opts.vector_weight)
            except Exception:
                combined = fts_results
        else:
            combined = fts_results

        decayed = apply_time_decay(combined, opts.decay_rate)
        return mmr_rerank(decayed, opts.mmr_lambda, opts.limit)
