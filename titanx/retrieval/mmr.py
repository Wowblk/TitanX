from __future__ import annotations

import math
import time

from .types import RetrievalResult


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na * nb else 0.0


def apply_time_decay(results: list[RetrievalResult], decay_rate: float) -> list[RetrievalResult]:
    now = time.time()
    out = []
    for r in results:
        age_days = (now - r.entry.created_at.timestamp()) / 86_400
        out.append(RetrievalResult(
            entry=r.entry,
            score=r.score * math.exp(-decay_rate * age_days),
            source=r.source,
        ))
    return out


def mmr_rerank(candidates: list[RetrievalResult], lmbda: float, limit: int) -> list[RetrievalResult]:
    """Maximal Marginal Relevance. lmbda=1 → pure relevance; lmbda=0 → pure diversity."""
    if not candidates:
        return []

    selected: list[RetrievalResult] = []
    remaining = list(candidates)

    while len(selected) < limit and remaining:
        best_idx = 0
        best_score = float("-inf")

        for i, candidate in enumerate(remaining):
            relevance = candidate.score
            max_sim = 0.0

            if selected:
                a_emb = candidate.entry.embedding
                for sel in selected:
                    b_emb = sel.entry.embedding
                    if a_emb and b_emb:
                        sim = cosine_similarity(a_emb, b_emb)
                        if sim > max_sim:
                            max_sim = sim

            mmr_score = lmbda * relevance - (1 - lmbda) * max_sim
            if mmr_score > best_score:
                best_score = mmr_score
                best_idx = i

        selected.append(remaining.pop(best_idx))

    return selected
