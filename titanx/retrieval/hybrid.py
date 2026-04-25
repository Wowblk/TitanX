from __future__ import annotations

from typing import Callable

from ..storage.types import StorageBackend
from .mmr import apply_time_decay, mmr_rerank
from .types import EmbeddingProvider, HybridRetrievalOptions, RetrievalResult


def _clamp_weight(w: float) -> float:
    """RRF math goes negative when ``weight < 0`` (silent ranking inversion)
    and weighted-sum becomes meaningless above 1; clamp defensively."""
    if w < 0:
        return 0.0
    if w > 1:
        return 1.0
    return w


def _rrf_merge(
    vec_results: list[RetrievalResult],
    fts_results: list[RetrievalResult],
    vector_weight: float,
    k: int = 60,
) -> list[RetrievalResult]:
    """Reciprocal Rank Fusion — rank-based combiner.

    The classical RRF formula is ``sum_l 1 / (k + rank_l(i))`` summed over
    every list ``l`` that contains item ``i``. We extend it by a per-list
    multiplier (the legacy ``vector_weight`` knob) but document explicitly
    that **this multiplier has weaker authority than callers usually
    expect** — both lists' top-1 contributions sit within the same
    ~1/(k+1) order of magnitude. For score-based weighting use the
    ``"weighted"`` fusion mode.

    Implementation note: we no longer pre-normalise the input lists with
    ``_normalize`` because RRF reads only ``rank``, not ``score``. The
    historical normalize step was a costly no-op.
    """
    scores: dict[str, dict] = {}

    def add_list(lst: list[RetrievalResult], weight: float) -> None:
        for rank, r in enumerate(lst):
            entry_id = r.entry.id
            contribution = weight * (1 / (k + rank + 1))
            if entry_id in scores:
                scores[entry_id]["score"] += contribution
            else:
                scores[entry_id] = {
                    "entry": r.entry,
                    "score": contribution,
                }

    add_list(vec_results, vector_weight)
    add_list(fts_results, 1 - vector_weight)

    merged = sorted(scores.values(), key=lambda x: x["score"], reverse=True)
    return [RetrievalResult(entry=v["entry"], score=v["score"], source="hybrid") for v in merged]


def _min_max(values: list[float]) -> tuple[float, float]:
    return (min(values), max(values)) if values else (0.0, 0.0)


def _weighted_merge(
    vec_results: list[RetrievalResult],
    fts_results: list[RetrievalResult],
    vector_weight: float,
) -> list[RetrievalResult]:
    """Score-based combiner: per-list min-max normalise then linearly mix.

    This is the combiner that actually matches the user's mental model
    when they read ``vector_weight=0.7`` as "70 % vector, 30 % FTS". Each
    list is independently normalised to [0, 1] (so BM25's long-tail
    distribution and cosine's [-1, 1] distribution become comparable),
    items missing from one list contribute 0 from that side, and the
    final score is a convex combination.

    A union-of-lists is always preferred over an intersection here:
    high-quality FTS-only or vector-only hits are common (the two
    rankers disagree on what's relevant by design), and dropping them
    would lose recall.
    """
    def _normalise(lst: list[RetrievalResult]) -> dict[str, tuple[RetrievalResult, float]]:
        if not lst:
            return {}
        vals = [r.score for r in lst]
        lo, hi = _min_max(vals)
        span = hi - lo
        out: dict[str, tuple[RetrievalResult, float]] = {}
        for r in lst:
            normalised_score = (r.score - lo) / span if span > 0 else 1.0
            out[r.entry.id] = (r, normalised_score)
        return out

    vec_n = _normalise(vec_results)
    fts_n = _normalise(fts_results)

    out: list[RetrievalResult] = []
    for entry_id in set(vec_n) | set(fts_n):
        v = vec_n.get(entry_id)
        f = fts_n.get(entry_id)
        v_score = v[1] if v else 0.0
        f_score = f[1] if f else 0.0
        score = vector_weight * v_score + (1 - vector_weight) * f_score
        # Use whichever list saw the entry as the canonical source; vector
        # wins ties because it usually carries the embedding payload.
        entry = (v[0] if v else f[0]).entry  # type: ignore[union-attr]
        out.append(RetrievalResult(entry=entry, score=score, source="hybrid"))

    out.sort(key=lambda r: r.score, reverse=True)
    return out


# Hook signature for embedding-provider failures. ``HybridRetriever``
# silently falls back to FTS-only when the embedder raises, which is the
# right availability behaviour but is a black box for ops. Wire this to
# the audit log / metrics / dashboard alert so degraded-mode retrieval is
# observable. Implementations must not raise — exceptions are swallowed.
EmbeddingErrorHook = Callable[[Exception], None]


class HybridRetriever:
    def __init__(
        self,
        storage: StorageBackend,
        embedding: EmbeddingProvider | None = None,
        *,
        on_embedding_error: EmbeddingErrorHook | None = None,
    ) -> None:
        self._storage = storage
        self._embedding = embedding
        self._on_embedding_error = on_embedding_error

    async def search(
        self, query: str, options: HybridRetrievalOptions | None = None
    ) -> list[RetrievalResult]:
        opts = options or HybridRetrievalOptions()
        # Cap fetch_limit so MMR's O(N²) loop doesn't melt under aggressive
        # ``opts.limit`` settings. ``max_fetch`` is the user-facing knob.
        fetch_limit = min(opts.limit * 3, opts.max_fetch)
        vector_weight = _clamp_weight(opts.vector_weight)

        fts_raw = await self._storage.search_by_fts(query, opts.session_id, fetch_limit)
        fts_results = [
            RetrievalResult(entry=m, score=m.score, source="fts") for m in fts_raw
        ]

        vec_results: list[RetrievalResult] = []
        embedding_failed = False
        if self._embedding:
            try:
                query_emb = await self._embedding.embed(query)
                vec_raw = await self._storage.search_by_vector(
                    query_emb, opts.session_id, fetch_limit,
                )
                vec_results = [
                    RetrievalResult(entry=m, score=m.score, source="vector")
                    for m in vec_raw
                ]
            except Exception as exc:
                # Availability-first: fall back to FTS-only retrieval rather
                # than failing the request. But surface the failure via the
                # hook so the host can alert / record degraded mode in the
                # audit log. Never let an observability bug break retrieval.
                embedding_failed = True
                if self._on_embedding_error is not None:
                    try:
                        self._on_embedding_error(exc)
                    except Exception:
                        pass

        if vec_results and not embedding_failed:
            if opts.fusion == "weighted":
                combined = _weighted_merge(vec_results, fts_results, vector_weight)
            else:
                combined = _rrf_merge(vec_results, fts_results, vector_weight)
        else:
            # Either there's no embedding provider, or it just failed. Either
            # way, FTS-only path. We still flow through decay + MMR so the
            # caller gets uniformly-shaped output.
            combined = [
                RetrievalResult(entry=r.entry, score=r.score, source="hybrid")
                for r in fts_results
            ]

        decayed = apply_time_decay(combined, opts.decay_rate)
        return mmr_rerank(decayed, opts.mmr_lambda, opts.limit)
