from __future__ import annotations

import math
from datetime import datetime, timezone

from .types import RetrievalResult


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity with explicit dimension validation.

    The historical implementation used ``zip(a, b)`` for the dot product,
    which **silently truncates** when the two embeddings have different
    lengths. That is the single most common production data-bug source in
    embedding pipelines (model upgrades, multi-provider routing, mid-flight
    schema migrations) and it produced mathematically meaningless numbers
    because the dot was computed over the truncated prefix while the norms
    were computed over the full vectors. We now ``raise`` instead — the
    caller's data layer is the right place to handle dimension mismatches.

    Zero-magnitude vectors are mathematically undefined under cosine; we
    return ``0.0`` so MMR treats them as "not similar to anything", which
    is the conservative answer for diversity ranking.
    """
    if len(a) != len(b):
        raise ValueError(
            f"Embedding dimension mismatch: {len(a)} vs {len(b)}. "
            "This usually indicates a stale embedding written under a "
            "different model — re-embed or filter at the storage layer."
        )
    if not a:
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    denom = math.sqrt(na) * math.sqrt(nb)
    if denom == 0.0:
        return 0.0
    return dot / denom


def _content_jaccard(a: str, b: str) -> float:
    """Token-set Jaccard similarity, used as a fallback when one or both
    candidates lack an embedding.

    The MMR diversity term needs *some* notion of "are these two items
    similar?" even when embeddings are missing (e.g. legacy rows written
    before vectorisation rolled out, or content from a tool that doesn't
    embed). The previous implementation defaulted ``max_sim`` to 0.0 in
    that case, which gifted embedding-less candidates an infinite
    diversity buff and let them crowd the result list. Jaccard is a
    crude-but-bounded ([0, 1]) substitute that keeps the algorithm
    well-defined; for production deployments with mixed-coverage
    embeddings this is materially better than the implicit "0".
    """
    ta = set(a.lower().split()) if a else set()
    tb = set(b.lower().split()) if b else set()
    if not ta and not tb:
        return 0.0
    union = ta | tb
    if not union:
        return 0.0
    return len(ta & tb) / len(union)


def _pairwise_similarity(a_entry, b_entry) -> float:
    """Pick the best similarity proxy available between two entries.

    Embedding cosine when both have one (the strong signal), token Jaccard
    otherwise (the weak fallback). We deliberately do NOT mix the two:
    asymmetric "cosine on one side, Jaccard on the other" produces
    incoherent rankings.
    """
    a_emb = a_entry.embedding
    b_emb = b_entry.embedding
    if a_emb and b_emb:
        return cosine_similarity(a_emb, b_emb)
    return _content_jaccard(a_entry.content, b_entry.content)


def apply_time_decay(
    results: list[RetrievalResult], decay_rate: float
) -> list[RetrievalResult]:
    """Multiply each result's score by ``exp(-decay_rate * age_days)``.

    Time-zone correctness: ``datetime.timestamp()`` on a *naive* datetime
    interprets the value as local time — so a row written with
    ``datetime.utcnow()`` (naive UTC) on a host in UTC+8 historically
    produced an age that was off by 8/24 ≈ 0.33 days. We now use
    ``datetime`` arithmetic and force naive datetimes to UTC by
    convention, matching what every storage backend in this repo writes.
    Negative ages (clock skew, future-dated entries) are clamped to 0 so
    new arrivals don't get a relevance boost above 1.0.
    """
    now_utc = datetime.now(timezone.utc)
    out = []
    for r in results:
        created = r.entry.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = max(0.0, (now_utc - created).total_seconds() / 86_400)
        out.append(RetrievalResult(
            entry=r.entry,
            score=r.score * math.exp(-decay_rate * age_days),
            source=r.source,
        ))
    return out


def mmr_rerank(
    candidates: list[RetrievalResult], lmbda: float, limit: int
) -> list[RetrievalResult]:
    """Maximal Marginal Relevance with scale-corrected relevance.

    The textbook MMR formula is ``λ·rel(i) − (1−λ)·max_sim(i, S)`` where
    ``rel`` and ``max_sim`` are expected to live on comparable scales
    (typically both in [0, 1]). The historical implementation passed the
    raw fusion score through as ``rel`` — but RRF scores live in
    ~[0.001, 0.05] while cosine sim lives in [0, 1], so the diversity
    term was ~20× louder than the relevance term and ``λ`` was
    effectively ignored. We now min-max normalise the relevance side so
    the dial actually controls the trade-off it advertises.

    ``λ=1`` → pure relevance ranking.
    ``λ=0`` → pure diversity (greedy max-min covering).
    """
    if not candidates:
        return []
    if limit <= 0:
        return []

    # Scale-correct relevance. Without this, MMR's diversity term swamps
    # relevance whenever the fusion stage produces small scores (RRF
    # routinely does — top-1 ≈ 0.016 at k=60), making λ a no-op below ~0.95.
    scores = [c.score for c in candidates]
    rel_max = max(scores)
    rel_min = min(scores)
    span = rel_max - rel_min
    if span <= 0:
        # All relevances identical — every selection is purely about
        # diversity, so any constant in [0, 1] works for the relevance term.
        def normalised(_r: RetrievalResult) -> float:
            return 1.0
    else:
        def normalised(r: RetrievalResult) -> float:
            return (r.score - rel_min) / span

    selected: list[RetrievalResult] = []
    remaining = list(candidates)

    while len(selected) < limit and remaining:
        best_idx = 0
        best_score = float("-inf")

        for i, candidate in enumerate(remaining):
            relevance = normalised(candidate)
            max_sim = 0.0
            for sel in selected:
                sim = _pairwise_similarity(candidate.entry, sel.entry)
                if sim > max_sim:
                    max_sim = sim

            mmr_score = lmbda * relevance - (1 - lmbda) * max_sim
            if mmr_score > best_score:
                best_score = mmr_score
                best_idx = i

        selected.append(remaining.pop(best_idx))

    return selected
