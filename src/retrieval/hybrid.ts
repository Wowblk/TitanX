import type { StorageBackend } from "../storage/types.js";
import type { EmbeddingProvider, HybridRetrievalOptions, RetrievalResult } from "./types.js";
import { applyTimeDecay, mmrRerank } from "./mmr.js";

function normalizeScores(results: RetrievalResult[]): RetrievalResult[] {
  if (results.length === 0) return [];
  const max = Math.max(...results.map((r) => r.score));
  if (max === 0) return results;
  return results.map((r) => ({ ...r, score: r.score / max }));
}

// Reciprocal Rank Fusion: merges two ranked lists without needing score normalization.
function rrfMerge(
  vectorResults: RetrievalResult[],
  ftsResults: RetrievalResult[],
  vectorWeight: number,
  k = 60,
): RetrievalResult[] {
  const scores = new Map<string, { result: RetrievalResult; score: number }>();

  const addList = (list: RetrievalResult[], weight: number) => {
    list.forEach((r, rank) => {
      const existing = scores.get(r.entry.id);
      const contribution = weight * (1 / (k + rank + 1));
      if (existing) {
        existing.score += contribution;
        existing.result = { ...existing.result, source: "hybrid" };
      } else {
        scores.set(r.entry.id, { result: { ...r, source: "hybrid" }, score: contribution });
      }
    });
  };

  addList(vectorResults, vectorWeight);
  addList(ftsResults, 1 - vectorWeight);

  return [...scores.values()]
    .sort((a, b) => b.score - a.score)
    .map(({ result, score }) => ({ ...result, score }));
}

export class HybridRetriever {
  public constructor(
    private readonly storage: StorageBackend,
    private readonly embedding?: EmbeddingProvider,
  ) {}

  public async search(query: string, options: HybridRetrievalOptions = {}): Promise<RetrievalResult[]> {
    const {
      limit = 10,
      sessionId,
      vectorWeight = 0.7,
      decayRate = 0.01,
      mmrLambda = 0.5,
    } = options;

    const fetchLimit = limit * 3;

    // Always run FTS
    const ftsRaw = await this.storage.searchByFTS(query, sessionId, fetchLimit);
    const ftsResults: RetrievalResult[] = normalizeScores(
      ftsRaw.map((m) => ({ entry: m, score: m.score, source: "fts" as const })),
    );

    // Vector search if embedding provider available
    let combined: RetrievalResult[];
    if (this.embedding) {
      try {
        const queryEmbedding = await this.embedding.embed(query);
        const vecRaw = await this.storage.searchByVector(queryEmbedding, sessionId, fetchLimit);
        const vecResults: RetrievalResult[] = normalizeScores(
          vecRaw.map((m) => ({ entry: m, score: m.score, source: "vector" as const })),
        );
        combined = rrfMerge(vecResults, ftsResults, vectorWeight);
      } catch {
        // Embedding failed — fall back to FTS-only
        combined = ftsResults;
      }
    } else {
      combined = ftsResults;
    }

    // Apply time decay
    const decayed = applyTimeDecay(combined, decayRate);

    // MMR reranking for diversity
    return mmrRerank(decayed, mmrLambda, limit);
  }
}
