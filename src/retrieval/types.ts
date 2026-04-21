import type { MemoryEntry } from "../storage/types.js";

export interface EmbeddingProvider {
  embed(text: string): Promise<number[]>;
}

export interface RetrievalResult {
  entry: MemoryEntry;
  score: number;
  source: "vector" | "fts" | "hybrid";
}

export interface HybridRetrievalOptions {
  limit?: number;
  sessionId?: string;
  vectorWeight?: number;   // 0–1, weight for vector score (default 0.7)
  decayRate?: number;      // time decay per day (default 0.01)
  mmrLambda?: number;      // MMR diversity trade-off 0–1 (default 0.5)
}
