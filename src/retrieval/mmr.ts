import type { RetrievalResult } from "./types.js";

export function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  return denom === 0 ? 0 : dot / denom;
}

export function applyTimeDecay(results: RetrievalResult[], decayRate: number): RetrievalResult[] {
  const now = Date.now();
  return results.map((r) => {
    const ageMs = now - r.entry.createdAt.getTime();
    const ageDays = ageMs / 86_400_000;
    return { ...r, score: r.score * Math.exp(-decayRate * ageDays) };
  });
}

// Maximal Marginal Relevance reranking.
// lambda=1 → pure relevance; lambda=0 → pure diversity.
export function mmrRerank(candidates: RetrievalResult[], lambda: number, limit: number): RetrievalResult[] {
  if (candidates.length === 0) return [];

  const selected: RetrievalResult[] = [];
  const remaining = [...candidates];

  while (selected.length < limit && remaining.length > 0) {
    let bestIdx = 0;
    let bestScore = -Infinity;

    for (let i = 0; i < remaining.length; i++) {
      const relevance = remaining[i].score;
      let maxSim = 0;

      if (selected.length > 0) {
        for (const sel of selected) {
          const aEmb = remaining[i].entry.embedding;
          const bEmb = sel.entry.embedding;
          if (aEmb && bEmb) {
            const sim = cosineSimilarity(aEmb, bEmb);
            if (sim > maxSim) maxSim = sim;
          }
        }
      }

      const mmrScore = lambda * relevance - (1 - lambda) * maxSim;
      if (mmrScore > bestScore) {
        bestScore = mmrScore;
        bestIdx = i;
      }
    }

    selected.push(remaining[bestIdx]);
    remaining.splice(bestIdx, 1);
  }

  return selected;
}
