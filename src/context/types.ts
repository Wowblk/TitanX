import type { Message } from "../types.js";

export interface CompactionStrategy {
  summarize(messages: Message[]): Promise<string>;
}

export interface CompactionOptions {
  tokenBudget: number;
  maxPtlRetries?: number;
  maxConsecutiveFailures?: number;
}

export interface CompactionTracking {
  consecutiveFailures: number;
}

export interface CompactionResult {
  summary: string;
  messagesRetained: number;
  ptlAttempts: number;
}
