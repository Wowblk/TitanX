import { randomUUID } from "node:crypto";
import type { AgentState, Message, UserMessage } from "../types.js";
import type {
  CompactionOptions,
  CompactionResult,
  CompactionStrategy,
  CompactionTracking,
} from "./types.js";

const DEFAULT_MAX_PTL_RETRIES = 3;
const DEFAULT_MAX_CONSECUTIVE_FAILURES = 3;
const PTL_TRIM_RATIO = 0.2;

function nonSystemMessages(messages: Message[]): Message[] {
  return messages.filter((m) => m.role !== "system");
}

function trimOldest(messages: Message[]): Message[] | null {
  const trimCount = Math.ceil(messages.length * PTL_TRIM_RATIO);
  if (trimCount === 0 || messages.length <= trimCount) return null;
  return messages.slice(trimCount);
}

function buildSummaryMessage(summary: string): UserMessage {
  return { id: randomUUID(), role: "user", content: `[Conversation summary]\n${summary}` };
}

export async function autoCompactIfNeeded(
  state: AgentState,
  strategy: CompactionStrategy,
  options: CompactionOptions,
  tracking: CompactionTracking,
): Promise<{ wasCompacted: boolean; result?: CompactionResult; tracking: CompactionTracking }> {
  const maxConsecutiveFailures = options.maxConsecutiveFailures ?? DEFAULT_MAX_CONSECUTIVE_FAILURES;
  const maxPtlRetries = options.maxPtlRetries ?? DEFAULT_MAX_PTL_RETRIES;

  if (tracking.consecutiveFailures >= maxConsecutiveFailures) {
    return { wasCompacted: false, tracking };
  }

  if (!state.needsCompaction && state.totalInputTokens < options.tokenBudget) {
    return { wasCompacted: false, tracking };
  }

  let candidates = nonSystemMessages(state.messages);
  let summary: string | null = null;
  let ptlAttempts = 0;

  while (summary === null) {
    try {
      summary = await strategy.summarize(candidates);
    } catch {
      if (ptlAttempts >= maxPtlRetries) {
        return {
          wasCompacted: false,
          tracking: { consecutiveFailures: tracking.consecutiveFailures + 1 },
        };
      }
      const trimmed = trimOldest(candidates);
      if (trimmed === null) {
        return {
          wasCompacted: false,
          tracking: { consecutiveFailures: tracking.consecutiveFailures + 1 },
        };
      }
      candidates = trimmed;
      ptlAttempts++;
    }
  }

  const systemMessages = state.messages.filter((m) => m.role === "system");
  state.messages = [...systemMessages, buildSummaryMessage(summary)];
  state.totalInputTokens = 0;
  state.needsCompaction = false;

  return {
    wasCompacted: true,
    result: { summary, messagesRetained: state.messages.length, ptlAttempts },
    tracking: { consecutiveFailures: 0 },
  };
}
