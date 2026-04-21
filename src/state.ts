import { randomUUID } from "node:crypto";
import type {
  AgentConfig,
  AgentState,
  Message,
  PendingApproval,
  ToolDefinition,
} from "./types.js";

function randomId(): string {
  return randomUUID();
}

export interface CreateConfigInput {
  userId?: string;
  channel?: string;
  systemPrompt?: string;
  availableTools?: ToolDefinition[];
  maxIterations?: number;
  autoApproveTools?: boolean;
}

export function createConfig(input: CreateConfigInput = {}): AgentConfig {
  return {
    threadId: randomId(),
    sessionId: randomId(),
    userId: input.userId ?? "default",
    channel: input.channel ?? "repl",
    systemPrompt: input.systemPrompt ?? "",
    availableTools: input.availableTools ?? [],
    maxIterations: input.maxIterations ?? 10,
    autoApproveTools: input.autoApproveTools ?? false,
  };
}

export function createInitialState(messages?: Message[]): AgentState {
  return {
    signal: "continue",
    iteration: 0,
    consecutiveToolIntentNudges: 0,
    forceText: false,
    messages: messages ?? [],
    pendingApproval: null,
    lastResponseType: "none",
    lastTextResponse: "",
    needsCompaction: false,
    totalInputTokens: 0,
    totalOutputTokens: 0,
  };
}

export function appendMessage(state: AgentState, message: Message): void {
  state.messages.push(message);
}

export function setPendingApproval(state: AgentState, approval: PendingApproval | null): void {
  state.pendingApproval = approval;
}
