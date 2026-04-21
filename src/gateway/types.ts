import type { AgentRuntime } from "../runtime.js";
import type { RuntimeHooks } from "../types.js";
import type { StorageBackend } from "../storage/types.js";
import type { HybridRetriever } from "../retrieval/hybrid.js";

export interface GatewayOptions {
  port?: number;
  apiKey?: string;
  storage?: StorageBackend;
  retriever?: HybridRetriever;
  createRuntime: (sessionId: string, hooks: RuntimeHooks) => AgentRuntime | Promise<AgentRuntime>;
}

export interface SessionEntry {
  runtime: AgentRuntime;
  approveResolve: (() => void) | null;
}
