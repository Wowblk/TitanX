export type Role = "system" | "user" | "assistant" | "tool";

export type LoopSignal = "continue" | "stop" | "interrupt";

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  requiresApproval?: boolean;
  requiresSanitization?: boolean;
}

export interface ToolCall {
  id: string;
  name: string;
  args: Record<string, unknown>;
}

export interface PendingApproval {
  toolName: string;
  toolCallId: string;
  parameters: Record<string, unknown>;
  requiresAlways: boolean;
}

export interface MessageBase {
  id: string;
  role: Role;
}

export interface SystemMessage extends MessageBase {
  role: "system";
  content: string;
}

export interface UserMessage extends MessageBase {
  role: "user";
  content: string;
}

export interface AssistantMessage extends MessageBase {
  role: "assistant";
  content: string;
  toolCalls?: ToolCall[];
}

export interface ToolMessage extends MessageBase {
  role: "tool";
  toolName: string;
  toolCallId: string;
  content: string;
  isError?: boolean;
}

export type Message = SystemMessage | UserMessage | AssistantMessage | ToolMessage;

export type LastResponseType = "text" | "tool_calls" | "none" | "need_approval";

export interface AgentConfig {
  readonly threadId: string;
  readonly sessionId: string;
  readonly userId: string;
  readonly channel: string;
  readonly systemPrompt: string;
  readonly availableTools: ReadonlyArray<ToolDefinition>;
  readonly maxIterations: number;
  readonly autoApproveTools: boolean;
}

export interface AgentState {
  signal: LoopSignal;
  iteration: number;
  consecutiveToolIntentNudges: number;
  forceText: boolean;
  messages: Message[];
  pendingApproval: PendingApproval | null;
  lastResponseType: LastResponseType;
  lastTextResponse: string;
  needsCompaction: boolean;
  totalInputTokens: number;
  totalOutputTokens: number;
}

export interface LlmUsage {
  inputTokens?: number;
  outputTokens?: number;
}

export interface LlmTurnResult {
  type: "text" | "tool_calls";
  text?: string;
  toolCalls?: ToolCall[];
  usage?: LlmUsage;
}

export interface ToolExecutionResult {
  output: string;
  error?: string;
}

export interface ValidationIssue {
  field: string;
  message: string;
  code: string;
  severity: "warning" | "error";
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
}

export interface SafetyResult {
  safe: boolean;
  sanitizedContent: string;
  violations: Array<{
    pattern: string;
    action: "warn" | "sanitize" | "block" | "review";
  }>;
}

export interface ValidatorLike {
  validateInput(content: string, field?: string): ValidationResult;
  validateToolParams(params: Record<string, unknown>): ValidationResult;
}

export interface SafetyLayerLike {
  validator: ValidatorLike;
  checkInput(content: string): SafetyResult;
  sanitizeToolOutput(toolName: string, output: string): { content: string };
}

export interface LlmAdapter {
  respond(config: AgentConfig, state: AgentState): Promise<LlmTurnResult>;
}

export interface ToolRuntime {
  listTools(): ToolDefinition[];
  execute(name: string, params: Record<string, unknown>): Promise<ToolExecutionResult>;
}

export interface RuntimeHooks {
  onEvent?(event: RuntimeEvent, config: AgentConfig, state: AgentState): Promise<void> | void;
}

export type RuntimeEvent =
  | { type: "loop_start" }
  | { type: "iteration_start"; iteration: number }
  | { type: "assistant_text"; text: string }
  | { type: "assistant_tool_calls"; toolCalls: ToolCall[] }
  | { type: "tool_result"; toolName: string; toolCallId: string; isError: boolean }
  | { type: "pending_approval"; approval: PendingApproval }
  | { type: "loop_end"; reason: string }
  | { type: "compaction_triggered"; summary: string; ptlAttempts: number }
  | { type: "compaction_failed"; consecutiveFailures: number };
