import { randomUUID } from "node:crypto";
import {
  appendMessage,
  createConfig,
  createInitialState,
  setPendingApproval,
  type CreateConfigInput,
} from "./state.js";
import type { ReadonlyPolicyView } from "./policy/index.js";
import { autoCompactIfNeeded } from "./context/compactor.js";
import type { CompactionOptions, CompactionStrategy, CompactionTracking } from "./context/types.js";
import type {
  AgentConfig,
  AgentState,
  AssistantMessage,
  LlmAdapter,
  PendingApproval,
  RuntimeEvent,
  RuntimeHooks,
  SafetyLayerLike,
  ToolCall,
  ToolRuntime,
  ToolMessage,
  UserMessage,
} from "./types.js";

function messageId(): string {
  return randomUUID();
}

export class AgentRuntime {
  public readonly config: AgentConfig;
  public readonly state: AgentState;
  private compactionTracking: CompactionTracking = { consecutiveFailures: 0 };

  public constructor(
    private readonly llm: LlmAdapter,
    private readonly tools: ToolRuntime,
    private readonly safety: SafetyLayerLike,
    configInput: CreateConfigInput = {},
    private readonly hooks: RuntimeHooks = {},
    private readonly policyStore?: ReadonlyPolicyView,
    private readonly compactionStrategy?: CompactionStrategy,
    private readonly compactionOptions?: CompactionOptions,
  ) {
    this.config = createConfig({
      ...configInput,
      availableTools: configInput.availableTools ?? tools.listTools(),
    });
    this.state = createInitialState();
  }

  private get effectiveMaxIterations(): number {
    return this.policyStore?.getPolicy().maxIterations ?? this.config.maxIterations;
  }

  private get effectiveAutoApproveTools(): boolean {
    return this.policyStore?.getPolicy().autoApproveTools ?? this.config.autoApproveTools;
  }

  public async runPrompt(content: string): Promise<AgentState> {
    const inputCheck = this.safety.checkInput(content);
    if (!inputCheck.safe) {
      throw new Error(`Unsafe input blocked: ${inputCheck.violations.map((v) => v.pattern).join(", ")}`);
    }

    const validation = this.safety.validator.validateInput(content, "input");
    if (!validation.isValid) {
      throw new Error(
        `Invalid input: ${validation.errors.map((issue) => `${issue.field}: ${issue.message}`).join("; ")}`,
      );
    }

    const userMessage: UserMessage = {
      id: messageId(),
      role: "user",
      content: inputCheck.sanitizedContent,
    };
    appendMessage(this.state, userMessage);

    await this.emit({ type: "loop_start" });
    this.state.signal = "continue";
    return this.runLoop();
  }

  public approvePendingTool(): void {
    setPendingApproval(this.state, null);
    this.state.signal = "continue";
    this.state.lastResponseType = "none";
  }

  public async resume(): Promise<AgentState> {
    if (this.state.signal !== "continue") return this.state;
    return this.runLoop();
  }

  private async runLoop(): Promise<AgentState> {
    while (this.state.signal !== "stop") {
      this.state.iteration += 1;
      await this.emit({ type: "iteration_start", iteration: this.state.iteration });

      if (this.state.iteration > this.effectiveMaxIterations) {
        this.state.signal = "stop";
        await this.emit({ type: "loop_end", reason: "max_iterations" });
        break;
      }

      const turn = await this.llm.respond(this.config, this.state);
      this.state.totalInputTokens += turn.usage?.inputTokens ?? 0;
      this.state.totalOutputTokens += turn.usage?.outputTokens ?? 0;

      if (this.compactionStrategy && this.compactionOptions) {
        const compact = await autoCompactIfNeeded(
          this.state,
          this.compactionStrategy,
          this.compactionOptions,
          this.compactionTracking,
        );
        const prevFailures = this.compactionTracking.consecutiveFailures;
        this.compactionTracking = compact.tracking;
        if (compact.wasCompacted && compact.result) {
          await this.emit({
            type: "compaction_triggered",
            summary: compact.result.summary,
            ptlAttempts: compact.result.ptlAttempts,
          });
        } else if (!compact.wasCompacted && compact.tracking.consecutiveFailures > prevFailures) {
          await this.emit({
            type: "compaction_failed",
            consecutiveFailures: compact.tracking.consecutiveFailures,
          });
        }
      }

      if (turn.type === "text") {
        const text = turn.text ?? "";
        const assistantMessage: AssistantMessage = { id: messageId(), role: "assistant", content: text };
        appendMessage(this.state, assistantMessage);
        this.state.lastResponseType = "text";
        this.state.lastTextResponse = text;
        await this.emit({ type: "assistant_text", text });
        this.state.signal = "stop";
        await this.emit({ type: "loop_end", reason: "completed" });
        break;
      }

      const toolCalls = turn.toolCalls ?? [];
      const assistantMessage: AssistantMessage = {
        id: messageId(),
        role: "assistant",
        content: turn.text ?? "",
        toolCalls,
      };
      appendMessage(this.state, assistantMessage);
      this.state.lastResponseType = "tool_calls";
      await this.emit({ type: "assistant_tool_calls", toolCalls });

      const outcome = await this.executeToolCalls(toolCalls);
      if (outcome === "pending_approval") {
        this.state.lastResponseType = "need_approval";
        this.state.signal = "stop";
        await this.emit({ type: "loop_end", reason: "pending_approval" });
        break;
      }

      this.state.lastResponseType = "none";
    }

    return this.state;
  }

  private async executeToolCalls(toolCalls: ToolCall[]): Promise<"continue" | "pending_approval"> {
    for (const toolCall of toolCalls) {
      const toolDef = this.config.availableTools.find((tool) => tool.name === toolCall.name);
      const validation = this.safety.validator.validateToolParams(toolCall.args);
      if (!validation.isValid) {
        appendMessage(
          this.state,
          this.buildToolMessage(toolCall, `Invalid tool parameters: ${validation.errors.map((e) => e.message).join("; ")}`, true),
        );
        continue;
      }

      if (toolDef?.requiresApproval && !this.effectiveAutoApproveTools) {
        const approval: PendingApproval = {
          toolName: toolCall.name,
          toolCallId: toolCall.id,
          parameters: toolCall.args,
          requiresAlways: true,
        };
        setPendingApproval(this.state, approval);
        await this.emit({ type: "pending_approval", approval });
        return "pending_approval";
      }

      const result = await this.tools.execute(toolCall.name, toolCall.args);
      const content = toolDef?.requiresSanitization
        ? this.safety.sanitizeToolOutput(toolCall.name, result.output).content
        : result.output;
      const isError = Boolean(result.error);
      appendMessage(this.state, this.buildToolMessage(toolCall, content, isError));
      await this.emit({
        type: "tool_result",
        toolName: toolCall.name,
        toolCallId: toolCall.id,
        isError,
      });
    }

    return "continue";
  }

  private buildToolMessage(toolCall: ToolCall, content: string, isError: boolean): ToolMessage {
    return {
      id: messageId(),
      role: "tool",
      toolName: toolCall.name,
      toolCallId: toolCall.id,
      content,
      isError,
    };
  }

  private async emit(event: RuntimeEvent): Promise<void> {
    await this.hooks.onEvent?.(event, this.config, this.state);
  }
}
