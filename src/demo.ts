import { createSandboxedRuntime } from "./factory.js";
import type { CreateConfigInput } from "./state.js";
import type {
  AgentConfig,
  AgentState,
  LlmAdapter,
  LlmTurnResult,
  SafetyLayerLike,
  ValidationResult,
} from "./types.js";

class DemoLlmAdapter implements LlmAdapter {
  public async respond(_config: AgentConfig, state: AgentState): Promise<LlmTurnResult> {
    const alreadyCalledTool = state.messages.some(
      (message) => message.role === "tool" && message.toolName === "run_wasm_command",
    );

    if (!alreadyCalledTool) {
      return {
        type: "tool_calls",
        toolCalls: [
          {
            id: "toolcall-demo-wasm",
            name: "run_wasm_command",
            args: {
              command: "hello",
              args: ["Titanclaw-ts"],
            },
          },
        ],
      };
    }

    return {
      type: "text",
      text: "WASM demo completed.",
    };
  }
}

function validResult(): ValidationResult {
  return {
    isValid: true,
    errors: [],
    warnings: [],
  };
}

const demoSafetyLayer: SafetyLayerLike = {
  validator: {
    validateInput(): ValidationResult {
      return validResult();
    },
    validateToolParams(): ValidationResult {
      return validResult();
    },
  },
  checkInput(content: string) {
    return {
      safe: true,
      sanitizedContent: content,
      violations: [],
    };
  },
  sanitizeToolOutput(_toolName: string, output: string) {
    return { content: output };
  },
};

export function createDemoRuntime(helloModulePath: string) {
  const config: CreateConfigInput = {
    maxIterations: 4,
    autoApproveTools: true,
  };

  return createSandboxedRuntime({
    llm: new DemoLlmAdapter(),
    safety: demoSafetyLayer,
    config,
    wasmCommands: {
      hello: {
        modulePath: helloModulePath,
      },
    },
  });
}
