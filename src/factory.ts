import { AgentRuntime } from "./runtime.js";
import {
  DockerSandboxBackend,
  E2BSandboxBackend,
  SandboxRouter,
  SandboxedToolRuntime,
  WasmSandboxBackend,
  type SandboxBackend,
  type SandboxedToolHandler,
  type WasmCommandRegistration,
} from "./sandbox/index.js";
import { ResilientSandboxBackend, type ResilientOptions } from "./resilience/resilient-backend.js";
import type { CreateConfigInput } from "./state.js";
import type { PolicyStore } from "./policy/index.js";
import type { CompactionOptions, CompactionStrategy } from "./context/types.js";
import type {
  LlmAdapter,
  RuntimeHooks,
  SafetyLayerLike,
} from "./types.js";
import type { RuntimeDirectories } from "./sandbox/types.js";

export interface CreateSandboxedRuntimeOptions {
  llm: LlmAdapter;
  safety: SafetyLayerLike;
  config: CreateConfigInput;
  hooks?: RuntimeHooks;
  backends?: SandboxBackend[];
  toolHandlers?: SandboxedToolHandler[];
  wasmCommands?: Record<string, WasmCommandRegistration>;
  directories?: Partial<RuntimeDirectories>;
  allowedWritePaths?: string[];
  policyStore?: PolicyStore;
  compactionStrategy?: CompactionStrategy;
  compactionOptions?: CompactionOptions;
  resilientOptions?: ResilientOptions;
}

const DEFAULT_SANDBOXED_TOOL_HANDLERS: SandboxedToolHandler[] = [
  {
    definition: {
      name: "run_wasm_command",
      description: "Execute a registered low-risk command in the WASI sandbox backend.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "Registered WASI command name" },
          args: {
            type: "array",
            items: { type: "string" },
            description: "Optional argv passed to the WASI module",
          },
        },
        required: ["command"],
      },
      requiresApproval: true,
      requiresSanitization: true,
    },
    policy: {
      preferredBackend: "wasm",
      riskLevel: "low",
    },
    request(params) {
      const command = typeof params.command === "string" ? params.command : "";
      const args = Array.isArray(params.args)
        ? params.args.filter((value): value is string => typeof value === "string")
        : undefined;
      return { command, args };
    },
  },
  {
    definition: {
      name: "run_command",
      description: "Execute a command in the selected sandbox backend.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "Command to execute" },
          args: {
            type: "array",
            items: { type: "string" },
            description: "Optional argv passed to the command",
          },
          cwd: { type: "string", description: "Optional working directory" },
        },
        required: ["command"],
      },
      requiresApproval: true,
      requiresSanitization: true,
    },
    policy: {
      riskLevel: "medium",
      needsFilesystem: true,
    },
    request(params) {
      const command = typeof params.command === "string" ? params.command : "";
      const args = Array.isArray(params.args)
        ? params.args.filter((value): value is string => typeof value === "string")
        : undefined;
      const cwd = typeof params.cwd === "string" ? params.cwd : undefined;
      return { command, args, cwd };
    },
  },
  {
    definition: {
      name: "run_browser_task",
      description: "Execute a browser-oriented task in a remote isolated sandbox.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "Browser task command to execute" },
          args: {
            type: "array",
            items: { type: "string" },
            description: "Optional argv passed to the browser task",
          },
        },
        required: ["command"],
      },
      requiresApproval: true,
      requiresSanitization: true,
    },
    policy: {
      riskLevel: "high",
      needsBrowser: true,
      requiresRemoteIsolation: true,
    },
    request(params) {
      const command = typeof params.command === "string" ? params.command : "";
      const args = Array.isArray(params.args)
        ? params.args.filter((value): value is string => typeof value === "string")
        : undefined;
      return { command, args };
    },
  },
];

function createDefaultBackends(
  wasmCommands?: Record<string, WasmCommandRegistration>,
  directories?: Partial<RuntimeDirectories>,
  resilientOptions?: ResilientOptions,
): SandboxBackend[] {
  const raw: SandboxBackend[] = [
    new WasmSandboxBackend({
      commands: wasmCommands,
      logDir: directories?.logs,
      cacheDir: directories?.cache,
    }),
    new DockerSandboxBackend(),
    new E2BSandboxBackend(),
  ];
  if (!resilientOptions) return raw;
  return raw.map((b) => new ResilientSandboxBackend(b, resilientOptions));
}

export function createSandboxedRuntime(
  options: CreateSandboxedRuntimeOptions,
): AgentRuntime {
  const router = new SandboxRouter(
    options.backends ?? createDefaultBackends(options.wasmCommands, options.directories, options.resilientOptions),
  );
  const tools = new SandboxedToolRuntime(
    router,
    options.toolHandlers ?? DEFAULT_SANDBOXED_TOOL_HANDLERS,
    options.allowedWritePaths,
    options.policyStore,
  );

  return new AgentRuntime(
    options.llm,
    tools,
    options.safety,
    options.config,
    options.hooks,
    options.policyStore,
    options.compactionStrategy,
    options.compactionOptions,
  );
}
