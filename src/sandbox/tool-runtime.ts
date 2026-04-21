import type { ToolDefinition, ToolExecutionResult, ToolRuntime } from "../types.js";
import type { ReadonlyPolicyView } from "../policy/index.js";
import { SandboxRouter } from "./router.js";
import { extractShellWriteTargets, isPathAllowed } from "./path-guard.js";
import type {
  SandboxExecutionRequest,
  SandboxRouterInput,
  SandboxToolPolicy,
} from "./types.js";

export interface SandboxedToolHandler {
  definition: ToolDefinition;
  request(params: Record<string, unknown>): SandboxExecutionRequest;
  policy?: SandboxToolPolicy;
}

export class SandboxedToolRuntime implements ToolRuntime {
  private readonly handlers = new Map<string, SandboxedToolHandler>();

  public constructor(
    private readonly router: SandboxRouter,
    handlers: SandboxedToolHandler[],
    private readonly allowedWritePaths?: string[],
    private readonly policyStore?: ReadonlyPolicyView,
  ) {
    for (const handler of handlers) {
      this.handlers.set(handler.definition.name, handler);
    }
  }

  public listTools(): ToolDefinition[] {
    return [...this.handlers.values()].map((handler) => handler.definition);
  }

  public async execute(
    name: string,
    params: Record<string, unknown>,
  ): Promise<ToolExecutionResult> {
    const handler = this.handlers.get(name);
    if (!handler) {
      return {
        output: `Unknown tool: ${name}`,
        error: "unknown_tool",
      };
    }

    const request = handler.request(params);

    const effectivePaths = this.policyStore
      ? this.policyStore.getPolicy().allowedWritePaths
      : this.allowedWritePaths;
    if (effectivePaths && effectivePaths.length > 0) {
      const denied = this.checkWritePaths(request, effectivePaths);
      if (denied) {
        return { output: denied, error: "path_not_allowed" };
      }
    }

    const selection = await this.router.select(this.policyToRouterInput(handler.policy));
    const result = await selection.backend.execute(request);
    const prefix = `[sandbox:${selection.backend.kind}]`;
    const content =
      result.stdout.trim().length > 0
        ? `${prefix} ${result.stdout}`.trim()
        : `${prefix} exit=${result.exitCode}`.trim();

    return {
      output: content,
      error: result.exitCode === 0 ? undefined : result.stderr || `exit_code_${result.exitCode}`,
    };
  }

  private checkWritePaths(request: SandboxExecutionRequest, allowedPaths: string[]): string | null {
    if (request.cwd && !isPathAllowed(request.cwd, allowedPaths)) {
      return `Working directory '${request.cwd}' is not permitted by the path whitelist`;
    }

    const writeTargets = extractShellWriteTargets(request.command, request.args);
    for (const target of writeTargets) {
      if (!isPathAllowed(target, allowedPaths)) {
        return `Write to '${target}' is not permitted by the path whitelist`;
      }
    }

    return null;
  }

  private policyToRouterInput(policy?: SandboxToolPolicy): SandboxRouterInput {
    return {
      preferredBackend: policy?.preferredBackend,
      riskLevel: policy?.riskLevel,
      requiresRemoteIsolation: policy?.requiresRemoteIsolation,
      needsFilesystem: policy?.needsFilesystem,
      needsNetwork: policy?.needsNetwork,
      needsBrowser: policy?.needsBrowser,
      needsPackageInstall: policy?.needsPackageInstall,
    };
  }
}
