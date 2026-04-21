import { performance } from "node:perf_hooks";

import type {
  SandboxBackend,
  SandboxBackendCapabilities,
  SandboxExecutionRequest,
  SandboxExecutionResult,
  SandboxFileEntry,
  SandboxSession,
  SandboxSnapshot,
} from "../types.js";

type E2BExecutorResult = {
  exitCode?: number;
  stdout?: string;
  stderr?: string;
};

type E2BCommandResult = {
  exitCode?: number;
  stdout?: string;
  stderr?: string;
};

type E2BSandboxInstance = {
  sandboxId: string;
  commands: {
    run: (cmd: string, opts?: Record<string, unknown>) => Promise<E2BCommandResult>;
  };
  files?: {
    write: (path: string, content: string) => Promise<void>;
    read: (path: string) => Promise<string>;
  };
  kill: (opts?: Record<string, unknown>) => Promise<void>;
  pause?: (opts?: Record<string, unknown>) => Promise<boolean>;
  createSnapshot?: (opts?: Record<string, unknown>) => Promise<{ snapshotId: string }>;
};

type E2BSandboxStatic = {
  create: (...args: unknown[]) => Promise<E2BSandboxInstance>;
  connect: (sandboxId: string, opts?: Record<string, unknown>) => Promise<E2BSandboxInstance>;
  kill?: (sandboxId: string, opts?: Record<string, unknown>) => Promise<boolean>;
};

type E2BModule = {
  Sandbox: E2BSandboxStatic;
};

export interface E2BSandboxBackendOptions {
  apiKey?: string;
  available?: boolean;
  executor?: (
    request: SandboxExecutionRequest,
    session?: SandboxSession,
  ) => Promise<E2BExecutorResult>;
  fileWriter?: (
    files: SandboxFileEntry[],
    session?: SandboxSession,
  ) => Promise<void>;
  fileReader?: (
    path: string,
    session?: SandboxSession,
  ) => Promise<string>;
  template?: string;
  timeoutMs?: number;
}

function quoteShell(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function buildShellCommand(request: SandboxExecutionRequest): string {
  const segments: string[] = [];
  if (request.cwd) {
    segments.push(`cd ${quoteShell(request.cwd)}`);
  }
  const argv = [request.command, ...(request.args ?? [])].map(quoteShell).join(" ");
  segments.push(argv);
  return segments.join(" && ");
}

function normalizeEnv(env?: Record<string, string>): Record<string, string> {
  if (!env) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => {
      const [key, value] = entry;
      return key.length > 0 && typeof value === "string";
    }),
  );
}

export class E2BSandboxBackend implements SandboxBackend {
  public readonly kind = "e2b" as const;
  private sdkModulePromise: Promise<E2BModule> | null = null;

  public constructor(private readonly options: E2BSandboxBackendOptions = {}) {}

  public capabilities(): SandboxBackendCapabilities {
    return {
      kind: this.kind,
      supportsPersistence: true,
      supportsSnapshots: true,
      supportsBrowser: true,
      supportsNetwork: true,
      supportsPackageInstall: true,
      supportedCapabilities: [
        "command-exec",
        "filesystem",
        "network",
        "browser",
        "package-install",
        "snapshot",
        "resume",
      ],
    };
  }

  public async isAvailable(): Promise<boolean> {
    if (typeof this.options.available === "boolean") {
      return this.options.available;
    }

    if (!this.resolveApiKey()) {
      return false;
    }

    try {
      await this.loadSdk();
      return true;
    } catch {
      return false;
    }
  }

  public async createSession(metadata?: Record<string, string>): Promise<SandboxSession> {
    const sandbox = await this.createSandbox(metadata);
    return {
      id: sandbox.sandboxId,
      backend: this.kind,
      metadata,
    };
  }

  public async destroySession(sessionId: string): Promise<void> {
    const sandbox = await this.connectSandbox(sessionId);
    await sandbox.kill();
  }

  public async writeFiles(
    files: SandboxFileEntry[],
    session?: SandboxSession,
  ): Promise<void> {
    if (this.options.fileWriter) {
      await this.options.fileWriter(files, session);
      return;
    }

    await this.withSandbox(session, async (sandbox) => {
      if (!sandbox.files?.write) {
        throw new Error("Installed E2B SDK does not expose files.write()");
      }

      for (const file of files) {
        await sandbox.files.write(file.path, file.content);
      }
    });
  }

  public async readFile(path: string, session?: SandboxSession): Promise<string> {
    if (this.options.fileReader) {
      return await this.options.fileReader(path, session);
    }

    return await this.withSandbox(session, async (sandbox) => {
      if (!sandbox.files?.read) {
        throw new Error("Installed E2B SDK does not expose files.read()");
      }

      return await sandbox.files.read(path);
    });
  }

  public async execute(
    request: SandboxExecutionRequest,
    session?: SandboxSession,
  ): Promise<SandboxExecutionResult> {
    const startedAt = performance.now();

    try {
      const result = this.options.executor
        ? await this.options.executor(request, session)
        : await this.executeWithE2B(request, session);

      return {
        backend: this.kind,
        exitCode: result.exitCode ?? 0,
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        durationMs: performance.now() - startedAt,
      };
    } catch (error) {
      return {
        backend: this.kind,
        exitCode: 1,
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error),
        durationMs: performance.now() - startedAt,
      };
    }
  }

  public async snapshot(session: SandboxSession): Promise<SandboxSnapshot> {
    const sandbox = await this.connectSandbox(session.id);
    if (!sandbox.createSnapshot) {
      throw new Error("Installed E2B SDK does not expose createSnapshot()");
    }

    const result = await sandbox.createSnapshot();
    return {
      id: result.snapshotId,
      createdAt: new Date().toISOString(),
      backend: this.kind,
    };
  }

  public async resume(snapshotId: string): Promise<SandboxSession> {
    const sdk = await this.loadSdk();
    const sandbox = this.options.template
      ? await sdk.Sandbox.create(this.options.template, {
          apiKey: this.resolveApiKey(),
          timeoutMs: this.options.timeoutMs,
          metadata: { sourceSnapshotId: snapshotId },
        })
      : await sdk.Sandbox.create(snapshotId, {
          apiKey: this.resolveApiKey(),
          timeoutMs: this.options.timeoutMs,
          metadata: { sourceSnapshotId: snapshotId },
        });

    return {
      id: sandbox.sandboxId,
      backend: this.kind,
      metadata: { sourceSnapshotId: snapshotId },
    };
  }

  private async executeWithE2B(
    request: SandboxExecutionRequest,
    session?: SandboxSession,
  ): Promise<E2BExecutorResult> {
    return await this.withSandbox(session, async (sandbox) => {
      const result = await sandbox.commands.run(buildShellCommand(request), {
        cwd: request.cwd,
        envs: normalizeEnv(request.env),
        timeoutMs: request.timeoutMs ?? this.options.timeoutMs ?? 60_000,
      });
      return {
        exitCode: result.exitCode ?? 0,
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
      };
    });
  }

  private async createSandbox(
    metadata?: Record<string, string>,
  ): Promise<E2BSandboxInstance> {
    const sdk = await this.loadSdk();
    const opts = {
      apiKey: this.resolveApiKey(),
      timeoutMs: this.options.timeoutMs,
      metadata,
    };

    if (this.options.template) {
      return await sdk.Sandbox.create(this.options.template, opts);
    }

    return await sdk.Sandbox.create(opts);
  }

  private async connectSandbox(sessionId: string): Promise<E2BSandboxInstance> {
    const sdk = await this.loadSdk();
    return await sdk.Sandbox.connect(sessionId, {
      apiKey: this.resolveApiKey(),
      timeoutMs: this.options.timeoutMs,
    });
  }

  private async loadSdk(): Promise<E2BModule> {
    if (!this.sdkModulePromise) {
      this.sdkModulePromise = import("e2b")
        .then((module) => module as E2BModule)
        .catch((error) => {
          throw new Error(
            `Failed to load E2B SDK. Install it with 'npm install e2b'. ${error instanceof Error ? error.message : String(error)}`,
          );
        });
    }

    return await this.sdkModulePromise;
  }

  private resolveApiKey(): string | undefined {
    return this.options.apiKey ?? process.env.E2B_API_KEY;
  }

  private async withSandbox<T>(
    session: SandboxSession | undefined,
    action: (sandbox: E2BSandboxInstance) => Promise<T>,
  ): Promise<T> {
    const ephemeral = !session;
    const sandbox = session ? await this.connectSandbox(session.id) : await this.createSandbox();

    try {
      return await action(sandbox);
    } finally {
      if (ephemeral) {
        await sandbox.kill().catch(() => undefined);
      }
    }
  }
}
