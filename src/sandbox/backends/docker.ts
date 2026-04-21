import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { Buffer } from "node:buffer";
import { dirname } from "node:path";

import type {
  SandboxBackend,
  SandboxBackendCapabilities,
  SandboxExecutionRequest,
  SandboxExecutionResult,
  SandboxFileEntry,
  SandboxSession,
  SandboxSnapshot,
} from "../types.js";

type DockerExecutorResult = {
  exitCode?: number;
  stdout?: string;
  stderr?: string;
};

type DockerCommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export interface DockerSandboxBackendOptions {
  available?: boolean;
  executor?: (
    request: SandboxExecutionRequest,
    session?: SandboxSession,
  ) => Promise<DockerExecutorResult>;
  fileWriter?: (
    files: SandboxFileEntry[],
    session?: SandboxSession,
  ) => Promise<void>;
  fileReader?: (
    path: string,
    session?: SandboxSession,
  ) => Promise<string>;
  snapshotCreator?: (session: SandboxSession) => Promise<SandboxSnapshot>;
  snapshotResumer?: (snapshotId: string) => Promise<SandboxSession>;
  dockerBin?: string;
  image?: string;
  network?: "none" | "bridge";
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

function normalizeEnv(env?: Record<string, string>): Array<[string, string]> {
  if (!env) {
    return [];
  }

  return Object.entries(env).filter((entry): entry is [string, string] => {
    const [key, value] = entry;
    return key.length > 0 && typeof value === "string";
  });
}

async function runProcess(
  command: string,
  args: string[],
  options: {
    env?: NodeJS.ProcessEnv;
    input?: string;
    timeoutMs?: number;
  } = {},
): Promise<DockerCommandResult> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: options.env,
      stdio: "pipe",
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;

    child.stdout.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    child.on("error", (error: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timeout) {
        clearTimeout(timeout);
      }
      reject(error);
    });

    child.on("close", (code: number | null) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timeout) {
        clearTimeout(timeout);
      }
      resolve({
        exitCode: code ?? 1,
        stdout,
        stderr,
      });
    });

    if (options.input) {
      child.stdin.write(options.input);
    }
    child.stdin.end();

    if (options.timeoutMs && options.timeoutMs > 0) {
      timeout = setTimeout(() => {
        if (settled) {
          return;
        }
        settled = true;
        child.kill("SIGKILL");
        reject(new Error(`Docker command timed out after ${options.timeoutMs}ms`));
      }, options.timeoutMs);
    }
  });
}

export class DockerSandboxBackend implements SandboxBackend {
  public readonly kind = "docker" as const;
  private readonly dockerBin: string;
  private readonly image: string;
  private readonly network: "none" | "bridge";

  public constructor(private readonly options: DockerSandboxBackendOptions = {}) {
    this.dockerBin = options.dockerBin ?? "docker";
    this.image = options.image ?? "alpine:3.20";
    this.network = options.network ?? "none";
  }

  public capabilities(): SandboxBackendCapabilities {
    return {
      kind: this.kind,
      supportsPersistence: true,
      supportsSnapshots: true,
      supportsBrowser: false,
      supportsNetwork: true,
      supportsPackageInstall: true,
      supportedCapabilities: [
        "command-exec",
        "filesystem",
        "network",
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

    try {
      const result = await runProcess(this.dockerBin, ["version", "--format", "{{.Server.Version}}"], {
        timeoutMs: 3_000,
      });
      return result.exitCode === 0;
    } catch {
      return false;
    }
  }

  public async createSession(metadata?: Record<string, string>): Promise<SandboxSession> {
    const containerName = `titanclaw-${randomUUID()}`;
    const args = [
      "run",
      "-d",
      "--rm",
      "--init",
      "--name",
      containerName,
      "--network",
      this.network,
      this.image,
      "sh",
      "-lc",
      "while true; do sleep 3600; done",
    ];
    const result = await runProcess(this.dockerBin, args, { timeoutMs: 10_000 });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr.trim() || "Failed to create Docker sandbox session");
    }

    return {
      id: containerName,
      backend: this.kind,
      metadata,
    };
  }

  public async destroySession(sessionId: string): Promise<void> {
    await runProcess(this.dockerBin, ["rm", "-f", sessionId], { timeoutMs: 10_000 });
  }

  public async writeFiles(
    files: SandboxFileEntry[],
    session?: SandboxSession,
  ): Promise<void> {
    if (this.options.fileWriter) {
      await this.options.fileWriter(files, session);
      return;
    }

    await this.withSession(session, async (activeSession) => {
      for (const file of files) {
        const args = this.buildExecArgs(
          activeSession.id,
          `mkdir -p ${quoteShell(dirname(file.path))} && cat > ${quoteShell(file.path)}`,
          [],
          undefined,
          true,
        );
        const result = await runProcess(this.dockerBin, args, {
          input: file.content,
          timeoutMs: 30_000,
        });
        if (result.exitCode !== 0) {
          throw new Error(result.stderr.trim() || `Failed to write Docker file: ${file.path}`);
        }
      }
    });
  }

  public async readFile(path: string, session?: SandboxSession): Promise<string> {
    if (this.options.fileReader) {
      return await this.options.fileReader(path, session);
    }

    return await this.withSession(session, async (activeSession) => {
      const args = this.buildExecArgs(
        activeSession.id,
        `cat ${quoteShell(path)}`,
        [],
      );
      const result = await runProcess(this.dockerBin, args, {
        timeoutMs: 30_000,
      });
      if (result.exitCode !== 0) {
        throw new Error(result.stderr.trim() || `Failed to read Docker file: ${path}`);
      }

      return result.stdout;
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
        : await this.executeWithDocker(request, session);

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

  private async executeWithDocker(
    request: SandboxExecutionRequest,
    session?: SandboxSession,
  ): Promise<DockerExecutorResult> {
    const shellCommand = buildShellCommand(request);
    const envEntries = normalizeEnv(request.env);
    const attachStdin = typeof request.input === "string";

    const args = session
      ? this.buildExecArgs(session.id, shellCommand, envEntries, request.cwd, attachStdin)
      : this.buildRunArgs(shellCommand, envEntries, request.cwd, attachStdin);

    const result = await runProcess(this.dockerBin, args, {
      input: request.input,
      timeoutMs: request.timeoutMs ?? 30_000,
    });

    return result;
  }

  private buildRunArgs(
    shellCommand: string,
    envEntries: Array<[string, string]>,
    cwd?: string,
    attachStdin = false,
  ): string[] {
    const args = ["run", "--rm", "--init", "--network", this.network];

    if (attachStdin) {
      args.push("-i");
    }

    if (cwd) {
      args.push("-w", cwd);
    }

    for (const [key, value] of envEntries) {
      args.push("-e", `${key}=${value}`);
    }

    args.push(this.image, "sh", "-lc", shellCommand);
    return args;
  }

  private buildExecArgs(
    sessionId: string,
    shellCommand: string,
    envEntries: Array<[string, string]>,
    cwd?: string,
    attachStdin = false,
  ): string[] {
    const args = ["exec"];

    if (attachStdin) {
      args.push("-i");
    }

    if (cwd) {
      args.push("-w", cwd);
    }

    for (const [key, value] of envEntries) {
      args.push("-e", `${key}=${value}`);
    }

    args.push(sessionId, "sh", "-lc", shellCommand);
    return args;
  }

  public async snapshot(session: SandboxSession): Promise<SandboxSnapshot> {
    if (this.options.snapshotCreator) {
      return await this.options.snapshotCreator(session);
    }

    const imageTag = `titanclaw-snapshot-${randomUUID()}`;
    const result = await runProcess(this.dockerBin, ["commit", session.id, imageTag], {
      timeoutMs: 30_000,
    });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr.trim() || `Failed to create Docker snapshot for session: ${session.id}`);
    }

    return {
      id: imageTag,
      createdAt: new Date().toISOString(),
      backend: this.kind,
    };
  }

  public async resume(snapshotId: string): Promise<SandboxSession> {
    if (this.options.snapshotResumer) {
      return await this.options.snapshotResumer(snapshotId);
    }

    const containerName = `titanclaw-${randomUUID()}`;
    const args = [
      "run", "-d", "--rm", "--init",
      "--name", containerName,
      "--network", this.network,
      snapshotId,
      "sh", "-lc", "while true; do sleep 3600; done",
    ];
    const result = await runProcess(this.dockerBin, args, { timeoutMs: 10_000 });
    if (result.exitCode !== 0) {
      throw new Error(result.stderr.trim() || `Failed to resume Docker snapshot: ${snapshotId}`);
    }

    return {
      id: containerName,
      backend: this.kind,
      metadata: { sourceSnapshotId: snapshotId },
    };
  }

  private async withSession<T>(
    session: SandboxSession | undefined,
    action: (activeSession: SandboxSession) => Promise<T>,
  ): Promise<T> {
    if (session) {
      return await action(session);
    }

    const ephemeralSession = await this.createSession();
    try {
      return await action(ephemeralSession);
    } finally {
      await this.destroySession(ephemeralSession.id).catch(() => undefined);
    }
  }
}
