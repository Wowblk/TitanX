import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { closeSync, openSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { deserialize, serialize } from "node:v8";
import { WASI } from "node:wasi";

import type {
  SandboxBackend,
  SandboxBackendCapabilities,
  SandboxExecutionRequest,
  SandboxExecutionResult,
} from "../types.js";

type WasmExecutorResult = {
  exitCode?: number;
  stdout?: string;
  stderr?: string;
};

export interface WasmCommandRegistration {
  modulePath: string;
  args?: string[];
  env?: Record<string, string>;
  preopens?: Record<string, string>;
}

export interface WasmSandboxBackendOptions {
  available?: boolean;
  executor?: (request: SandboxExecutionRequest) => Promise<WasmExecutorResult>;
  commands?: Record<string, WasmCommandRegistration>;
  logDir?: string;
  cacheDir?: string;
}

function normalizeArgs(args?: string[]): string[] {
  return Array.isArray(args) ? args.filter((value) => value.length > 0) : [];
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

export class WasmSandboxBackend implements SandboxBackend {
  public readonly kind = "wasm" as const;
  private readonly commands: Map<string, WasmCommandRegistration>;
  private readonly moduleCache = new Map<string, WebAssembly.Module>();

  public constructor(private readonly options: WasmSandboxBackendOptions = {}) {
    this.commands = new Map(Object.entries(options.commands ?? {}));
  }

  public capabilities(): SandboxBackendCapabilities {
    return {
      kind: this.kind,
      supportsPersistence: false,
      supportsSnapshots: false,
      supportsBrowser: false,
      supportsNetwork: false,
      supportsPackageInstall: false,
      supportedCapabilities: ["command-exec"],
    };
  }

  public async isAvailable(): Promise<boolean> {
    return this.options.available ?? true;
  }

  public registerCommand(name: string, registration: WasmCommandRegistration): void {
    this.commands.set(name, registration);
  }

  public async execute(request: SandboxExecutionRequest): Promise<SandboxExecutionResult> {
    const startedAt = performance.now();

    try {
      const result = this.options.executor
        ? await this.options.executor(request)
        : await this.executeRegisteredModule(request);

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

  private async loadModule(registration: WasmCommandRegistration): Promise<WebAssembly.Module> {
    const cached = this.moduleCache.get(registration.modulePath);
    if (cached) return cached;

    const moduleBytes = await readFile(resolve(registration.modulePath));

    if (this.options.cacheDir) {
      const hash = createHash("sha256").update(moduleBytes).digest("hex");
      const cachePath = join(this.options.cacheDir, `${hash}.v8cache`);
      try {
        const cacheData = await readFile(cachePath);
        const module = deserialize(cacheData) as WebAssembly.Module;
        this.moduleCache.set(registration.modulePath, module);
        return module;
      } catch {
        // cache miss — compile fresh
      }
      const module = await WebAssembly.compile(moduleBytes);
      await mkdir(this.options.cacheDir, { recursive: true });
      await writeFile(cachePath, serialize(module));
      this.moduleCache.set(registration.modulePath, module);
      return module;
    }

    const module = await WebAssembly.compile(moduleBytes);
    this.moduleCache.set(registration.modulePath, module);
    return module;
  }

  private async executeRegisteredModule(
    request: SandboxExecutionRequest,
  ): Promise<WasmExecutorResult> {
    const registration = this.commands.get(request.command);
    if (!registration) {
      throw new Error(`Unregistered WASI command: ${request.command}`);
    }

    const module = await this.loadModule(registration);

    let logDir: string;
    let persistent: boolean;

    if (this.options.logDir) {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const runId = randomUUID().slice(0, 8);
      logDir = join(this.options.logDir, `${ts}-${request.command}-${runId}`);
      await mkdir(logDir, { recursive: true });
      persistent = true;
    } else {
      logDir = await mkdtemp(join(tmpdir(), "titanclaw-wasi-"));
      persistent = false;
    }

    const stdoutPath = join(logDir, "stdout.log");
    const stderrPath = join(logDir, "stderr.log");
    const stdoutFd = openSync(stdoutPath, "w+");
    const stderrFd = openSync(stderrPath, "w+");

    try {
      const wasi = new WASI({
        version: "preview1",
        args: [
          request.command,
          ...normalizeArgs(registration.args),
          ...normalizeArgs(request.args),
        ],
        env: {
          ...normalizeEnv(registration.env),
          ...normalizeEnv(request.env),
        },
        preopens: registration.preopens ?? {},
        stdin: undefined,
        stdout: stdoutFd,
        stderr: stderrFd,
      });

      const imports = wasi.getImportObject() as WebAssembly.Imports;
      const instance = await WebAssembly.instantiate(module, imports);
      const start = (instance.exports as Record<string, unknown>)["_start"];
      if (typeof start !== "function") {
        throw new Error(`WASI module '${request.command}' does not export '_start'`);
      }

      let exitCode = 0;
      try {
        wasi.start(instance as WebAssembly.Instance);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const match = /exit code[: ]+(\d+)/i.exec(message);
        if (match) {
          exitCode = Number(match[1]);
        } else {
          throw error;
        }
      }

      closeSync(stdoutFd);
      closeSync(stderrFd);

      const stdout = await readFile(stdoutPath, "utf8");
      const stderr = await readFile(stderrPath, "utf8");
      return { exitCode, stdout, stderr };
    } finally {
      try {
        closeSync(stdoutFd);
      } catch {
        // ignore double-close
      }
      try {
        closeSync(stderrFd);
      } catch {
        // ignore double-close
      }
      if (!persistent) {
        await rm(logDir, { recursive: true, force: true });
      }
    }
  }
}
