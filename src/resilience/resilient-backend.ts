import type {
  SandboxBackend,
  SandboxBackendCapabilities,
  SandboxExecutionRequest,
  SandboxExecutionResult,
  SandboxFileEntry,
  SandboxSession,
  SandboxSnapshot,
} from "../sandbox/types.js";
import { CircuitBreaker, CircuitOpenError, type CircuitBreakerOptions } from "./circuit-breaker.js";
import { withRetry, type RetryOptions } from "./retry.js";

export interface ResilientOptions {
  failureThreshold?: number;
  successThreshold?: number;
  cooldownMs?: number;
  windowMs?: number;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean;
}

function isRetryable(error: unknown): boolean {
  // Never retry if the circuit is already open
  return !(error instanceof CircuitOpenError);
}

export class ResilientSandboxBackend implements SandboxBackend {
  public readonly kind: SandboxBackend["kind"];
  private readonly breaker: CircuitBreaker;
  private readonly retryOptions: RetryOptions;

  public constructor(
    private readonly backend: SandboxBackend,
    options: ResilientOptions = {},
  ) {
    this.kind = backend.kind;

    const breakerOptions: CircuitBreakerOptions = {
      failureThreshold: options.failureThreshold ?? 5,
      successThreshold: options.successThreshold ?? 2,
      cooldownMs: options.cooldownMs ?? 60_000,
      windowMs: options.windowMs ?? 60_000,
    };
    this.breaker = new CircuitBreaker(backend.kind, breakerOptions);

    this.retryOptions = {
      maxAttempts: options.maxAttempts ?? 3,
      baseDelayMs: options.baseDelayMs ?? 100,
      maxDelayMs: options.maxDelayMs ?? 10_000,
      jitter: options.jitter ?? true,
      retryIf: isRetryable,
    };
  }

  public getCircuitState() {
    return this.breaker.getState();
  }

  public capabilities(): SandboxBackendCapabilities {
    return this.backend.capabilities();
  }

  public async isAvailable(): Promise<boolean> {
    if (this.breaker.getState() === "open") return false;
    return this.backend.isAvailable();
  }

  public async execute(
    request: SandboxExecutionRequest,
    session?: SandboxSession,
  ): Promise<SandboxExecutionResult> {
    return this.breaker.call(() =>
      withRetry(() => this.backend.execute(request, session), this.retryOptions),
    );
  }

  public async createSession(metadata?: Record<string, string>): Promise<SandboxSession> {
    if (!this.backend.createSession) throw new Error(`${this.kind} does not support sessions`);
    return this.breaker.call(() =>
      withRetry(() => this.backend.createSession!(metadata), this.retryOptions),
    );
  }

  public async destroySession(sessionId: string): Promise<void> {
    if (!this.backend.destroySession) return;
    return this.backend.destroySession(sessionId);
  }

  public async writeFiles(files: SandboxFileEntry[], session?: SandboxSession): Promise<void> {
    if (!this.backend.writeFiles) throw new Error(`${this.kind} does not support writeFiles`);
    return this.breaker.call(() =>
      withRetry(() => this.backend.writeFiles!(files, session), this.retryOptions),
    );
  }

  public async readFile(path: string, session?: SandboxSession): Promise<string> {
    if (!this.backend.readFile) throw new Error(`${this.kind} does not support readFile`);
    return this.breaker.call(() =>
      withRetry(() => this.backend.readFile!(path, session), this.retryOptions),
    );
  }

  public async snapshot(session: SandboxSession): Promise<SandboxSnapshot> {
    if (!this.backend.snapshot) throw new Error(`${this.kind} does not support snapshot`);
    return this.breaker.call(() =>
      withRetry(() => this.backend.snapshot!(session), this.retryOptions),
    );
  }

  public async resume(snapshotId: string): Promise<SandboxSession> {
    if (!this.backend.resume) throw new Error(`${this.kind} does not support resume`);
    return this.breaker.call(() =>
      withRetry(() => this.backend.resume!(snapshotId), this.retryOptions),
    );
  }
}
