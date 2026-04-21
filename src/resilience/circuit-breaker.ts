export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitBreakerOptions {
  failureThreshold: number;  // failures in window to open (default 5)
  successThreshold: number;  // consecutive successes in half-open to close (default 2)
  cooldownMs: number;        // ms in open before attempting half-open (default 60_000)
  windowMs: number;          // rolling window for failure counting (default 60_000)
}

export const DEFAULT_CIRCUIT_BREAKER_OPTIONS: CircuitBreakerOptions = {
  failureThreshold: 5,
  successThreshold: 2,
  cooldownMs: 60_000,
  windowMs: 60_000,
};

export class CircuitOpenError extends Error {
  public constructor(public readonly circuitName: string) {
    super(`Circuit breaker '${circuitName}' is open — service unavailable`);
    this.name = "CircuitOpenError";
  }
}

export class CircuitBreaker {
  private state: CircuitState = "closed";
  private failureTimestamps: number[] = [];
  private halfOpenSuccesses = 0;
  private openedAt: number | null = null;

  public constructor(
    public readonly name: string,
    private readonly options: CircuitBreakerOptions = DEFAULT_CIRCUIT_BREAKER_OPTIONS,
  ) {}

  public getState(): CircuitState {
    return this.state;
  }

  public async call<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === "open") {
      if (!this.shouldAttemptReset()) {
        throw new CircuitOpenError(this.name);
      }
      this.transitionTo("half-open");
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    if (this.state === "half-open") {
      this.halfOpenSuccesses += 1;
      if (this.halfOpenSuccesses >= this.options.successThreshold) {
        this.transitionTo("closed");
      }
    }
  }

  private onFailure(): void {
    const now = Date.now();
    this.failureTimestamps.push(now);
    this.failureTimestamps = this.failureTimestamps.filter(
      (t) => now - t < this.options.windowMs,
    );

    if (this.state === "half-open") {
      this.transitionTo("open");
    } else if (
      this.state === "closed" &&
      this.failureTimestamps.length >= this.options.failureThreshold
    ) {
      this.transitionTo("open");
    }
  }

  private shouldAttemptReset(): boolean {
    return this.openedAt !== null && Date.now() - this.openedAt >= this.options.cooldownMs;
  }

  private transitionTo(next: CircuitState): void {
    this.state = next;
    if (next === "open") {
      this.openedAt = Date.now();
      this.halfOpenSuccesses = 0;
    } else if (next === "closed") {
      this.failureTimestamps = [];
      this.halfOpenSuccesses = 0;
      this.openedAt = null;
    } else if (next === "half-open") {
      this.halfOpenSuccesses = 0;
    }
  }
}
