export interface RetryOptions {
  maxAttempts: number;   // default 3
  baseDelayMs: number;   // default 100
  maxDelayMs: number;    // default 10_000
  jitter: boolean;       // add randomness to prevent thundering herd (default true)
  retryIf?: (error: unknown) => boolean;
}

export const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxAttempts: 3,
  baseDelayMs: 100,
  maxDelayMs: 10_000,
  jitter: true,
};

function computeDelay(attempt: number, options: RetryOptions): number {
  const exponential = options.baseDelayMs * Math.pow(2, attempt);
  const capped = Math.min(exponential, options.maxDelayMs);
  return options.jitter ? Math.random() * capped : capped;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = DEFAULT_RETRY_OPTIONS,
): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt < options.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      if (options.retryIf && !options.retryIf(error)) {
        throw error;
      }

      if (attempt < options.maxAttempts - 1) {
        await sleep(computeDelay(attempt, options));
      }
    }
  }

  throw lastError;
}
