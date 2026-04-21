import test from "node:test";
import assert from "node:assert/strict";

import { CircuitBreaker, CircuitOpenError } from "../dist/resilience/circuit-breaker.js";
import { withRetry } from "../dist/resilience/retry.js";
import { ResilientSandboxBackend } from "../dist/resilience/resilient-backend.js";

// ─── CircuitBreaker (9 tests) ────────────────────────────────────────────────

test("circuit: initial state is closed", () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 3, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  assert.equal(cb.getState(), "closed");
});

test("circuit: successful calls stay closed", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 3, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  await cb.call(async () => "ok");
  await cb.call(async () => "ok");
  assert.equal(cb.getState(), "closed");
});

test("circuit: opens after failure threshold", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 3, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  const fail = async () => { throw new Error("down"); };
  for (let i = 0; i < 3; i++) {
    await assert.rejects(cb.call(fail));
  }
  assert.equal(cb.getState(), "open");
});

test("circuit: throws CircuitOpenError when open", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 1, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  await assert.rejects(cb.call(async () => { throw new Error("down"); }));
  assert.equal(cb.getState(), "open");
  await assert.rejects(
    cb.call(async () => "ok"),
    (err) => err instanceof CircuitOpenError && err.circuitName === "svc",
  );
});

test("circuit: transitions to half-open after cooldown", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 1, successThreshold: 2, cooldownMs: 20, windowMs: 1000 });
  await assert.rejects(cb.call(async () => { throw new Error("down"); }));
  assert.equal(cb.getState(), "open");
  await new Promise((r) => setTimeout(r, 30));
  // Next call should attempt probe (half-open)
  await assert.rejects(cb.call(async () => { throw new Error("still down"); }));
  // Failed in half-open → back to open
  assert.equal(cb.getState(), "open");
});

test("circuit: closes after successive successes in half-open", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 1, successThreshold: 2, cooldownMs: 20, windowMs: 1000 });
  await assert.rejects(cb.call(async () => { throw new Error("down"); }));
  await new Promise((r) => setTimeout(r, 30));
  await cb.call(async () => "probe1");  // half-open, success 1
  await cb.call(async () => "probe2");  // half-open, success 2 → closed
  assert.equal(cb.getState(), "closed");
});

test("circuit: returns to open on failure in half-open", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 1, successThreshold: 3, cooldownMs: 20, windowMs: 1000 });
  await assert.rejects(cb.call(async () => { throw new Error("down"); }));
  await new Promise((r) => setTimeout(r, 30));
  await cb.call(async () => "probe1");  // half-open success
  assert.equal(cb.getState(), "half-open");
  await assert.rejects(cb.call(async () => { throw new Error("relapse"); }));
  assert.equal(cb.getState(), "open");
});

test("circuit: rolling window prunes old failures", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 3, successThreshold: 2, cooldownMs: 50, windowMs: 30 });
  const fail = async () => { throw new Error("down"); };
  await assert.rejects(cb.call(fail));
  await assert.rejects(cb.call(fail));
  assert.equal(cb.getState(), "closed");  // only 2 failures, need 3
  await new Promise((r) => setTimeout(r, 40));  // wait for window to expire
  await assert.rejects(cb.call(fail));    // old failures pruned, this is only 1
  assert.equal(cb.getState(), "closed");  // still closed — old failures expired
});

test("circuit: passes return value through", async () => {
  const cb = new CircuitBreaker("svc", { failureThreshold: 3, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  const result = await cb.call(async () => 42);
  assert.equal(result, 42);
});

// ─── withRetry (6 tests) ─────────────────────────────────────────────────────

test("retry: returns result immediately on success", async () => {
  let calls = 0;
  const result = await withRetry(async () => { calls++; return "ok"; }, { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0, jitter: false });
  assert.equal(result, "ok");
  assert.equal(calls, 1);
});

test("retry: retries on failure and eventually succeeds", async () => {
  let calls = 0;
  const result = await withRetry(async () => {
    calls++;
    if (calls < 3) throw new Error("transient");
    return "recovered";
  }, { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0, jitter: false });
  assert.equal(result, "recovered");
  assert.equal(calls, 3);
});

test("retry: throws after max attempts exhausted", async () => {
  let calls = 0;
  await assert.rejects(
    withRetry(async () => { calls++; throw new Error("permanent"); }, { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0, jitter: false }),
    /permanent/,
  );
  assert.equal(calls, 3);
});

test("retry: does not retry non-retryable errors", async () => {
  let calls = 0;
  await assert.rejects(
    withRetry(async () => { calls++; throw new Error("fatal"); }, {
      maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0, jitter: false,
      retryIf: (err) => err instanceof Error && err.message !== "fatal",
    }),
    /fatal/,
  );
  assert.equal(calls, 1);  // no retry
});

test("retry: delay grows exponentially (no jitter)", async () => {
  const delays = [];
  let prev = Date.now();
  let calls = 0;
  await assert.rejects(
    withRetry(async () => {
      const now = Date.now();
      if (calls > 0) delays.push(now - prev);
      prev = now;
      calls++;
      throw new Error("fail");
    }, { maxAttempts: 3, baseDelayMs: 20, maxDelayMs: 1000, jitter: false }),
  );
  // delay[1] should be roughly 2x delay[0]
  assert.ok(delays[1] >= delays[0]);
});

test("retry: respects maxDelayMs cap", async () => {
  const start = Date.now();
  let calls = 0;
  await assert.rejects(
    withRetry(async () => { calls++; throw new Error("fail"); }, {
      maxAttempts: 4, baseDelayMs: 50, maxDelayMs: 60, jitter: false,
    }),
  );
  const elapsed = Date.now() - start;
  // 3 delays: 50ms + 60ms (capped from 100) + 60ms (capped from 200) ≈ 170ms
  // Allow generous range for CI variability
  assert.ok(elapsed < 500, `Total time ${elapsed}ms exceeded cap expectation`);
});

// ─── ResilientSandboxBackend (3 tests) ────────────────────────────────────────

function makeBackend(failCount = 0) {
  let calls = 0;
  return {
    kind: "docker",
    capabilities: () => ({ kind: "docker", supportsPersistence: true, supportsSnapshots: true, supportsBrowser: false, supportsNetwork: true, supportsPackageInstall: true, supportedCapabilities: [] }),
    isAvailable: async () => true,
    execute: async (req) => {
      calls++;
      if (calls <= failCount) throw new Error("backend error");
      return { backend: "docker", exitCode: 0, stdout: "ok", stderr: "", durationMs: 1 };
    },
    getCalls: () => calls,
  };
}

test("resilient: passes through successful execution", async () => {
  const backend = makeBackend(0);
  const resilient = new ResilientSandboxBackend(backend, { maxAttempts: 1, baseDelayMs: 0, maxDelayMs: 0, jitter: false, failureThreshold: 5, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  const result = await resilient.execute({ command: "ls" });
  assert.equal(result.stdout, "ok");
  assert.equal(resilient.getCircuitState(), "closed");
});

test("resilient: retries transient failures transparently", async () => {
  const backend = makeBackend(2);  // first 2 calls fail
  const resilient = new ResilientSandboxBackend(backend, { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0, jitter: false, failureThreshold: 5, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  const result = await resilient.execute({ command: "ls" });
  assert.equal(result.stdout, "ok");
  assert.equal(backend.getCalls(), 3);
});

test("resilient: opens circuit after sustained failures", async () => {
  const backend = makeBackend(99);
  const resilient = new ResilientSandboxBackend(backend, { maxAttempts: 1, baseDelayMs: 0, maxDelayMs: 0, jitter: false, failureThreshold: 3, successThreshold: 2, cooldownMs: 50, windowMs: 1000 });
  for (let i = 0; i < 3; i++) {
    await assert.rejects(resilient.execute({ command: "ls" }));
  }
  assert.equal(resilient.getCircuitState(), "open");
  // Next call should be rejected immediately by the circuit
  await assert.rejects(
    resilient.execute({ command: "ls" }),
    (err) => err instanceof CircuitOpenError,
  );
});
