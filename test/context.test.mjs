import test from "node:test";
import assert from "node:assert/strict";

import { autoCompactIfNeeded } from "../dist/context/compactor.js";

function makeState({ totalInputTokens = 0, needsCompaction = false, messages = [] } = {}) {
  return {
    signal: "continue",
    iteration: 0,
    consecutiveToolIntentNudges: 0,
    forceText: false,
    messages,
    pendingApproval: null,
    lastResponseType: "none",
    lastTextResponse: "",
    needsCompaction,
    totalInputTokens,
    totalOutputTokens: 0,
  };
}

function makeStrategy(fn) {
  return { summarize: fn };
}

const OPTS = { tokenBudget: 5000 };

// ─── autoCompactIfNeeded (11 tests) ──────────────────────────────────────────

test("compact: no-op when under token budget", async () => {
  const state = makeState({ totalInputTokens: 1000 });
  const result = await autoCompactIfNeeded(state, makeStrategy(async () => "s"), OPTS, { consecutiveFailures: 0 });
  assert.equal(result.wasCompacted, false);
  assert.equal(state.totalInputTokens, 1000);
});

test("compact: triggers when over token budget", async () => {
  const state = makeState({
    totalInputTokens: 6000,
    messages: [{ id: "1", role: "user", content: "hello" }],
  });
  const result = await autoCompactIfNeeded(state, makeStrategy(async () => "summary"), OPTS, { consecutiveFailures: 0 });
  assert.equal(result.wasCompacted, true);
});

test("compact: triggers on needsCompaction flag regardless of token count", async () => {
  const state = makeState({
    totalInputTokens: 100,
    needsCompaction: true,
    messages: [{ id: "1", role: "user", content: "hello" }],
  });
  const result = await autoCompactIfNeeded(
    state,
    makeStrategy(async () => "summary"),
    { tokenBudget: 99999 },
    { consecutiveFailures: 0 },
  );
  assert.equal(result.wasCompacted, true);
});

test("compact: preserves system messages after compaction", async () => {
  const state = makeState({
    totalInputTokens: 6000,
    messages: [
      { id: "s1", role: "system", content: "You are an assistant." },
      { id: "u1", role: "user", content: "hello" },
      { id: "a1", role: "assistant", content: "hi" },
    ],
  });
  await autoCompactIfNeeded(state, makeStrategy(async () => "summary"), OPTS, { consecutiveFailures: 0 });
  assert.equal(state.messages[0].role, "system");
  assert.equal(state.messages[0].content, "You are an assistant.");
});

test("compact: summary message contains [Conversation summary] and strategy output", async () => {
  const state = makeState({
    totalInputTokens: 6000,
    messages: [{ id: "u1", role: "user", content: "hello" }],
  });
  await autoCompactIfNeeded(state, makeStrategy(async () => "the user said hello"), OPTS, { consecutiveFailures: 0 });
  const summaryMsg = state.messages.find((m) => m.content.includes("[Conversation summary]"));
  assert.ok(summaryMsg, "summary message not found");
  assert.ok(summaryMsg.content.includes("the user said hello"));
});

test("compact: resets totalInputTokens to 0 after compaction", async () => {
  const state = makeState({
    totalInputTokens: 8000,
    messages: [{ id: "u1", role: "user", content: "hello" }],
  });
  await autoCompactIfNeeded(state, makeStrategy(async () => "summary"), OPTS, { consecutiveFailures: 0 });
  assert.equal(state.totalInputTokens, 0);
});

test("compact: clears needsCompaction flag after compaction", async () => {
  const state = makeState({
    totalInputTokens: 100,
    needsCompaction: true,
    messages: [{ id: "u1", role: "user", content: "hello" }],
  });
  await autoCompactIfNeeded(state, makeStrategy(async () => "summary"), { tokenBudget: 99999 }, { consecutiveFailures: 0 });
  assert.equal(state.needsCompaction, false);
});

test("compact: PTL retries on summarize failure then succeeds", async () => {
  let calls = 0;
  const state = makeState({
    totalInputTokens: 6000,
    messages: Array.from({ length: 10 }, (_, i) => ({ id: `m${i}`, role: "user", content: `msg ${i}` })),
  });
  const strategy = makeStrategy(async (messages) => {
    calls++;
    if (calls === 1) throw new Error("Prompt Too Long");
    return `summary of ${messages.length} messages`;
  });
  const result = await autoCompactIfNeeded(state, strategy, { ...OPTS, maxPtlRetries: 3 }, { consecutiveFailures: 0 });
  assert.equal(result.wasCompacted, true);
  assert.equal(result.result?.ptlAttempts, 1);
  assert.equal(calls, 2);
});

test("compact: fails and increments consecutiveFailures after exhausting PTL retries", async () => {
  const state = makeState({
    totalInputTokens: 6000,
    messages: Array.from({ length: 10 }, (_, i) => ({ id: `m${i}`, role: "user", content: `msg ${i}` })),
  });
  const strategy = makeStrategy(async () => { throw new Error("always fails"); });
  const result = await autoCompactIfNeeded(state, strategy, { ...OPTS, maxPtlRetries: 2 }, { consecutiveFailures: 0 });
  assert.equal(result.wasCompacted, false);
  assert.equal(result.tracking.consecutiveFailures, 1);
});

test("compact: circuit breaker skips summarize after maxConsecutiveFailures", async () => {
  let calls = 0;
  const strategy = makeStrategy(async () => { calls++; throw new Error("fail"); });
  const opts = { tokenBudget: 5000, maxPtlRetries: 0, maxConsecutiveFailures: 3 };
  let tracking = { consecutiveFailures: 0 };
  for (let i = 0; i < 4; i++) {
    const state = makeState({
      totalInputTokens: 6000,
      messages: [{ id: "u1", role: "user", content: "x" }],
    });
    const r = await autoCompactIfNeeded(state, strategy, opts, tracking);
    tracking = r.tracking;
  }
  assert.equal(calls, 3);  // 4th call blocked by circuit breaker
});

test("compact: resets consecutiveFailures to 0 on success", async () => {
  const state = makeState({
    totalInputTokens: 6000,
    messages: [{ id: "u1", role: "user", content: "hello" }],
  });
  const result = await autoCompactIfNeeded(
    state,
    makeStrategy(async () => "summary"),
    OPTS,
    { consecutiveFailures: 2 },
  );
  assert.equal(result.wasCompacted, true);
  assert.equal(result.tracking.consecutiveFailures, 0);
});
