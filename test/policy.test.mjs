import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PolicyStore } from "../dist/policy/policy-store.js";
import { AuditLog } from "../dist/policy/audit-log.js";
import { BreakGlassController } from "../dist/policy/break-glass.js";

const BASE = { allowedWritePaths: [], autoApproveTools: false, maxIterations: 10 };
const RELAXED = { allowedWritePaths: ["/tmp"], autoApproveTools: true, maxIterations: 50 };

// ─── PolicyStore (7 tests) ───────────────────────────────────────────────────

test("store: initial policy is accessible via getPolicy()", () => {
  const store = new PolicyStore(BASE);
  assert.deepEqual(store.getPolicy(), BASE);
});

test("store: set() updates current policy", async () => {
  const store = new PolicyStore(BASE);
  await store.set(RELAXED, "test");
  assert.deepEqual(store.getPolicy(), RELAXED);
});

test("store: set() saves snapshot of previous policy", async () => {
  const store = new PolicyStore(BASE);
  const snap = await store.set(RELAXED, "upgrade");
  assert.equal(snap.reason, "upgrade");
  assert.deepEqual(snap.policy, BASE);
});

test("store: rollback() restores policy from snapshot", async () => {
  const store = new PolicyStore(BASE);
  const snap = await store.set(RELAXED, "upgrade");
  await store.rollback(snap.id);
  assert.deepEqual(store.getPolicy(), BASE);
});

test("store: rollback() throws on unknown snapshot id", async () => {
  const store = new PolicyStore(BASE);
  await assert.rejects(() => store.rollback("nonexistent-id"), /Unknown policy snapshot/);
});

test("store: set() appends a policy_change audit entry", async () => {
  const log = new AuditLog();
  const store = new PolicyStore(BASE, log);
  await store.set(RELAXED, "reason");
  const entries = log.getEntries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].event, "policy_change");
  assert.deepEqual(entries[0].before, BASE);
  assert.deepEqual(entries[0].after, RELAXED);
});

test("store: rollback() appends a rollback audit entry", async () => {
  const log = new AuditLog();
  const store = new PolicyStore(BASE, log);
  const snap = await store.set(RELAXED, "up");
  await store.rollback(snap.id);
  const entries = log.getEntries();
  assert.equal(entries[1].event, "rollback");
  assert.equal(entries[1].snapshotId, snap.id);
});

// ─── AuditLog (2 tests) ──────────────────────────────────────────────────────

test("audit: entries accessible in-memory immediately after append", async () => {
  const log = new AuditLog();
  const entry = { timestamp: new Date().toISOString(), event: "policy_change", actor: "host", before: BASE, after: RELAXED, reason: "test" };
  await log.append(entry);
  assert.equal(log.getEntries().length, 1);
  assert.equal(log.getEntries()[0].reason, "test");
});

test("audit: persists entries as JSONL when logPath is given", async () => {
  const dir = await mkdtemp(join(tmpdir(), "titanclaw-audit-"));
  const logPath = join(dir, "sub", "audit.jsonl");
  const log = new AuditLog(logPath);
  const entry = { timestamp: new Date().toISOString(), event: "policy_change", actor: "host", before: BASE, after: RELAXED, reason: "persist-test" };
  await log.append(entry);
  const contents = await readFile(logPath, "utf8");
  const parsed = JSON.parse(contents.trim());
  assert.equal(parsed.reason, "persist-test");
});

// ─── BreakGlassController (7 tests) ──────────────────────────────────────────

test("break-glass: initial state is inactive", () => {
  const store = new PolicyStore(BASE);
  const bg = new BreakGlassController(store);
  assert.equal(bg.isActive(), false);
  assert.equal(bg.getSession(), null);
});

test("break-glass: activate() relaxes policy in store", async () => {
  const store = new PolicyStore(BASE);
  const bg = new BreakGlassController(store);
  await bg.activate("incident", 60_000, RELAXED);
  assert.deepEqual(store.getPolicy(), RELAXED);
  bg.dispose();
});

test("break-glass: activate() sets isActive() and session timestamps", async () => {
  const store = new PolicyStore(BASE);
  const bg = new BreakGlassController(store);
  const before = Date.now();
  await bg.activate("incident", 30_000, RELAXED);
  const session = bg.getSession();
  assert.ok(session);
  assert.ok(new Date(session.activatedAt).getTime() >= before);
  assert.ok(new Date(session.expiresAt).getTime() > new Date(session.activatedAt).getTime());
  assert.equal(bg.isActive(), true);
  bg.dispose();
});

test("break-glass: activate() rejects double activation", async () => {
  const store = new PolicyStore(BASE);
  const bg = new BreakGlassController(store);
  await bg.activate("first", 60_000, RELAXED);
  await assert.rejects(() => bg.activate("second", 60_000, RELAXED), /already active/);
  bg.dispose();
});

test("break-glass: TTL expiry restores original policy", async () => {
  const store = new PolicyStore(BASE);
  const bg = new BreakGlassController(store);
  await bg.activate("incident", 20, RELAXED);
  assert.deepEqual(store.getPolicy(), RELAXED);
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(store.getPolicy(), BASE);
});

test("break-glass: TTL expiry clears active session", async () => {
  const store = new PolicyStore(BASE);
  const bg = new BreakGlassController(store);
  await bg.activate("incident", 20, RELAXED);
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(bg.isActive(), false);
});

test("break-glass: audit log contains activated and expired events", async () => {
  const log = new AuditLog();
  const store = new PolicyStore(BASE, log);
  const bg = new BreakGlassController(store);
  await bg.activate("incident", 20, RELAXED);
  await new Promise((r) => setTimeout(r, 50));
  const events = log.getEntries().map((e) => e.event);
  assert.ok(events.includes("break_glass_activated"));
  assert.ok(events.includes("break_glass_expired"));
});
