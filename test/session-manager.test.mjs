import test from "node:test";
import assert from "node:assert/strict";

import { SandboxRouter } from "../dist/sandbox/router.js";
import { SandboxSessionManager } from "../dist/sandbox/session-manager.js";

function backend(kind, options = {}) {
  const state = {
    destroyed: [],
    writes: [],
    reads: [],
    executed: [],
    snapshotCalls: [],
    resumeCalls: [],
    ...options.state,
  };

  return {
    kind,
    state,
    capabilities() {
      return {
        kind,
        supportsPersistence: kind !== "wasm",
        supportsSnapshots: kind !== "wasm",
        supportsBrowser: kind === "e2b",
        supportsNetwork: kind !== "wasm",
        supportsPackageInstall: kind !== "wasm",
        supportedCapabilities: ["command-exec", "filesystem", "snapshot", "resume"],
      };
    },
    async isAvailable() {
      return options.available ?? true;
    },
    async createSession(metadata) {
      if (options.syntheticOnly) {
        throw new Error("should not create a persistent session");
      }
      return {
        id: `${kind}-session-1`,
        backend: kind,
        metadata,
      };
    },
    async destroySession(sessionId) {
      state.destroyed.push(sessionId);
    },
    async execute(request, session) {
      state.executed.push({ request, session });
      return {
        backend: kind,
        exitCode: 0,
        stdout: `${kind}:${request.command}`,
        stderr: "",
        durationMs: 1,
      };
    },
    async writeFiles(files, session) {
      state.writes.push({ files, session });
    },
    async readFile(path, session) {
      state.reads.push({ path, session });
      return `${kind}:${path}`;
    },
    async snapshot(session) {
      state.snapshotCalls.push(session);
      return {
        id: `${kind}-snapshot-1`,
        createdAt: "2026-04-19T00:00:00.000Z",
        backend: kind,
      };
    },
    async resume(snapshotId) {
      state.resumeCalls.push(snapshotId);
      return {
        id: `${kind}-resumed-1`,
        backend: kind,
        metadata: { snapshotId },
      };
    },
  };
}

test("SandboxSessionManager creates a synthetic session for wasm backends", async () => {
  const wasmBackend = {
    ...backend("wasm"),
    createSession: undefined,
    destroySession: undefined,
    snapshot: undefined,
    resume: undefined,
    writeFiles: undefined,
    readFile: undefined,
  };
  const manager = new SandboxSessionManager(new SandboxRouter([wasmBackend]));

  const session = await manager.create({ riskLevel: "low" }, { scope: "demo" });

  assert.equal(session.backend, "wasm");
  assert.equal(session.persistent, false);
  assert.deepEqual(manager.getSession(session.id)?.metadata, { scope: "demo" });
});

test("SandboxSessionManager executes, uploads, downloads, snapshots, resumes, and destroys sessions", async () => {
  const dockerBackend = backend("docker");
  const e2bBackend = backend("e2b");
  const manager = new SandboxSessionManager(
    new SandboxRouter([backend("wasm"), dockerBackend, e2bBackend]),
  );

  const session = await manager.create(
    { riskLevel: "medium", needsFilesystem: true },
    { task: "build" },
  );
  const firstLastUsedAt = session.lastUsedAt;

  const execResult = await manager.execute(session.id, { command: "pwd" });
  await manager.writeFiles(session.id, [
    { path: "/workspace/input.txt", content: "hello" },
  ]);
  const fileContent = await manager.readFile(session.id, "/workspace/input.txt");
  const snapshot = await manager.snapshot(session.id);
  const resumed = await manager.resume(snapshot);
  await manager.destroy(session.id);

  assert.equal(execResult.stdout, "docker:pwd");
  assert.equal(fileContent, "docker:/workspace/input.txt");
  assert.equal(snapshot.backend, "docker");
  assert.equal(resumed.backend, "docker");
  assert.equal(resumed.persistent, true);
  assert.notEqual(manager.getSession(resumed.id), undefined);
  assert.equal(manager.getSession(session.id), undefined);
  assert.equal(dockerBackend.state.executed.length, 1);
  assert.equal(dockerBackend.state.writes.length, 1);
  assert.equal(dockerBackend.state.reads.length, 1);
  assert.equal(dockerBackend.state.snapshotCalls.length, 1);
  assert.deepEqual(dockerBackend.state.resumeCalls, ["docker-snapshot-1"]);
  assert.deepEqual(dockerBackend.state.destroyed, ["docker-session-1"]);
  assert.notEqual(
    manager.getSession(resumed.id)?.createdAt,
    undefined,
  );
  assert.ok(manager.getSession(resumed.id)?.lastUsedAt);
  assert.ok(firstLastUsedAt);
});
