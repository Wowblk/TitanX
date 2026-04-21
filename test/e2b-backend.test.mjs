import test from "node:test";
import assert from "node:assert/strict";

import { E2BSandboxBackend } from "../dist/sandbox/backends/e2b.js";

test("E2BSandboxBackend respects explicit availability override", async () => {
  const availableBackend = new E2BSandboxBackend({ available: true });
  const unavailableBackend = new E2BSandboxBackend({ available: false });

  assert.equal(await availableBackend.isAvailable(), true);
  assert.equal(await unavailableBackend.isAvailable(), false);
});

test("E2BSandboxBackend wraps executor output", async () => {
  const backend = new E2BSandboxBackend({
    executor: async (request) => ({
      exitCode: 0,
      stdout: `${request.command} completed remotely`,
      stderr: "",
    }),
  });

  const result = await backend.execute({ command: "browser-task" });

  assert.equal(result.backend, "e2b");
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "browser-task completed remotely");
});

test("E2BSandboxBackend converts executor failures into sandbox errors", async () => {
  const backend = new E2BSandboxBackend({
    executor: async () => {
      throw new Error("e2b unavailable");
    },
  });

  const result = await backend.execute({ command: "browser-task" });

  assert.equal(result.backend, "e2b");
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr, /e2b unavailable/);
});

test("E2BSandboxBackend delegates file upload and download helpers", async () => {
  const writes = [];
  const backend = new E2BSandboxBackend({
    fileWriter: async (files, session) => {
      writes.push({ files, session });
    },
    fileReader: async (path, session) => `${session?.id ?? "no-session"}:${path}`,
  });
  const session = {
    id: "e2b-session-1",
    backend: "e2b",
  };

  await backend.writeFiles(
    [{ path: "/workspace/hello.txt", content: "hello e2b" }],
    session,
  );
  const content = await backend.readFile("/workspace/hello.txt", session);

  assert.deepEqual(writes, [
    {
      files: [{ path: "/workspace/hello.txt", content: "hello e2b" }],
      session,
    },
  ]);
  assert.equal(content, "e2b-session-1:/workspace/hello.txt");
});
