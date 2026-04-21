import test from "node:test";
import assert from "node:assert/strict";

import { DockerSandboxBackend } from "../dist/sandbox/backends/docker.js";

test("DockerSandboxBackend respects explicit availability override", async () => {
  const availableBackend = new DockerSandboxBackend({ available: true });
  const unavailableBackend = new DockerSandboxBackend({ available: false });

  assert.equal(await availableBackend.isAvailable(), true);
  assert.equal(await unavailableBackend.isAvailable(), false);
});

test("DockerSandboxBackend wraps executor results in a normalized sandbox response", async () => {
  const backend = new DockerSandboxBackend({
    executor: async (request) => ({
      exitCode: 0,
      stdout: `${request.command} ${request.args.join(" ")}`.trim(),
      stderr: "",
    }),
  });

  const result = await backend.execute({
    command: "echo",
    args: ["hello", "docker"],
  });

  assert.equal(result.backend, "docker");
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "echo hello docker");
});

test("DockerSandboxBackend converts executor failures into sandbox errors", async () => {
  const backend = new DockerSandboxBackend({
    executor: async () => {
      throw new Error("docker exploded");
    },
  });

  const result = await backend.execute({ command: "echo" });

  assert.equal(result.backend, "docker");
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr, /docker exploded/);
});

test("DockerSandboxBackend delegates file upload and download helpers", async () => {
  const writes = [];
  const backend = new DockerSandboxBackend({
    fileWriter: async (files, session) => {
      writes.push({ files, session });
    },
    fileReader: async (path, session) => `${session?.id ?? "no-session"}:${path}`,
  });
  const session = {
    id: "docker-session-1",
    backend: "docker",
  };

  await backend.writeFiles(
    [{ path: "/workspace/hello.txt", content: "hello docker" }],
    session,
  );
  const content = await backend.readFile("/workspace/hello.txt", session);

  assert.deepEqual(writes, [
    {
      files: [{ path: "/workspace/hello.txt", content: "hello docker" }],
      session,
    },
  ]);
  assert.equal(content, "docker-session-1:/workspace/hello.txt");
});
