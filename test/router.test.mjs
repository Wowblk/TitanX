import test from "node:test";
import assert from "node:assert/strict";

import { SandboxRouter } from "../dist/sandbox/router.js";

function backend(kind, available = true) {
  return {
    kind,
    capabilities() {
      return {
        kind,
        supportsPersistence: kind !== "wasm",
        supportsSnapshots: kind !== "wasm",
        supportsBrowser: kind === "e2b",
        supportsNetwork: kind !== "wasm",
        supportsPackageInstall: kind !== "wasm",
        supportedCapabilities: ["command-exec"],
      };
    },
    async isAvailable() {
      return available;
    },
    async execute() {
      return {
        backend: kind,
        exitCode: 0,
        stdout: `${kind}-ok`,
        stderr: "",
        durationMs: 1,
      };
    },
  };
}

test("SandboxRouter selects wasm by default for low-risk workloads", async () => {
  const router = new SandboxRouter([
    backend("wasm"),
    backend("docker"),
    backend("e2b"),
  ]);

  const selection = await router.select({ riskLevel: "low" });
  assert.equal(selection.backend.kind, "wasm");
  assert.match(selection.reason, /default lightweight sandbox selected/);
});

test("SandboxRouter prefers docker for medium-risk filesystem workloads", async () => {
  const router = new SandboxRouter([
    backend("wasm"),
    backend("docker"),
    backend("e2b"),
  ]);

  const selection = await router.select({ riskLevel: "medium", needsFilesystem: true });
  assert.equal(selection.backend.kind, "docker");
});

test("SandboxRouter falls back from docker to e2b when docker is unavailable", async () => {
  const router = new SandboxRouter([
    backend("wasm"),
    backend("docker", false),
    backend("e2b"),
  ]);

  const selection = await router.select({ riskLevel: "medium", needsFilesystem: true });
  assert.equal(selection.backend.kind, "e2b");
  assert.match(selection.reason, /e2b fallback/);
});

test("SandboxRouter prefers e2b for browser or high-risk workloads", async () => {
  const router = new SandboxRouter([
    backend("wasm"),
    backend("docker"),
    backend("e2b"),
  ]);

  const selection = await router.select({ riskLevel: "high", needsBrowser: true });
  assert.equal(selection.backend.kind, "e2b");
});

test("SandboxRouter honors preferred backend and falls back when needed", async () => {
  const router = new SandboxRouter([
    backend("wasm", false),
    backend("docker"),
    backend("e2b"),
  ]);

  const selection = await router.select({ preferredBackend: "wasm" });
  assert.equal(selection.backend.kind, "docker");
  assert.match(selection.reason, /fallback to 'docker'/);
});
