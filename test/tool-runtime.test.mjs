import test from "node:test";
import assert from "node:assert/strict";

import { SandboxRouter } from "../dist/sandbox/router.js";
import { SandboxedToolRuntime } from "../dist/sandbox/tool-runtime.js";

function backend(kind) {
  return {
    kind,
    capabilities() {
      return {
        kind,
        supportsPersistence: true,
        supportsSnapshots: true,
        supportsBrowser: kind === "e2b",
        supportsNetwork: kind !== "wasm",
        supportsPackageInstall: kind !== "wasm",
        supportedCapabilities: ["command-exec"],
      };
    },
    async isAvailable() {
      return true;
    },
    async execute(request) {
      return {
        backend: kind,
        exitCode: 0,
        stdout: `${request.command}:${kind}`,
        stderr: "",
        durationMs: 1,
      };
    },
  };
}

test("SandboxedToolRuntime routes tool execution through the selected backend", async () => {
  const router = new SandboxRouter([
    backend("wasm"),
    backend("docker"),
    backend("e2b"),
  ]);
  const runtime = new SandboxedToolRuntime(router, [
    {
      definition: {
        name: "run_browser_task",
        description: "run a browser task",
        parameters: { type: "object" },
      },
      policy: {
        riskLevel: "high",
        needsBrowser: true,
        requiresRemoteIsolation: true,
      },
      request(params) {
        return {
          command: String(params.command ?? "noop"),
        };
      },
    },
  ]);

  const result = await runtime.execute("run_browser_task", {
    command: "scrape",
  });

  assert.equal(result.error, undefined);
  assert.equal(result.output, "[sandbox:e2b] scrape:e2b");
});

test("SandboxedToolRuntime returns a stable error for unknown tools", async () => {
  const router = new SandboxRouter([backend("wasm")]);
  const runtime = new SandboxedToolRuntime(router, []);
  const result = await runtime.execute("missing_tool", {});

  assert.equal(result.error, "unknown_tool");
  assert.match(result.output, /Unknown tool/);
});
