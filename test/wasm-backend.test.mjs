import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";

import { WasmSandboxBackend } from "../dist/sandbox/backends/wasm.js";

test("WasmSandboxBackend executes a registered WASI module", async () => {
  const backend = new WasmSandboxBackend({
    commands: {
      hello: {
        modulePath: resolve("examples/hello.wasm"),
      },
    },
  });

  const result = await backend.execute({
    command: "hello",
    args: ["Titanclaw-ts"],
  });

  assert.equal(result.backend, "wasm");
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /Hello from Titanclaw WASI!/);
});

test("WasmSandboxBackend rejects unregistered commands", async () => {
  const backend = new WasmSandboxBackend();
  const result = await backend.execute({ command: "missing-command" });

  assert.equal(result.exitCode, 1);
  assert.match(result.stderr, /Unregistered WASI command/);
});
