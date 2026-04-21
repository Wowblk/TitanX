# Examples

This directory contains the smallest possible WASI demo for `Titanclaw-ts`.

## Build `hello.wasm`

The `hello.wat` file is a text-format WebAssembly module that prints a single
line through the WASI `fd_write` import.

If you have `wabt` installed, build it with:

```bash
wat2wasm examples/hello.wat -o examples/hello.wasm
```

On macOS with Homebrew:

```bash
brew install wabt
wat2wasm examples/hello.wat -o examples/hello.wasm
```

## Run with the demo runtime

Wire the generated module into the `Titanclaw-ts` demo runtime:

```ts
import { createDemoRuntime } from "../src/demo.js";

const runtime = createDemoRuntime("/absolute/path/to/Titanclaw-ts/examples/hello.wasm");
await runtime.runPrompt("Run the demo");
console.log(runtime.state.messages);
```

## Run with the factory directly

```ts
import { createSandboxedRuntime } from "../src/factory.js";

const runtime = createSandboxedRuntime({
  llm,
  safety,
  config: { maxIterations: 8, autoApproveTools: true },
  wasmCommands: {
    hello: {
      modulePath: "/absolute/path/to/Titanclaw-ts/examples/hello.wasm",
    },
  },
});
```
