# TitanX

TitanX 是一个 Python Agent SDK，用于构建具备显式运行时语义、多层安全、策略控制、上下文压缩和沙箱工具执行能力的 autonomous agent。

当前仓库跟踪 Python 版本实现。之前的 TypeScript 版本已单独保留在旁边的 `../TitanX-ts/`，主要作为参考和对照。

## 快速开始

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python run.py
```

`run.py` 是统一入口，默认进入终端连续对话，也可以选择以下模式：

```bash
python run.py "你好"                   # 单次输入，回复后退出
python run.py --web                   # 网页界面：http://127.0.0.1:3000
python run.py --web --port 3001       # 使用其他端口
python run.py --check-context         # 校验归档、回查和压缩
python run.py --data-dir ./local-data # 指定本地数据目录
```

各模式共用 `titanx/application.py` 的运行时配置，**默认开启消息归档、大工具输出转存、
内置结构化摘要压缩和原文回查**。数据目录默认是 `.titanx`，上下文归档保存在
`.titanx/context.sqlite`。
终端支持 `/compact`（在下一条输入调用模型前尝试压缩）和 `/exit`（退出）。终端及
网页模式保留默认沙箱运行时接线；上下文校验使用进程内合成工具验证流程。

当前内置的仍然是**离线模拟 LLM**，不会调用真实模型 API。这里的默认启用只作用于统一
应用入口；直接使用 SDK 的 `AgentRuntime` 或 `create_sandboxed_runtime()` 时，仍由
调用方传入上下文配置。归档持久化不代表重启后自动恢复正在进行的对话或工具执行。

旧的 `demo.py`、`run_gateway.py` 和 `demo_context.py` 保留为兼容转发脚本，不再分别
维护运行时配置。实现方式、会话边界和验证记录见[统一入口说明](docs/unified-entrypoint.md)。

## 目录结构

| 路径 | 作用 |
| --- | --- |
| `run.py` | 终端、网页和上下文校验的统一入口 |
| `titanx/application.py` | 应用运行时组装和默认上下文配置 |
| `titanx/runtime.py` | Agent 主运行循环 |
| `titanx/types.py` | 核心 dataclass 和 adapter 接口 |
| `titanx/factory.py` | 默认运行时组装 |
| `titanx/safety/` | 输入校验、脱敏和安全检查 |
| `titanx/sandbox/` | 工具运行时、路由、路径保护和后端接口 |
| `titanx/resilience/` | 重试和熔断支持 |
| `titanx/context/` | token 跟踪和上下文压缩 |
| `titanx/policy/` | 策略存储、审计日志和 break-glass 控制 |
| `titanx/storage/` | 存储后端接口和实现 |
| `titanx/retrieval/` | 混合检索和 MMR 排序 |
| `titanx/tools/` | 可选工具目录，包括参考 IronClaw 的 WASM 工具 |
| `titanx/gateway/` | FastAPI gateway 和 UI 服务 |

## IronClaw WASM 工具目录

TitanX 内置了一组可选的 IronClaw 风格 WASM 工具定义：`github`、`gmail`、
`google_calendar`、`google_docs`、`google_drive`、`google_sheets`、
`google_slides`、`slack`、`telegram_mtproto`、`web_search`、`llm_context`
和 `composio`。

启用方式：

```python
from titanx import CreateSandboxedRuntimeOptions, create_sandboxed_runtime
from titanx.sandbox import WasmCommandRegistration

runtime = create_sandboxed_runtime(CreateSandboxedRuntimeOptions(
    llm=llm,
    safety=safety,
    enable_ironclaw_wasm_tools=True,
    wasm_commands={
        # 每个 command 指向一个 TitanX 兼容的 WASI wrapper。
        "web_search_tool": WasmCommandRegistration(module_path="./wasm/web_search_tool.wasm"),
        "github_tool": WasmCommandRegistration(module_path="./wasm/github_tool.wasm"),
    },
))
```

这些 handler 使用 `titanx-wasi-json-argv` ABI：TitanX 执行已注册的 WASI
command，并传入一个 JSON 参数：

```json
{"tool":"web_search","action":"search","params":{"query":"TitanX"}}
```

这里没有假设 IronClaw 的 component-model/WIT ABI。要真正运行对应工具，需要把
工具编译或包装成 TitanX 兼容的 WASI command：读取 `argv[1]`，然后把结果写到
stdout。
