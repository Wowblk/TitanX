# KnowFlow Agent（`titanx-agent`）

KnowFlow 助手背后的 Python agent 服务。它把通用的 TitanX runtime 适配到
KnowFlow：一个 Kimi（Moonshot）LLM adapter、一个调用 KnowFlow HTTP API 的工具
runtime，以及一个 gateway 启动脚本。

TitanX SDK **不再**内嵌在这里。SDK 只存在于 monorepo 根目录（`../../../titanx`），
本包以路径依赖的方式引用它。

## 目录结构

| 路径 | 作用 |
| --- | --- |
| `knowflow_agent/llm/kimi.py` | `KimiLlm` — Moonshot `chat/completions` adapter |
| `knowflow_agent/tools/knowflow.py` | `KnowFlowToolRuntime` — 四个 KnowFlow 工具（均为 `return_direct`）|
| `run_gateway.py` | 会话工厂 + `create_gateway` 启动（端口 3000）|
| `tests/` | agent 自身测试；SDK 测试套件在仓库根目录 |

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

在本目录安装时会以路径依赖的方式从 `../../../` 引入 SDK。

## 运行

```bash
KIMI_API_KEY=... python run_gateway.py    # http://localhost:3000
```

未设置 `KIMI_API_KEY` 时 gateway 回退到 `EchoLlm`（不会调用任何工具）。

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `KIMI_API_KEY` | — | Moonshot API key；未设置则用 `EchoLlm` |
| `KIMI_BASE_URL` | `https://api.moonshot.cn` | Chat API 地址 |
| `KIMI_CHAT_MODEL` | `moonshot-v1-8k` | Chat 模型 |
| `KNOWFLOW_API_BASE_URL` | `http://127.0.0.1:8080` | 工具访问的 KnowFlow 后端 |
| `TITANX_MAX_ITERATIONS` | `8` | 单次 prompt 的迭代上限 |

## 两点需要留意

**默认拒绝（deny-by-default）策略。** SDK 会拒绝未出现在策略白名单里的已注册
工具。`run_gateway.py` 在 `KNOWFLOW_TOOLS` 中列出了四个 KnowFlow 工具；新增工具
必须加入该列表，否则 agent 无法调用。

**按会话绑定凭据。** gateway 通过 `request_context` 参数把请求体交给会话工厂，
因此每个用户的 bearer token 和 user id 在会话创建时绑定（之后该会话复用）。

## 测试

```bash
python -m pytest -q      # 需在本目录执行，以保证 knowflow_agent 可导入
```

## Docker

镜像从 monorepo 根目录构建（因为需要 SDK 源码）：见 `../deploy/docker-compose.yml`
中的 `titanx-agent` 服务与本目录的 `Dockerfile`。
