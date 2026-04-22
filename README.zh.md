# TitanX

TitanX 是一个 Python Agent SDK，用于构建具备显式运行时语义、多层安全、策略控制、上下文压缩和沙箱工具执行能力的 autonomous agent。

当前仓库跟踪 Python 版本实现。之前的 TypeScript 版本已单独保留在旁边的 `../TitanX-ts/`，主要作为参考和对照。

## 快速开始

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python demo.py
```

## Gateway 示例

```bash
python run_gateway.py
```

默认服务地址是 `http://localhost:3000`。

## 目录结构

| 路径 | 作用 |
| --- | --- |
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
| `titanx/gateway/` | FastAPI gateway 和 UI 服务 |
