# 统一应用入口

日期：2026-09-15。相关原则：TXS-04、TXS-07、TXS-09、TXS-10。

原先 `demo.py`、`run_gateway.py` 和 `demo_context.py` 分别组装运行时，只有上下文
示例配置了归档和压缩。用户从终端或网页进入时，实际启用的功能因此不同。

现在由 [`run.py`](../run.py) 提供统一入口，所有模式使用
[`titanx/application.py`](../titanx/application.py) 的公共配置。上下文管理成为这个
应用的默认能力；SDK 构造函数本身的可选配置和默认值保持不变。

## 使用方式

| 命令 | 行为 |
| --- | --- |
| `python run.py` | 在终端连续对话，同一进程内复用运行时 |
| `python run.py "你好"` | 执行一轮输入并退出 |
| `python run.py --web` | 启动网页界面，默认监听 `127.0.0.1:3000` |
| `python run.py --web --port 3001` | 修改网页服务端口 |
| `python run.py --check-context` | 执行原上下文示例的离线校验流程 |
| `python run.py --data-dir ./local-data` | 修改本地数据目录，也可与其他模式参数组合 |

默认数据目录是当前工作目录下的 `.titanx`；SQLite 归档路径是该目录下的
`context.sqlite`。不同模式共用配置和存储实现，但各自创建的运行时有独立的会话范围。
旧脚本只做兼容转发，不再保有各自的运行时组装逻辑。

终端支持 `/exit` 退出，以及 `/compact` 请求在下一条消息调用模型前压缩。兼容的
`python demo.py` 默认执行一次 `Hello, TitanX!`；`python run_gateway.py` 等价于
`python run.py --web`；`python demo_context.py` 等价于 `python run.py --check-context`。
原有 `uvicorn run_gateway:app` 导入方式继续可用，数据库在 lifespan 中打开。

## 默认上下文行为

统一入口为运行时提供 `ContextOptions` 和 `CompactionOptions`：

- 消息归档到本地 SQLite。
- 大工具输出先归档，再在活跃上下文中保留有界预览和引用。
- 调用主模型前检查输入预算，达到阈值时使用内置 `LlmCompactionStrategy` 生成结构化摘要。
- `context_search` 和 `context_read` 在当前运行时的会话范围内检索、分页读取原文。
- 当前任务由宿主维护的 `TaskState` 表达，压缩不负责重建授权或批准记录。

输入压缩阈值为 12,000，压缩后目标为 9,000；模型窗口配置为 20,000，输出预留和
安全余量各 1,000。当前使用默认 UTF-8 字节估算，不是模型 tokenizer 的精确计数。
大输出转存阈值为 12,000 字符，预览为 800 字符，单次回查最多 4,000 字符；压缩
保留最近至少 6 条消息及完整工具组。主动提前压缩时摘要可能比待替换内容长；提交
条件是重建请求符合目标预算，并非每次处理都必须缩短消息。

以上数值均取自 `DemoApplication.create_runtime()`（`application.py`）的
`CompactionOptions` 与 `ContextOptions`（`context/manager.py`）默认值；源代码
是唯一事实来源，本节数值与其保持一致，如发生变动以代码为准。

终端和网页通过 `create_sandboxed_runtime()` 保留默认沙箱接线。上下文校验也使用
`DemoApplication.create_runtime()` 及相同上下文设置，但传入窄范围的合成日志工具
和预设 adapter；该工具只在进程内生成文本，没有文件或网络操作。它验证上下文流程，
不验证 WASM、Docker 或 E2B 的实际隔离能力。

当前应用使用离线模拟 adapter，包括摘要响应。上下文校验验证摘要结构、来源引用、
预算及状态流转，不证明真实模型摘要的语义保真度。接入真实模型仍需要实现并接入
`LlmAdapter`；本次整合没有新增外部模型调用。

详细的摘要、预算、转存和失败处理规则见[上下文机制](context-management.md)。

## 执行边界与原则

| 原则 | 本次接入 | 保留的边界与缺口 |
| --- | --- | --- |
| TXS-04 身份与会话范围 | 创建运行时时由宿主分配新的 UUID，归档和回查绑定该运行时会话；网关请求中的 session selector 只用于选择进程内会话 | selector 不作为持久化归档的访问授权。现有网关不是完整的多租户认证和资源所有权系统；共享 API key 也不能代替租户隔离 |
| TXS-07 上下文始终是数据 | 统一入口接入既有归档、引用、结构化摘要、任务状态和有界回查 | 摘要不授予权限，批准不从摘要重建；本次没有宣称解决全部来源传播或摘要准确性问题 |
| TXS-09 安全恢复 | 同一进程内连续使用运行时；SQLite 保留上下文证据 | 重启后创建新的宿主会话，不根据客户端 selector 自动加载旧归档；归档不提供执行账本，也不恢复批准、在途工具调用或副作用状态 |
| TXS-10 消耗与停止 | 共用上下文预算、转存阈值、分页边界及既有运行时停止机制；明确关闭 SQLite 资源 | 本次没有实现统一成本、全局总时长或跨进程恢复预算，也不能用模拟校验代替真实模型和沙箱限额验证 |

网页模式通过 FastAPI lifespan 持有共享 SQLite store，并在应用结束时关闭；终端
模式通过 `finally` 关闭 store。共享 store 不表示不同运行时共用同一个会话 ID。
网页默认绑定回环地址；上线部署仍须按现有安全设计落实认证、会话所有权和资源授权。
终端显示转存、压缩和停止原因；网页显示压缩失败、准备阻塞、重试耗尽及异常停止事件。

## 验证记录

验证入口为 [`tests/test_application.py`](../tests/test_application.py) 及离线上下文
校验。验证命令如下，各项执行情况在本节末尾分别记录：

```bash
python -m compileall -q titanx run.py demo.py run_gateway.py demo_context.py
python -m pytest -q tests/test_application.py tests/test_context_compaction.py tests/test_context_management.py tests/test_gateway_chat.py tests/test_gateway_hardening.py tests/test_runtime_lifecycle.py
python run.py "你好"
python run.py --check-context
```

已核对的行为包括：各入口使用相同上下文能力；终端支持单次和连续输入；网页连续
请求复用进程内会话；新宿主会话不能凭客户端 selector 读取旧持久化会话；存储在正常
退出及异常路径关闭；原始工具输出可回查且不会重放工具；旧脚本仍可运行。

已执行 `python run.py --check-context`，结果如下：

- 合成工具输出由 44,017 字符转存为 1,150 字符的预览和引用。
- 三次主动压缩的请求估算分别为 3,691 → 3,960、4,077 → 2,772、2,895 → 2,352，
  均符合 9,000 的目标预算；第一轮说明提前压缩不保证立即变短。
- 原始工具只执行 1 次，任务版本最终为 2，原始证据仍可检索。

这些数字来自离线预设响应，用于确认接线和流程。

最终验证结果（2026-09-15）：

- 上述六个测试文件共 **103 passed in 8.08s**；包含新增的 4 项入口回归测试。
- 默认运行时和网页各连续提交 20 条约 600 字符的消息，自然触发压缩并完成全部对话；
  压缩后能读取最早消息原文。此场景发现 6,500 的旧目标无法容纳完整工具目录与最近
  消息，因此共享目标调整为 9,000，仍低于 12,000 的触发阈值。
- 单条输入过大时，CLI 返回非零；网页流包含阻断和停止原因，不产生虚假的回复。
- SQLite 在应用生命周期开始时打开、结束后关闭；不同浏览器 selector 对应不同的
  宿主 UUID，新旧入口 `--help` 均不会创建归档文件。
- `compileall`、UI 内联 JavaScript 语法检查和 `git diff --check` 通过。
- 实际终端验证单次、连续输入、`/compact` 和 `/exit`；兼容终端与上下文脚本均返回 0。
- 临时启动 `127.0.0.1:3031`，通过浏览器确认 Echo 回复及超预算停止提示；随后正常
  关闭服务，并看到 application shutdown complete。测试归档使用临时目录。
