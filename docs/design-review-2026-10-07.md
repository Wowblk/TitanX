# TitanX 设计评审

日期：2026-10-07
范围：`titanx/` 全部模块（~15k 行），含 runtime、context、policy、mcp、gateway、factory 及 `docs/` 下的设计文档。
方法：静态阅读代码 + 交叉核对文档，未运行、未改动任何代码。所有结论均带 `file:line`。

> **处理状态（2026-10-07 更新）：已全部闭合。** 本评审编号问题 #1–#16 与各非编号小节
> （§1.6 / §2.1 / §2.3 / §3.1 / §3.2 / §5.3 / §5.4）均已修复，逐条对应的落地 PR 见文末
> 「优先级汇总」表的「状态」列；实现细节见 `CHANGELOG.md`。下表 `file:line` 为评审当时
> 的快照坐标，修复后行号已变动，仅作定位参考。

---

## 0. 一句话总结

`ExecutionGuard` 那一层的 TOCTOU 防护本身做得不错（epoch 在首个 `await` 前发布、派发前重新校验、单次消费）。**风险几乎全部集中在各平面"接线"的地方**——工厂默认不共享 `PolicyStore`、MCP 与 `PolicyStore` 分家、审计少字段、网关无 teardown、transcript 无单一 owner。下面按严重程度排列。

---

## 1. 信任边界与安全接线（最严重）

### 1.1 【Critical】默认工厂里沙箱路径策略根本没接上
`factory.py:160-165` 用 `policy_store=options.policy_store` 构造 `SandboxedToolRuntime`；`factory.py:177` 把同一个（可能是 `None` 的）值传给 `AgentRuntime`。而 `AgentRuntime` 在 `runtime.py:103-110` 会**自己新建**一个 `PolicyStore`。

后果（宿主不显式传 `policy_store` 时）：
- `SandboxedToolRuntime._policy_store` 恒为 `None` → `tool_runtime.py:51-58` 取不到 live policy；
- `tool_runtime.py:59` 的 `if effective_paths:` 为假 → **宿主侧路径检查整个跳过**；
- `tool_runtime.py:69` 为假 → **不会把 `allowed_write_paths` 传给后端**，Docker `_filesystem_flags` 收到 `None`（`docker.py:116,151`），kernel 边界也不生效。

即 `model-tool-loop-security-design.md:36`、README:188-189 承诺的"写入隔离的真正边界"，在默认路径下**从未被武装**。结果不是"拒绝全部写"，而是"完全没执行"。

### 1.2 【High】MCP admission 是独立于 PolicyStore 的第二套授权平面
`McpAdmissionRuntime`（`mcp/admission.py:340`）有自己的 allowlist、指纹、epoch（`admission.py:86-207`），与 `PolicyStore`/`ExecutionGuard` 不共享任何状态：
- 放行由两套逻辑各判一次（`admission.py:201-207` 决定是否被发现，`policy_store.py:66-109` 决定审批/拒绝）；
- `McpAdmissionPolicy` 默认 `requires_approval=True`，但 `policy_store.py:100-104` 的 `auto_approve_tools` 会**静默覆盖**——MCP 无法强制审批；
- MCP allowlist 不进入 policy 快照/epoch/审计，没有统一 allow/deny 视图。

### 1.3 【High】不是默认拒绝
`policy_store.py:106-109`：任何已注册且 `requires_approval=False` 的工具直接放行，无资源检查。与 `PRINCIPLES.md` TXS-02"权限不明确…不派发操作"直接冲突（`ADOPTION.md:15` 承认）。内置工具因为默认 `requires_approval=True`（`factory.py:86,101,116`）掩盖了这个缺口，自定义 handler 则暴露。

### 1.4 【High】审计不满足自己的原则
- `execution.py:320-330` 的 `audit_details()` 只输出 `execution_id/run_id/batch_id/ordinal/policy_epoch/approval_status`，**丢掉了 `ToolIntent` 里已有的 identity（thread/session/user/channel）和 `contract_digest`**，违反 `PRINCIPLES.md` TXS-11（identity/session/工具契约需入审计）。
- `runtime.py:109` 默认 `AuditLog()` 无 `log_path` → 工具决策只在内存，`append()` 返回不代表落盘；"集中审计"在默认部署下不落盘，而 `audit.py:365-381` 又会因此对**每个** runtime 都打 warning（噪声化）。

### 1.5 【Medium】第二套审计表仍在公开 API
`StorageBackend.save_log`（`storage/types.py:72`、`libsql.py:265`、`pg_vector.py:177`）是被 `audit_log.py:5-9` 点名批评的 Q20 反模式，目前无生产写入者但仍是公开接口、`routes/logs.py` 仍读，且 `audit_sinks.storage_secondary_sink`（`audit_sinks.py:52-80`）转发的字段比 JSONL 记录更少（丢 `execution_id/run_id/batch_id/ordinal/policy_epoch`）。

### 1.6 【Medium】其余安全缝隙
- `BreakGlassController.dispose()`（`break_glass.py:156-169`）：取消计时器但**不回滚**放宽的策略，公开 API、被 `policy/__init__.py:16` 导出，docstring 自认是 foot-gun。
- `approved_tool_call_ids` 无授权语义却仍被写/清/读（`runtime.py:293,315,367,673`），警告只写在 `approve_pending_tool` docstring，`AgentState` 类型上无警示。
- MCP 合约哈希在 `admission.py:611-628` 内联重算，可能与公开的 `tool_contract_fingerprint`（`admission.py:267-288`）漂移，导致外部计算的 pin 校验不过。
- `McpAdmissionRuntime.execute` 在 `self._lock` 下做整个网络调用（`admission.py:407-450`），同 runtime 所有 MCP 工具串行，一个挂死会阻塞其余工具。
- `ExecutionGuard` 绑定 identity 但运行时从不认证（`execution.py:161-163`）；`runtime.py:51,73-81` 的 `user_id/channel` 可被不可信调用方指定，绑定形同虚设（文档承认，但代码把它当授权输入）。

---

## 2. 状态所有权不清

### 2.1 【High】transcript 被两个组件各自重写
`manager.ContextManager.prepare`（`manager.py:105-108`）与 `compactor.auto_compact_if_needed`（`compactor.py:221-222`）都直接改 `state.messages`，仅靠 `runtime.py:534-548` 的调用顺序协调，**没有任何模块强制"先 prepare 再 compact"**。两者各有自己的分组/阈值/重试/提交逻辑，字节阈值与字符阈值并存。

相关：
- 摘要身份定义两处：`compactor._is_summary`/`SUMMARY_PREFIX`（`compactor.py:17-26`）重复了 `types.py:44-47` 的 `SystemMessage.is_summary` 契约。
- 任务持久化两种：既有消息行（`manager.py:75`）又有 `tasks` 表（`store.py:160-164`），`load_task` 无生产调用。
- session_id 两个来源：`ContextOptions.session_id`（`manager.py:19`）与 `AgentConfig.session_id`（`types.py:112`），`runtime.py:83-84` 单向 patch，构造顺序一旦改变就会错配。

### 2.2 【High】没有 teardown 契约
`AgentRuntime`/`ContextManager` 都没有 `close()`。`SessionRegistry` 按 LRU/TTL 驱逐时（`session_registry.py:141-163`）只弹内存对象，**不销毁 sandbox session**——`docker.py:406`、`sidecar.py:375`、`session_manager.py:224` 的 `destroy_session` 从网关驱逐路径不可达。→ 内存有界，**容器/磁盘无界**。

同时 `application.py:58` 每次 `create_runtime` 都新造 `uuid4()`，`store.delete_session`（`store.py:170-174`）无生产调用者 → 被驱逐的 SQLite 行永久泄漏。文档把 `delete_session` 当作清理手段，但它既没被调用、也不与 registry 驱逐联动。

### 2.3 【Medium】config/state 边界名义存在、实际被绕过
- `runtime.py:83-86` 构造后从旁路 option `replace()` config：`context_options.session_id` 改 `config.session_id`；**`reserved_output_tokens` 静默改写 `config.max_output_tokens`**（宿主只想预留预算，却顺手改了 provider 生成长度）。config 组装本应在 factory。
- `max_iterations`/`auto_approve_tools` 在 config 与 PolicyStore 里各存一份，循环只读 policy 那份（`runtime.py:403-409`）——config 里那份是误导性种子。
- `_effective_auto_approve`（`runtime.py:408-409`）**从未被调用**，与 `policy_store.py:94-104` 重复。

---

## 3. 运行时结构

### 3.1 【High】`AgentRuntime` 一个类承担至少 7 种职责
`runtime.py` 1293 行。`__init__`（45-142）既做接线又从 option 重推 config；`_execute_tool_calls`（796-1102）**单方法 306 行**，把 参数校验→策略→审批暂停→执行→输出安全检查→审计→消息提交→事件发射 串在一起，含 5 条异常恢复分支。

全文约 24 处函数内 `import`（64,65,69,119,128,131,296,412,457,495,554,686,710,771,789,812,936,1105,1146,1157,1212,1247…）来绕循环依赖——运行时不 import context/policy/safety 就起不来，分层已破。

### 3.2 【Medium】隐藏的第二状态机
`_context_stop_reason`/`_context_completion_pending`（`runtime.py:134-135`）叠加在 `AgentState.signal` 之上的私有恢复状态，由 `_stop_for_context`(790)、`_finish_loop`(776-779)、`retry_context`(178-185)、`_run_prompt`(282-283) 多处读写。

### 3.3 【Low】死代码
`wait_for_approval`（`runtime.py:369`）、`require_api_key`（`server.py:51`）、`_effective_auto_approve`（`runtime.py:408`）、`server.run_gateway`（`server.py:134`）均无生产调用者。

---

## 4. 入口与 CLI 碎片化

### 4.1 【Medium】五个入口 shim + 一个完全独立的 CLI
`run.py`(5)/`run_gateway.py`(12)/`demo.py`(7)/`demo_context.py`(7)/`application.main`(232-259) 之外，`titanx/cli.py:253` 是**另一个** console script。`pyproject.toml` 只注册 `titanx = titanx.cli:main`（审计 CLI）——装了包的用户拿到的是审计命令，真正的应用只能靠 `python run.py`。

### 4.2 【Medium】鉴权逻辑重复且语义相反
`_check_api_key` **定义两遍**：`server.py:38-48`（缺 provided 返 False）vs `chat.py:42-47`（缺 expected 返 True）。`require_api_key`（`server.py:51-62`）声明是"唯一鉴权入口"却无人调用。SSE 与 WS 的 run+close 生命周期近乎重复（`chat.py:159-178` vs `369-384`）。

### 4.3 【Medium】旗舰入口下部分路由恒不可用
`create_demo_gateway`（`application.py:77-102`）不传 `storage`/`retriever` → `/api/memory`、`/api/jobs`、`/api/logs` 恒返 501（`memory.py:17` 等）。`run_gateway.py:12` 在 import 时另建一个默认 gateway，`uvicorn run_gateway:app` 会静默忽略 CLI 的 `--port/--data-dir`。绑定地址也不一致：`application.main` 绑 `127.0.0.1`（`application.py:252`），`server.run_gateway` 绑 `0.0.0.0`（`server.py:134-137`）。

---

## 5. 上下文与持久化

### 5.1 【High】单写锁 + 取消泄漏
`SQLiteContextStore` 用一把 `threading.RLock`（`store.py:96-100`）串行所有 runtime/session 的所有上下文操作。`manager._wait` 超时只取消 `await`，`to_thread` 事务继续跑并持锁（文档 `context-management.md:244-245` 承认）。`close()` 与排队事务有竞态（`store.py:176-180`），而 `application.py:98` 在请求可能仍在收尾时关闭。

### 5.2 【Medium】PTL 选错牺牲组
`compactor.py:62` 的 `_drop_largest` 用字节估算挑要丢的组，而非触发溢出的 `options.token_estimator`——自定义 tokenizer 下"最大组"可能是错的。`_estimate` 每次调用还 deepcopy config（frozen，没必要）+ messages（`compactor.py:88`）。

### 5.3 【Medium】O(n²) 归档
`prepare` 全量归档一次（`runtime.py:536`）、`_finish_loop` 再归档一次（`runtime.py:774`）、`commit_compaction` 再序列化一次（`store.py:147`）。每次把整个 transcript JSON 序列化并逐行 `INSERT OR IGNORE`，经单写锁。

### 5.4 【Low】其它
- `search` 是对序列化 JSON 的 `instr` 子串匹配（`store.py:141-143`），会命中 role 名/UUID/artifact id，非内容搜索。
- `context_read` schema 声明 max 16000，实际按 `read_max_chars`（默认 4000）静默截断，且不告知（`manager.py:49,117-122`）。
- artifact 仅按内容哈希、按 `(session,id)` 存（`store.py:86-88`），无去重/GC；`put_artifact`（`manager.py:92`）在"是否更短"判断前调用 → 可能留孤儿（`manager.py:102-104`）。
- `ContextStore` ABC 不完整：`list_compactions`/`delete_session`/`close` 只在具体类上（`store.py:34-53` vs 155/170/176）。

---

## 6. 文档与实现漂移

| 位置 | 问题 |
|---|---|
| `context-management.md:47` vs `unified-entrypoint.md:91` | 同一 demo 结果给出 `418` vs `1150` 字符两个数字（实现 ~1150，418 为旧值） |
| `context-compaction.md:156` | 说 commit 条件是"严格小于 token_budget"，代码是 `<= options.target_tokens`（`compactor.py:199`） |
| `context-compaction.md:17` | 说压缩需同时有 `compaction_strategy` 和 `compaction_options`，但 `runtime.py:130-132` 现会自动建 `LlmCompactionStrategy` |
| `runtime-prompt-admission.md:183` | 说"不修改 resume()"，但代码已有 `_exclusive_execution`（`runtime.py:227-245`） |
| `context-runtime-comparison-2026-09-08.md:21-33` | 状态表描述集成前状态，头部未标 superseded |
| `model-tool-loop-security-design.md:36` vs 实现 | 承诺 Docker path 边界，但默认工厂不设路径（见 1.1） |
| `PRINCIPLES.md` TXS-11 vs `execution.py:320-330` | 审计缺 identity/contract（见 1.4） |
| `unified-entrypoint.md:42-46` | 重复硬编码压缩常量（与 `application.py:60-65`、`context/types.py:60-64` 三处不同步） |

---

## 优先级汇总

| # | 级别 | 问题 | 位置 | 状态 |
|---|---|---|---|---|
| 1 | Critical | 默认工厂 sandbox 与 runtime 的 PolicyStore 不共享 → 路径检查与挂载传播双双静默失效 | `factory.py:160-177`, `runtime.py:103-110`, `tool_runtime.py:51-70`, `docker.py:151` | ✅ PR #4 |
| 2 | High | 审计决策/调用记录缺 identity/session 与工具契约摘要，违反 TXS-11 | `execution.py:320-330`, `runtime.py:1239-1262` | ✅ PR #3 |
| 3 | High | MCP admission 与 PolicyStore/ExecutionGuard 完全分离，无共享 epoch/快照/决策记录 | `mcp/admission.py` vs `policy/policy_store.py` | ✅ PR #4 |
| 4 | High | 已注册的非审批工具默认放行（非默认拒绝） | `policy_store.py:106-109` | ✅ PR #4 |
| 5 | High | transcript 无单一 owner，manager 与 compactor 各自重写 | `manager.py:105-108`, `compactor.py:221` | ✅ PR #4 |
| 6 | High | 无 teardown 契约：驱逐不销毁 sandbox session；`delete_session` 无人调用 → 磁盘泄漏 | `session_registry.py:141-163`, `application.py:58`, `store.py:170` | ✅ PR #4 |
| 7 | High | `reserved_output_tokens` 静默改写 `config.max_output_tokens` | `runtime.py:85-86` | ✅ PR #4 |
| 8 | Medium | `McpAdmissionRuntime.list_tools()` 在 `discover()` 前为空 → 先建 runtime 会让 MCP 工具永久 `unknown_tool` 且无报错 | `admission.py:391-400`, `runtime.py:67,113` | ✅ PR #5 |
| 9 | Medium | 单写锁 + 取消泄漏 + `close()` 竞态 | `store.py:96-100,176-180` | ✅ PR #5 |
| 10 | Medium | PTL 用字节而非配置的 tokenizer 选牺牲组 | `compactor.py:62` | ✅ PR #5 |
| 11 | Medium | 鉴权 `_check_api_key` 两处语义相反；`require_api_key` 死代码 | `server.py:38,51`, `chat.py:42` | ✅ PR #5 |
| 12 | Medium | 入口/CLI 碎片：5 个 shim + 独立审计 CLI；网关多路由恒 501 | `application.py:77-102`, `cli.py:253` | ✅ PR #5 |
| 13 | Medium | 第二审计表 `StorageBackend.save_log` 仍在公开 API | `storage/types.py:72` | ✅ PR #5 |
| 14 | Low | `BreakGlassController.dispose()` 公开 foot-gun（取消计时不回滚） | `break_glass.py:156-169` | ✅ PR #5 |
| 15 | Low | 死代码：`_effective_auto_approve`/`wait_for_approval`/`require_api_key`/`server.run_gateway` | 见 3.3 | ✅ PR #5 |
| 16 | Low | 文档与实现多处漂移 | 见第 6 节 | ✅ PR #5 |

**不在上表的条目：**

- **§3.1**（`AgentRuntime` god-class）与 **§3.2**（隐藏状态机）为结构性债，由 **PR #8** 闭合：
  工具管线提取为 `ToolCallPipeline`，恢复状态集中为 `ContextRecovery`（零行为变更重构）。
  §3.1 提取后经变异测试发现的覆盖缺口由 **PR #9** 补测。
- 非编号小节：**§5.4 / §1.6** 由 **PR #6** 闭合；**§2.3 / §5.3**（以及 §1.6 剩余项）由
  **PR #7** 闭合；**§2.1** 除表中 #5 外，摘要身份定义、任务持久化、`session_id` 来源等
  相关子项随 PR #4 / PR #7 一并收口。

---

## 做得好、不要被淹没的部分

- `ExecutionGuard` 的派发前重新校验与单次消费（`execution.py:298-318`）在单事件循环下正确关闭了 decision→dispatch 的 TOCTOU，epoch 在首个 `await` 前发布（`policy_store.py:138,182`）。
- `PolicyStore` 读写均 deepcopy、rollback 重新校验快照（`policy_store.py:54,61,169`）。
- `AuditLog` 每条 entry 与调用方/sink 解耦，单写协程，MCP 发现/结果大小有界（`audit_log.py:136-254`）。
- MCP 结果提取刻意丢弃 `_meta` 与非文本块，合约 pin 用 `hmac.compare_digest`（`admission.py:291-337,633`）。

---

*本评审为纯静态阅读结论，未执行代码。建议修复顺序：先 #1（唯一"默认配置下安全承诺静默失效"的问题），再 #2/#4，然后是所有权问题 #5/#6。*
