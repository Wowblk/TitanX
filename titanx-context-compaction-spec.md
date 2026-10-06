# Feature: TitanX 上下文压缩机制

## Problem Statement

当前 TitanX runtime 在长任务和多轮工具调用场景下，容易因为单 session 内上下文持续增长而接近或超过模型上下文窗口限制。现有机制如果只依赖模型调用失败后的错误处理，会导致超大 prompt 继续发送给模型，增加延迟、成本和失败率，也可能让 agent 在上下文不完整或不可控的状态下继续运行。

需要引入一套分层的上下文压缩机制，在每次模型调用前进行 pre-flight 检查，优先清理高 token、低长期价值内容；当上下文仍超过预算时，使用可插拔的 `CompactionStrategy` 生成结构化摘要，并重建为可继续执行任务的紧凑上下文。

该机制解决的是单 session 内长任务的上下文预算和连续性问题，不负责跨 session 长期记忆。

## Success Metrics

- 模型调用前可自动识别上下文超预算风险，并触发压缩
- 压缩后上下文 token 数低于当前模型 compaction budget
- 权限、运行环境、当前任务状态等 runtime state 在压缩后可被重新注入
- 自动压缩后下一轮模型调用成功率提升，prompt-too-long 错误显著下降
- 压缩失败时 runtime 显式中断，不进入不可控继续执行状态
- 支持至少 2 类压缩策略：轻量 micro-compaction 和完整 summary compaction

## User Stories

1. 作为 agent runtime，我可以在每次模型调用前检查上下文预算，必要时先压缩再调用模型
2. 作为长任务执行中的 agent，我可以在压缩后保留当前任务目标、关键决策、最近上下文和下一步行动
3. 作为系统开发者，我可以替换或扩展 `CompactionStrategy`，以适配不同模型、成本和质量要求
4. 作为平台运维人员，我可以通过日志和指标观察压缩触发原因、压缩前后 token 数、失败原因和重试次数

## Acceptance Criteria

- [ ] Runtime 在每次模型调用前执行 pre-flight context check
- [ ] 压缩触发条件支持 `estimated_context_tokens + expected_turn_growth > compaction_budget`
- [ ] `compaction_budget` 至少考虑模型上下文窗口、输出 token 预留和 safety buffer
- [ ] 支持 micro-compaction，不调用 LLM 即可清理旧 tool result、大文件读取结果、搜索结果和 shell 输出
- [ ] 支持 summary compaction，通过可插拔 `CompactionStrategy` 生成结构化摘要
- [ ] Summary 至少包含当前任务、关键决策、文件状态、错误修复、pending tasks 和 next step
- [ ] 压缩后上下文重建为 `system/developer context + runtime state snapshot + compaction summary + recent tail`
- [ ] System prompt、developer instructions、权限策略和 tool schema 不被总结丢弃，而是在重建上下文时重新注入
- [ ] 单次 summary 过长或压缩请求触发 prompt-too-long 时进入 PTL fallback
- [ ] PTL fallback 支持移除高成本低价值消息、裁剪最旧历史、缩短 recent tail 和要求更短 summary
- [ ] 连续压缩失败超过阈值后 runtime 显式中断并返回可诊断错误
- [ ] 支持手动触发 `/compact`，并复用自动压缩管线
- [ ] 压缩事件写入可观测日志，包含触发原因、压缩前后 token、策略名、耗时、重试次数和失败原因

## Proposed Design

TitanX 上下文压缩采用分层管线：

```text
pre-flight context check
→ micro-compaction
→ summary compaction
→ runtime state re-injection
→ PTL fallback
→ failure circuit breaker
```

每次模型调用前，runtime 先估算当前上下文规模：

```text
estimated_context_tokens
+ pending_input_tokens
+ pending_tool_result_tokens
+ expected_turn_growth
> compaction_budget
```

其中：

```text
compaction_budget = model_context_window - reserved_output_tokens - safety_buffer
reserved_output_tokens = min(model_max_output_tokens, 20_000)
safety_buffer = 13_000
expected_turn_growth = reserved_output_tokens + tool_growth_estimate
tool_growth_estimate = 10_000 ~ 20_000
```

如果上下文未超过预算，runtime 直接调用模型。如果超过预算，先执行 micro-compaction；若仍超过预算，则执行 summary compaction。

## Micro-Compaction

Micro-compaction 是低风险、非 LLM 的轻量压缩阶段，用于优先清理高 token、低长期价值内容。

可处理对象包括：

- 旧的 tool result
- 大型文件读取结果
- 搜索结果
- shell 输出
- web fetch 输出
- 重复诊断信息
- 已过期的中间状态

清理方式可以是占位符替换：

```text
[Old tool result content cleared]
```

也可以是结构化摘要：

```text
[Tool result cleared: Read src/auth/permissions.ts, 18k tokens, file later modified]
```

Micro-compaction 必须保留最近若干条工具结果，避免模型丢失当前工作现场。

## Summary Compaction

当 micro-compaction 后上下文仍超过预算时，runtime 调用 `CompactionStrategy` 生成结构化 summary。

输入包括：

- 待压缩的历史消息
- 当前 runtime state
- token budget
- 压缩触发原因
- 可选自定义压缩指令

不参与摘要压缩的内容包括：

- system prompt
- developer instructions
- permission policy
- sandbox constraints
- tool schema
- model/runtime 配置

这些内容应在压缩后作为 canonical context 重新注入。

Summary 输出必须结构化，建议包含：

1. Primary Request and Intent
2. Current Task State
3. Key Decisions
4. Files Read or Modified
5. Important Code Details
6. Errors and Fixes
7. Tool Results Worth Remembering
8. Pending Tasks
9. Next Step
10. User Preferences or Constraints

## Context Reconstruction

压缩成功后，runtime 将活跃上下文重建为：

```text
system/developer context
+ runtime state snapshot
+ compaction boundary marker
+ compaction summary
+ recent tail messages
```

`runtime state snapshot` 至少包含：

- cwd / workspace 信息
- 当前模型与权限模式
- active plan / todo 状态
- 最近读过的重要文件
- 最近修改过的文件
- 可用工具状态
- 当前任务目标
- compaction metadata

`recent tail messages` 应保留最近的真实用户消息、assistant 消息和关键工具交互，避免 summary 丢失临近上下文。

## PTL Fallback

如果压缩请求本身触发 prompt-too-long，或 summary 结果仍超过预算，runtime 进入 PTL fallback。

Fallback 顺序：

1. 移除或替换最大的低价值消息
2. 裁剪最旧的历史消息
3. 降低 recent tail 长度
4. 要求 `CompactionStrategy` 生成更短 summary
5. 重新估算 token 并重试

连续失败超过阈值后，runtime 必须中断：

```text
CompactionFailedError:
  reason: "context_unrecoverable"
  attempts: N
  estimated_tokens: X
  budget: Y
```

默认连续失败阈值为 `3`。

## CompactionStrategy Interface

```ts
interface CompactionStrategy {
  name: string

  compact(input: CompactionInput): Promise<CompactionOutput>
}

interface CompactionInput {
  messages: Message[]
  runtimeState: RuntimeStateSnapshot
  tokenBudget: number
  customInstructions?: string
  reason: 'auto' | 'manual' | 'reactive' | 'ptl_fallback'
}

interface CompactionOutput {
  summary: string
  tokensEstimate: number
  metadata?: {
    messagesCompacted: number
    messagesKept: number
    strategy: string
  }
}
```

## Observability

每次压缩需要记录：

- trigger reason
- pre_compact_tokens
- post_compact_tokens
- messages_compacted
- messages_kept
- summary_tokens
- strategy name
- retry count
- failure reason
- duration

## Manual Compaction

TitanX 应支持手动触发：

```text
/compact
```

手动压缩与自动压缩共享同一管线，但 trigger reason 为 `manual`，并允许用户附加压缩指令。

## Non-Goals

- 本期不实现跨 session 长期记忆
- 不实现用户偏好长期存储
- 不实现项目知识库构建
- 不实现 RAG 检索
- 不实现文件索引
- 不实现跨 session 的 summary 合并

## Constraints

- 必须兼容现有模型调用流程
- 不引入新的持久化存储组件
- 压缩机制不得修改 canonical system/developer instructions
- 压缩失败不得静默忽略
- Summary compaction 必须可插拔，不能绑定单一模型或单一供应商
- 压缩后必须保持任务连续性优先于极致 token 压缩率
