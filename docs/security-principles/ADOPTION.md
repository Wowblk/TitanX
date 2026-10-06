# 安全原则落地清单

记录日期：2026-09-10。依据：[当前安全设计](../model-tool-loop-security-design.md)
及相关代码入口的定点核对。第一期操作绑定授权已实现，详见
[修复与验证记录](../model-tool-loop-operation-authorization.md)；没有进行完整安全审计。

“已有基础”表示发现相关实现，不表示满足该原则的全部条件；本清单当前没有把任何一项
标为全面完成。第一期的测试证据单独列出，其他验收场景仍是后续要求。

## 实现与缺口

| 原则 | 状态 | 代码入口与已有基础 | 下一步及验收要求 |
| --- | --- | --- | --- |
| TXS-01 宿主授权 | 进程内准入已实现 | [execution.py](../../titanx/policy/execution.py)、[runtime.py](../../titanx/runtime.py)：私有批准记录和执行前复验，公开 call ID 集合不再授予权限 | 持久化授权与宿主外部身份验证仍需扩展 |
| TXS-02 最小能力 | 部分覆盖 | [tool_runtime.py](../../titanx/sandbox/tool_runtime.py)、[router.py](../../titanx/sandbox/router.py)：默认沙箱接线及路径、隔离约束 | 统一动作与资源范围；注册且未要求审批的工具当前可获允许，不能宣称所有工具默认拒绝 |
| TXS-03 精确审批 | 第一阶段已实现 | [execution.py](../../titanx/policy/execution.py)：不可变 ToolIntent、私有 ApprovalGrant、有效期/撤销/消费、策略 epoch 与同事件循环准入；网关回复绑定 execution ID | 独立资源解析、下游资源版本检查和跨进程批准存储仍待实现 |
| TXS-04 身份隔离 | 部署能力待补齐 | [gateway](../../titanx/gateway/)：API key 及会话串行执行基础；[统一入口](../unified-entrypoint.md)使用宿主新 UUID 作为归档范围，不将客户端 selector 用作持久化访问授权 | 认证主体与会话、审批、归档的所有权绑定；不能仅凭 session ID 读取资源；本地入口不代表实现多租户隔离 |
| TXS-05 参数与契约 | 通用校验及契约快照已接入 | [execution.py](../../titanx/policy/execution.py)：JSON Schema、有界 JSON、不可变契约和漂移拒绝；[admission.py](../../titanx/mcp/admission.py)：MCP allowlist/pin | schema 不代替业务资源授权；工具代码来源与依赖准入、复杂 schema 的执行时间隔离仍需部署控制 |
| TXS-06 执行隔离 | 默认工厂已有基础 | [factory.py](../../titanx/factory.py)、[router.py](../../titanx/sandbox/router.py)：沙箱接入、最低隔离要求 | 按工具核验文件、网络、凭证限制；自定义 ToolRuntime 的实际隔离单独验证 |
| TXS-07 上下文边界 | 已有数据管理基础 | [context](../../titanx/context/)、[runtime.py](../../titanx/runtime.py)：任务状态、摘要、归档回查及结果安全处理；[application.py](../../titanx/application.py)为统一入口默认接入这些能力 | 补充来源传播及授权独立性契约验证；不能从摘要重建批准；模拟摘要不证明语义保真度 |
| TXS-08 凭证与出口 | 可选接入，非全面强制 | [egress.py](../../titanx/safety/egress.py)：宿主显式接入的出口检查接口 | 核验实际网络路径，建立按主体/工具的凭证范围；读取授权不能覆盖任意外发 |
| TXS-09 安全恢复 | 新增授权复验与重叠运行保护 | [runtime.py](../../titanx/runtime.py)、[execution.py](../../titanx/policy/execution.py)：批准失效后重新判定、单次准入和批次游标；[统一入口](../unified-entrypoint.md)区分进程内连续会话与持久化证据 | `unknown`、副作用分类、下游幂等或结果核对；[内层重试](../../titanx/resilience/resilient_backend.py)仍需改造；上下文归档不等于跨进程执行恢复 |
| TXS-10 消耗与停止 | 分散存在相关限制 | [types.py](../../titanx/types.py)、[admission.py](../../titanx/mcp/admission.py)、[circuit_breaker.py](../../titanx/resilience/circuit_breaker.py)：轮数、MCP 边界和熔断；[统一入口](../unified-entrypoint.md)共用上下文预算与回查限制，按应用生命周期关闭 SQLite | 统一工具量、总时长、成本与恢复预算；明确取消后的外部结果 |
| TXS-11 可靠审计 | 新增操作关联字段 | [audit_log.py](../../titanx/policy/audit_log.py)、[runtime.py](../../titanx/runtime.py)：集中日志，决策/调用关联执行 ID、批次、策略版本及批准状态 | 执行前持久化确认、完整身份归因与按需完整性保护；append 返回不等于落盘成功 |
| TXS-12 委派权限 | 扩展时实施 | 当前设计不声称提供完整跨 Agent 授权 | 接入委派前落实身份、范围、期限与重复提交控制；子任务不自动继承全权 |

## 实施顺序

| 阶段 | 交付 | 相关原则 |
| --- | --- | --- |
| P0（进程内阶段已实现） | 不可变操作描述、私有批准台账、参数/契约校验、策略版本与执行前同步复验 | TXS-01、03、05 |
| P1 | 工具资源描述、实际执行能力核验、出口与凭证范围、副作用分类及消耗限制 | TXS-02、06、08、09、10 |
| P2 | 认证主体隔离、执行账本、可靠审计与跨进程恢复 | TXS-04、07、09、11 |
| 引入委派前 | 跨 Agent 身份、权限范围及消息协议 | TXS-12 |

阶段表示工程依赖，不表示风险轻重。若即将上线多租户服务，TXS-04 的身份隔离必须
提前作为上线条件；TXS-07 的数据与权限分离贯穿所有阶段。

## 更新与证据

第一期使用 [授权回归测试](../../tests/test_execution_authorization.py)、
[网关测试](../../tests/test_gateway_chat.py)和既有运行时/策略/上下文测试验证。
最新命令、结果和剩余限制见[交付记录](../model-tool-loop-operation-authorization.md)。

2026-09-15 的[统一入口接入记录](../unified-entrypoint.md)补充 TXS-04、07、09、10 的
配置、资源生命周期和会话边界。相关验证入口为
[test_application.py](../../tests/test_application.py)；与上下文、网关及生命周期回归一起
共 103 项通过，另完成终端与真实本机网页验证，完整命令及范围见接入记录。
离线上下文校验已完成：原工具执行 1 次，完成 3 次符合目标预算的摘要提交，原文仍可
检索；具体数值见接入记录。该结果不验证真实模型摘要质量或实际沙箱后端。

使用本地确定性替身验证状态、权限和资源边界；记录测试名称、运行命令、结果及适用配置。
真实后端限制还需要对应环境的验证，不能用替身结果代替实际隔离能力。
未执行的验证、跳过项与已知缺口明确保留。

每次完成相关修复时，可在问题 MD 中使用以下条目，并同步上表：

```text
关联原则：TXS-xx
问题与触发条件：
保护对象和信任边界：
修复前行为：
修复后行为及执行位置：
正常、拒绝、暂停/恢复等必要场景的验证：
实际后端/配置与测试结果：
剩余限制：
```

详细目标流程和审批状态图见[工具循环安全设计](../model-tool-loop-security-design.md)。
