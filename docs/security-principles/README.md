# TitanX 安全原则

基线日期：2026-09-10。适用项目：TitanX Python SDK。

这里保存团队后续设计、实现和审查时使用的安全原则。以 OWASP Agentic Top 10 2026
为主要风险参考，LLM Top 10 2026 为补充；具体工程要求由 TitanX 的执行边界决定。
官方资料的版本和核验范围见[资料索引](references/README.md)。

**原则已作为项目设计基线记录；控制是否实现，以落地清单中的代码和验证证据为准。**
采用这些资料不代表通过 OWASP 认证，也不代表已经覆盖全部风险。

## 目录

| 文件 | 用途 |
| --- | --- |
| [PRINCIPLES.md](PRINCIPLES.md) | 12 条项目原则，使用稳定编号 `TXS-01` 至 `TXS-12` |
| [ADOPTION.md](ADOPTION.md) | 当前基础、待补内容、实现顺序及验收要求 |
| [references/README.md](references/README.md) | OWASP 官方入口、版本日期、核验状态与来源说明 |
| [Model-Tool Loop 安全设计](../model-tool-loop-security-design.md) | 具体设计、目标流程图、审批和执行状态图 |
| [操作绑定审批修复](../model-tool-loop-operation-authorization.md) | 第一期实现、触发条件、修复前后图及协议迁移 |

## 如何使用

1. 修改模型循环、工具、策略、上下文、网关或沙箱时，先选择相关的 `TXS` 原则。
2. 在问题文档或设计中说明触发条件、保护对象、实际执行边界与预期行为。
3. 实现后更新落地清单，附代码入口和必要的验证结果；部分能力不能标记为全面完成。
4. 新增工具时同时说明参数契约、资源范围、身份来源、执行限制和副作用类别。
5. 不适用的要求记录原因；兼容性导致暂未满足的要求记录缺口及后续工作。

这些原则约束 TitanX 产品运行时的权限与行为。常规仓库编辑、阅读和测试继续遵循
当前开发任务的授权，不因文档中的产品审批设计增加一轮人工确认。

## 与现有文档的关系

- [SECURITY.md](../../SECURITY.md)：现有信任模型、支持范围与部署前提。
- [工具循环安全设计](../model-tool-loop-security-design.md)：落实原则的目标方案。
- [上下文机制](../context-management.md)：TaskState、摘要、归档和回查。
- [上下文压缩问题](../context-compaction.md)：压缩相关问题与修复记录。
- [审批期间新输入准入](../runtime-prompt-admission.md)：运行状态与输入边界。
- [熔断恢复问题](../circuit-breaker-routing-recovery.md)：可用性恢复及受控探测。

原则目录负责长期约束；问题文档记录具体触发与修复；设计文档描述接口和状态迁移。
后续官方版本更新时，核对差异并更新资料索引，保留旧版本的明确年份。
