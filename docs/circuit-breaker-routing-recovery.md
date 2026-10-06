# 沙箱熔断后无法通过正常路由恢复：问题与修复记录

记录日期：2026-09-05。对象：当前 Python 主项目 `TitanX/`。

## 问题结论与影响范围

在 `ResilientSandboxBackend` 已进入 `open` 的前提下，旧实现的
`is_available()` 无条件返回 `False`。`SandboxRouter.select()` 因而跳过该
后端，而冷却到期检查和 `open → half-open` 转换只能由实际执行进入
`CircuitBreaker.call()` 后触发。

如果此实例之后只通过正常路由接收调用，即使底层后端已经恢复、冷却时间
已经过去，也无法自动恢复。时间流逝本身不会修改状态。

没有合格备用后端时，工具分发持续报错；有合格备用后端时，请求可能持续
转移到备用后端，掩盖原后端无法回归的问题。这里的“无法恢复”是上述调用
路径下的行为：直接调用同一包装实例并完成恢复探测、重建实例等外部动作，
仍可能使其恢复。没有后台定时健康检查参与本问题。

## 完整触发条件

以下条件需要同时成立：

1. 使用长期存活的 `ResilientSandboxBackend` 实例，并将它注册到路由器。
   工厂默认只有设置 `resilient_options` 才包装自动创建的后端；如果调用方
   自己传入 `backends`，需要自行包装。不能把所有默认沙箱调用都算作受影响。
2. 被包装操作抛出的异常到达 `CircuitBreaker.call()`，并在统计窗口内累计
   达到 `failure_threshold`，令状态变成 `open`。包装顺序是
   `CircuitBreaker.call(with_retry(backend.execute))`，所以一次操作内部
   重试耗尽后才计为一次熔断失败，不是每次内部重试都单独计数。
3. 此后仍经 `SandboxRouter.select()` 选择同一实例，没有通过其他直接调用
   推进该熔断器的恢复状态。
4. 即使底层后端重新可用、冷却到期，旧可用性检查仍在底层健康检查之前
   返回 `False`，使恢复入口不可达。

默认参数是失败阈值 5、窗口 60 秒、冷却 60 秒、恢复成功阈值 2、最多尝试
3 次。复现中改用失败阈值 1、最多尝试 1 次，以排除重试等待和累计次数干扰。

**异常与退出码的区别：** 当前 Docker/E2B 的不少执行异常会被转换成
`SandboxExecutionResult(exit_code != 0)`。熔断器只根据抛出的异常记录失败，
不会自动把非零退出码算成异常。因此，不能声称任意 Docker/E2B 故障都会
触发这个问题。本次模拟后端明确抛出 `RuntimeError`，验证的是满足上述
条件后的路由与状态机缺陷，不是真实 Docker/E2B 故障实验。

## 旧代码的调用链与根因

```text
SandboxedToolRuntime.execute()
  → SandboxRouter.select()
    → ResilientSandboxBackend.is_available()
      → breaker.get_state() == "open"
      → False
    → 跳过此后端

因此无法到达：
selection.backend.execute()
  → CircuitBreaker.call()
    → _acquire_slot()
      → 检查冷却时间
      → open → half-open，并占用唯一探测名额
```

旧检查只读当前状态，没有区分“冷却尚未结束”和“冷却已结束、可以尝试”。
问题由路由器和熔断器组合产生；单独直接调用熔断器的恢复测试不能覆盖它。

涉及文件：

- `titanx/resilience/resilient_backend.py`：包装后端的可用性入口。
- `titanx/resilience/circuit_breaker.py`：冷却、探测准入和状态转换。
- `titanx/sandbox/router.py`：先检查可用性，再返回后端。
- `titanx/sandbox/tool_runtime.py`：先选路，再实际执行。

## 首次最小复现：实际执行过程

首次交互中运行了内存里的 Python 脚本，没有修改生产代码。底层后端模拟，
包装层、路由器和熔断器均为仓库真实实现。

配置：`failure_threshold=1`、`success_threshold=1`、`cooldown_ms=0`、
`max_attempts=1`。冷却为零是为了立即满足冷却条件，不是等待真实时间。

| 步骤 | 操作 | 旧实现实际结果 |
| --- | --- | --- |
| 1 | 包装后端执行一次，模拟底层抛出异常 | `closed → open` |
| 2 | 让底层 `execute()` 恢复成功，并保持健康检查为真 | 熔断器仍是 `open` |
| 3 | 调用包装层 `is_available()` | 返回 `False` |
| 4 | 经路由选择，要求至少 Docker 隔离 | 路由失败：`docker: is_available=False` |
| 5 | 绕过路由，直接调用同一包装实例的 `execute()` | 执行成功，状态变为 `closed` |

首次观察到的输出：

```text
RECOVERY_THROUGH_ROUTER: No sandbox backend is available for the requested execution profile (min_isolation='docker'; rejected: docker: is_available=False; e2b: backend not registered)
RECOVERY_BY_DIRECT_EXECUTE: closed
```

步骤 5 是定位根因的对照实验，不是业务端应采用的修复方案。

## 可重复运行的回归复现

复现现已保存为 `tests/test_resilient_backend_recovery.py`。主回归测试从真实的
`SandboxedToolRuntime.execute()` 进入，因此包含完整的工具分发、路由、
包装后端和熔断器链路。运行：

```bash
cd /Users/wowblk/TitanX/TitanX
.venv/bin/python -m pytest -q tests/test_resilient_backend_recovery.py::test_tool_dispatch_recovers_after_cooldown --tb=short
```

这个测试的完整过程：

1. 时钟从 100 秒开始，冷却设为 60 秒，失败阈值 1，恢复成功阈值 2。
2. 通过工具分发执行，模拟后端抛出一次 `RuntimeError`，断言状态为 `open`。
3. 恢复模拟后端，将熔断器所用单调时钟推进 60 秒，精确到冷却边界。
4. 再通过相同工具分发执行；预期第一轮恢复探测成功，状态为 `half-open`。
5. 再执行一次，预期达到成功阈值，状态变为 `closed`。
6. 断言底层只执行了 3 次：初始失败、第一次探测、第二次探测；状态事件
   依次为 `closed → open → half-open → closed`。

测试只替换 `circuit_breaker` 模块引用的时钟，不修改 `asyncio` 的真实计时。
无需 Docker、E2B、网络、模型密钥或实际等待 60 秒。

修改生产代码前，新测试文件实际结果为 **7 failed, 1 passed**。主回归在
第 4 步失败，错误就是上面的 `docker: is_available=False`。其余失败包括
被这条不可达路径阻断的后续恢复场景，不代表发现了 7 个独立缺陷。

## 修复方案

### 1. 增加无副作用的准入查询

在 `CircuitBreaker` 中增加 `can_attempt_call()`：

| 状态 | 查询结果 |
| --- | --- |
| `closed` | 允许尝试 |
| `open`，冷却未到 | 不允许 |
| `open`，冷却已到 | 允许尝试 |
| `half-open`，探测名额已占用 | 不允许 |
| `half-open`，没有进行中的探测 | 允许尝试 |

查询不改变状态、不占用探测名额、不触发状态事件。调用方可能只选择后端
却没有执行，不能让一次可用性查询消耗掉唯一名额。

### 2. 包装层组合准入状态与底层健康状态

`ResilientSandboxBackend.is_available()` 先查询准入，再调用底层健康检查，
最后重新查询准入。第二次检查处理 `await` 底层健康检查期间其他请求触发
熔断或占用探测名额的情况。

冷却到期只代表可以尝试，底层仍报告不可用时继续拒绝。原有路由排序、
能力要求和最低隔离要求不变。

### 3. 执行入口继续负责唯一探测

最终是否执行仍由 `CircuitBreaker.call()` 的 `_acquire_slot()` 加锁决定。
多个请求可能同时通过可用性查询，但同一时刻只允许一个半开恢复调用
进入底层。已经选好后端但输掉名额竞争的请求仍收到 `CircuitOpenError`。

成功达到阈值才关闭熔断器；恢复探测再次失败则重新打开，并重新计算冷却。
可用性查询不是执行名额预订，也不是执行必定成功的承诺。恢复由后续请求
驱动：冷却结束但没有新请求时，状态可以保持 `open`。

### 4. 同时补齐恢复探测的取消清理

恢复路径打通后，必须处理已发现的相邻缺陷：旧 `call()` 只捕获
`Exception`，`asyncio.CancelledError` 会跳过名额释放，令状态卡在
`half-open`，后续探测无法开始。

增加取消分支：释放本次探测名额，继续抛出取消；取消不计为服务成功或
服务失败，保留当前半开状态和已有成功计数，后续请求可再次争取探测名额。
这解决的是名额泄漏，不保证底层外部副作用被撤销，也不改变重试策略。

## 验证清单与结果

状态：已修复，2026-09-05 在当前本地工作区完成验证。

实现与测试迭代的实测结果：

| 阶段 | 实测结果 | 含义 |
| --- | --- | --- |
| 生产代码未修改，新增最初的 8 个测试 | 7 failed, 1 passed | 正常工具恢复无法通过路由；冷却前拒绝仍正确 |
| 仅修复准入查询与包装层 | 1 failed, 7 passed | 主恢复路径已通过；剩余为探测取消后的名额泄漏 |
| 增加取消清理，并把取消测试扩展为两种成功计数场景 | 新增 9 个回归均通过 | 验证取消不增加、也不清零已有成功次数 |
| 新回归与已有相关测试一起运行 | **50 passed in 0.66s** | 覆盖恢复、重试、路由、隔离要求、运行时生命周期和取消协议 |

完整验证命令：

```bash
cd /Users/wowblk/TitanX/TitanX
.venv/bin/python -m pytest -q tests/test_resilient_backend_recovery.py tests/test_retry.py tests/test_sandbox_router.py tests/test_sandbox_isolation_floor.py tests/test_runtime_lifecycle.py tests/test_runtime_cancellation_protocol.py --tb=short
.venv/bin/python -m compileall -q titanx demo.py run_gateway.py
.venv/bin/python demo.py
git diff --check
```

编译检查通过；示例输出为 `Final response: Echo: Hello, TitanX!`；补丁空白
检查通过。50 项是本次相关测试集合，不是全仓库测试数量。示例使用仓库的
Echo 模型适配器，不能作为真实模型或真实 Docker/E2B 集成测试的证据。

新回归用例明细（同属 `tests/test_resilient_backend_recovery.py`）：

| 用例 | 验证内容 |
| --- | --- |
| `test_tool_dispatch_recovers_after_cooldown` | 精确冷却边界后，经真实工具分发与路由恢复，成功两次才关闭 |
| `test_no_probe_before_cooldown_expires` | 冷却前路由和直接执行均拒绝，底层没有额外执行或健康查询 |
| `test_selection_does_not_claim_probe_or_emit_transitions` | 重复健康查询和仅选路不会占名额、改变状态或发布转换事件 |
| `test_underlying_availability_is_still_required` | 冷却到期但底层仍不可用时拒绝，恢复底层后可以再探测 |
| `test_failed_recovery_probe_restarts_cooldown` | 探测再次失败重新打开，新的冷却窗口结束后再允许尝试 |
| `test_preselected_concurrent_callers_share_one_probe` | 10 个请求先同时选路，只有 1 个进入底层；进行中的探测阻止新路由请求 |
| `test_cancelled_probe_releases_slot_without_counting_success[0]` | 首个恢复探测被取消后释放名额，仍需两次成功才能关闭 |
| `test_cancelled_probe_releases_slot_without_counting_success[1]` | 已成功一次后取消下个探测，保留成功计数，再成功一次即可关闭 |
| `test_recheck_admission_after_awaiting_backend_health` | 底层健康检查挂起期间被其他调用触发熔断，返回前重新判断准入 |

修复后的主回归结果：初始失败一次，推进模拟时钟 60 秒，正常工具分发
成功两次，底层执行总数为 3，转换事件为：

```text
closed → open → half-open → closed
```

生产逻辑只修改了 `circuit_breaker.py` 和 `resilient_backend.py`；路由器与
工具执行器无需修改。发布说明已补入 `CHANGELOG.md` 的 Unreleased / Fixed。

## 本记录的边界

本次修复针对路由无法触达熔断恢复入口，以及同一恢复路径的取消名额泄漏。
不修改先前审查中发现的待审批时插入新 prompt、旧压缩摘要累积等独立问题。
没有改变“哪些返回值应算作熔断失败”、操作重试的幂等性或后台健康检查策略。
