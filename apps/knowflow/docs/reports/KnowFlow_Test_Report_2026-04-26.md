# KnowFlow + Mini-Gateway 本地测试报告

测试时间：2026-04-26 01:18-01:27  
测试环境：本机 macOS，MySQL `127.0.0.1:3307`，Redis `127.0.0.1:6379`  
服务端口：前端 `5173`，Spring Boot 后端 `8080`，Mini-Gateway `8380`，TitanX Agent 网关 `3000`

## 1. 构建与单元测试

| 模块 | 命令 | 结果 |
| --- | --- | --- |
| KnowFlow 后端 | `mvn package` | 通过，4 tests，0 failures，0 errors |
| KnowFlow 前端 | `npm run build` | 通过，TypeScript + Vite 构建成功 |
| Mini-Gateway | `go test ./...` | 未完全通过，存在测试代码与当前接口不兼容/测试初始化崩溃 |

Mini-Gateway 失败点：

| 包 | 问题 |
| --- | --- |
| `internal/core/routing/proxy` | 测试调用 `GetLoadBalancerActiveTargets`，但当前 `HTTPProxy` 无该方法 |
| `internal/core/routing/router` | 测试仍按旧签名调用 `Match/Search(path)`，当前实现需要 `context.Context` |
| `internal/core/traffic` | `breaker_test` 初始化配置时触发 nil pointer panic |

已通过的 Mini-Gateway 包包括：`internal/core/loadbalancer`、`internal/core/security`、`pkg/util` 等。

## 2. 功能连通性

| 测试项 | 地址 | 结果 |
| --- | --- | --- |
| 后端 Feed | `GET http://127.0.0.1:8080/api/v1/knowposts/feed?page=1&size=20` | 200 |
| 网关转发 Feed | `GET http://127.0.0.1:8380/api/v1/knowposts/feed?page=1&size=20` | 200 |
| Mini-Gateway 健康检查 | `GET http://127.0.0.1:8380/health` | 200 |
| Mini-Gateway 指标 | `GET http://127.0.0.1:8380/metrics` | 可用 |
| TitanX Agent 网关 | `GET http://127.0.0.1:3000/health` | 404，该服务无 `/health` 路由 |

Mini-Gateway 当前配置中，HTTP 路由 `/api/v1/*path` 转发到 `http://127.0.0.1:8080`。gRPC 示例服务 `8391` 和 WebSocket 示例服务 `8392` 当前未启动，因此健康检查日志中这两类 target 失败；这不影响 KnowFlow HTTP 转发链路。

## 3. wrk 压测结果

测试接口：`GET /api/v1/knowposts/feed?page=1&size=20`

### 3.1 后端直连

| 并发 | 时长 | 请求数 | RPS | P50 | P95 | P99 | 错误 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 20 | 15s | 100,958 | 6,685.09 | 2.32ms | 30.74ms | 103.21ms | 0 |
| 50 | 15s | 81,980 | 5,365.35 | 6.96ms | 116.57ms | 761.40ms | 0 |
| 100 | 15s | 167,121 | 11,003.07 | 7.15ms | 87.30ms | 549.02ms | 0 |

补充受控脚本结果：

| 并发 | 请求数 | RPS | 成功率 | P50 | P95 | P99 | Max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20 | 2,000 | 5,797.75 | 100.00% | 2.41ms | 7.06ms | 16.19ms | 73.30ms |

### 3.2 Mini-Gateway 转发链路

当前 Mini-Gateway 配置：

- 全局限流：`qps=100`，`burst=300`
- 路由限流：`/api/v1/*path qps=800`，`burst=2000`
- 算法：`leaky_bucket`

wrk 会尽可能打满请求，因此会迅速超过限流阈值。以下结果包含大量 429，代表限流保护生效，不应作为业务成功吞吐解释。

| 并发 | 时长 | 请求数 | RPS | P50 | P95 | P99 | 非 2xx/3xx |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 15s | 8,227 | 547.57 | 3.42ms | 12.57ms | 51.59ms | 8,214 |
| 20 | 15s | 112,899 | 7,494.79 | 1.01ms | 27.50ms | 65.70ms | 112,097 |
| 50 | 15s | 197,334 | 13,072.41 | 3.38ms | 12.18ms | 63.12ms | 196,937 |
| 100 | 15s | 411,418 | 27,317.96 | 3.45ms | 12.03ms | 68.08ms | 410,914 |

受控速率测试将流量压在限流阈值以内：

| 场景 | 并发 | 请求数 | RPS | 成功率 | P50 | P95 | P99 | Max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gateway under limit | 2 | 1,000 | 45.68 | 100.00% | 2.10ms | 5.19ms | 15.99ms | 60.78ms |

### 3.3 前端 Vite Dev Server

| 地址 | 并发 | 时长 | 请求数 | RPS | P50 | P95 | P99 | 错误 |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `http://127.0.0.1:5173/` | 100 | 10s | 48,349 | 4,827.61 | 18.93ms | 38.15ms | 267.62ms | 0 |

注意：这是 Vite 开发服务器，不代表生产静态资源服务性能。

## 4. JMeter 结果

JMX 文件：`/Users/wowblk/dev/jmeter_feed_test.jmx`

| 目标 | 线程 | 循环 | 请求数 | 吞吐 | 平均 | P95 | P99 | Max | 错误率 | 状态码 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 后端直连 `8080` | 20 | 50 | 1,000 | 496.0/s | 2.11ms | 5ms | 13ms | 44ms | 0.00% | 200: 1000 |
| 网关 `8380` | 2 | 100 | 200 | 256.1/s | 2.69ms | 5ms | 9ms | 44ms | 8.50% | 200: 183, 429: 17 |

JMeter 再次验证：Mini-Gateway 当前全局限流配置会在突发流量超过阈值时返回 429。

## 5. 结论

1. KnowFlow 后端和前端构建测试通过；新增草稿功能未破坏现有测试。
2. 后端 Feed 直连在本地环境下可稳定承受高并发读，wrk 并发 100 下 RPS 约 11,003，错误为 0。
3. Mini-Gateway HTTP 转发链路功能正常，`/api/v1/*path` 能正确转发到 Spring Boot 后端。
4. Mini-Gateway 当前限流配置非常明显地生效：高并发压测时大量请求被 429 快速拒绝，这是保护后端的行为，不是后端失败。
5. 在限流阈值以内，Mini-Gateway 转发成功率 100%，P95 约 5.19ms，P99 约 15.99ms。
6. Mini-Gateway 单测存在测试代码滞后于实现的问题，需要单独修复测试签名和 breaker 初始化。
7. gRPC/WebSocket 示例 target 当前未启动，健康检查失败属于环境缺失；如果要测试多协议能力，需要先启动 `bin/grpc_services` 和 `bin/websocket_services`。

## 6. 建议

1. 若要测“纯网关转发极限吞吐”，建议临时关闭 `middleware.ratelimit` 或提高 `traffic.ratelimit.qps` 后单独开一轮测试。
2. 若要测“业务生产配置”，保留限流，并用 JMeter/受控脚本按目标 QPS 阶梯压测，例如 50/100/200/500 QPS。
3. 修复 Mini-Gateway 的过期单测，否则简历中“自研网关”项目如果被问到测试稳定性，会有可解释但不漂亮的缺口。
4. 前端性能建议使用生产构建后由 Nginx 或网关静态服务承载再测，Vite dev server 指标只用于开发态参考。
