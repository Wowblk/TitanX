# 高性能 API 网关中间件文档

**版本**: 0.1.0  
**更新日期**: 2025年3月17日  
**仓库地址**: [github.com/DoraZa/mini-gateway](https://github.com/DoraZa/mini-gateway)

本项目是一个高性能 API 网关中间件，基于 Go 语言开发，专为微服务架构设计。它集成了动态路由、安全控制、流量治理、协议转换和可观测性功能。本文档主要聚焦于测试方案，详细说明如何验证网关的各项功能。

## 项目概述

本网关旨在提供以下核心功能：
- **动态路由**: 支持 Trie 树和正则表达式匹配，延迟 <1ms。
- **负载均衡**: 实现轮询、加权轮询和一致性哈希。
- **安全控制**: JWT 鉴权、RBAC、IP 黑白名单、防注入攻击。
- **流量治理**: 熔断、限流、流量染色和灰度发布。
- **协议转换**: 支持 HTTP ↔ gRPC 和 WebSocket 代理。
- **可观测性**: 集成 Prometheus 和 Jaeger 提供实时监控和分布式追踪。

## 安装与运行

1. **克隆仓库**
   ```bash
   git clone https://github.com/DoraZa/mini-gateway.git
   cd mini-gateway
   ```

2. **安装依赖**
   ```bash
   make deps
   ```

3. **编译并运行**
   ```bash
   make run
   ```
   默认监听地址为 `http://127.0.0.1:8380`。

4. **（可选）启动监控服务**
   ```bash
   make setup-monitoring
   ```
   启动 Redis、Prometheus、Grafana 等依赖服务。

## 测试方案

### 1. API 测试

#### 前提条件
- 服务已运行：`make run`
- 默认监听地址：`http://127.0.0.1:8380`
- 如果启用了认证（`cfg.Middleware.Auth` 为 `true`），需要先获取 JWT 或 RBAC token。

#### 环境准备
 - 启动GRPC测试服务
 - 启动HTTP测试服务
 - 启动WEBSOCKET测试服务
```bash
# 通过执行脚本，唤起三个服务
make manage-test-start 
```
 - 检查测试服务是否正常启动/运行
```bash
make manage-test-status
make manage-test-health
```
 - 停止测试服务
```bash
make manage-test-stop
```

---

#### 1.1 健康检查路由：`GET /health`
##### 测试命令
```bash
# 成功场景：检查服务是否正常运行
curl -X GET http://127.0.0.1:8380/health
```
**预期输出**：
```json
{"status": "ok"}
```

**说明**：简单的健康检查端点，返回服务状态。

---

#### 1.2 状态检查路由：`GET /status`
##### 测试命令
```bash
# 成功场景：获取网关状态
curl -X GET http://127.0.0.1:8380/status
```
**预期输出**（示例，可能因运行时数据不同而变化）：
```json
{
  "status": "ok",
  "gateway": {
    "uptime": "1h23m45s",
    "version": "0.1.0",
    "memory_alloc_bytes": 12345678,
    "goroutine_count": 10
  },
  "backend_stats": [...],
  "load_balancer": {
    "type": "weighted_round_robin",
    "active_targets": 3,
    "unhealthy_targets": []
  },
  "plugins": [...]
}
```

**说明**：返回网关运行状态、后端健康状况、负载均衡信息和插件状态。

---

#### 1.3 登录路由：`POST /login`
##### 测试命令
```bash
# 成功场景：使用正确凭据登录
curl -X POST http://127.0.0.1:8380/login \
-H "Content-Type: application/json" \
-d '{"username": "admin", "password": "password"}'
```
**预期输出**（取决于 `cfg.Security.AuthMode`）：
- 如果 `jwt`：
  ```json
  {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
  ```
- 如果 `rbac`：
  ```json
  {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "username": "admin"}
  ```
- 如果无认证模式：
  ```json
  {"message": "Login successful", "username": "admin"}
  ```

```bash
# 失败场景：使用错误凭据
curl -X POST http://127.0.0.1:8380/login \
-H "Content-Type: application/json" \
-d '{"username": "admin", "password": "wrong"}'
```
**预期输出**：
```json
{"error": "Invalid credentials"}
```

```bash
# 失败场景：无效请求体
curl -X POST http://127.0.0.1:8380/login \
-H "Content-Type: application/json" \
-d '{"username": "admin"}'
```
**预期输出**：
```json
{"error": "Invalid request"}
```

**说明**：测试用户登录，支持 JWT 或 RBAC 认证，需提供正确用户名和密码。

---

#### 1.4 Prometheus 监控路由：`GET /metrics`
##### 测试命令
```bash
# 成功场景：获取 Prometheus 指标（假设启用了 Prometheus）
curl -X GET http://127.0.0.1:8380/metrics
```
**预期输出**（部分示例）：
```
# HELP gateway_requests_total Total number of HTTP requests
# TYPE gateway_requests_total counter
gateway_requests_total{method="GET",path="/health",status="200"} 5
gateway_requests_total{method="POST",path="/login",status="200"} 2
...
```

**说明**：需要 `cfg.Observability.Prometheus.Enabled` 为 `true`，返回 Prometheus 格式的指标数据。

---

#### 1.5 路由管理 API
##### 1.5.1 添加路由：`POST /api/routes/add`
```bash
# 成功场景：添加新路由
curl -X POST http://127.0.0.1:8380/api/routes/add \
-H "Content-Type: application/json" \
-d '{"path": "/api/test", "rules": [{"target": "http://127.0.0.1:8380", "weight": 100, "protocol": "http"}]}'
```
**预期输出**：
```json
{"message": "Route added successfully"}
```

```bash
# 失败场景：路径已存在
curl -X POST http://127.0.0.1:8380/api/routes/add \
-H "Content-Type: application/json" \
-d '{"path": "/api/test", "rules": [{"target": "http://127.0.0.1:8380", "weight": 100, "protocol": "http"}]}'
```
**预期输出**：
```json
{"error": "Route already exists"}
```

```bash
# 失败场景：无效请求体
curl -X POST http://127.0.0.1:8380/api/routes/add \
-H "Content-Type: application/json" \
-d '{"path": "/api/test"}'
```
**预期输出**：
```json
{"error": "Invalid request payload"}
```

**说明**：添加新的路由规则，需提供路径和规则详情。

---

##### 1.5.2 更新路由：`PUT /api/routes/update`
```bash
# 成功场景：更新现有路由
curl -X PUT http://127.0.0.1:8380/api/routes/update \
-H "Content-Type: application/json" \
-d '{"path": "/api/test", "rules": [{"target": "http://127.0.0.1:8081", "weight": 50, "protocol": "http"}]}'
```
**预期输出**：
```json
{"message": "Route updated successfully"}
```

```bash
# 失败场景：路径不存在
curl -X PUT http://127.0.0.1:8380/api/routes/update \
-H "Content-Type: application/json" \
-d '{"path": "/api/nonexistent", "rules": [{"target": "http://127.0.0.1:8081", "weight": 50, "protocol": "http"}]}'
```
**预期输出**：
```json
{"error": "Route not found"}
```

```bash
# 失败场景：无效请求体
curl -X PUT http://127.0.0.1:8380/api/routes/update \
-H "Content-Type: application/json" \
-d '{"path": "/api/test"}'
```
**预期输出**：
```json
{"error": "Invalid request payload"}
```

**说明**：更新现有路由规则，需提供路径和新规则。

---

##### 1.5.3 删除路由：`DELETE /api/routes/delete`
```bash
# 成功场景：删除现有路由
curl -X DELETE http://127.0.0.1:8380/api/routes/delete \
-H "Content-Type: application/json" \
-d '{"path": "/api/test", "rules": [{"target": "http://127.0.0.1:8380", "weight": 100, "protocol": "http"}]}'
```
**预期输出**：
```json
{"message": "Route deleted successfully"}
```

```bash
# 失败场景：路径不存在
curl -X DELETE http://127.0.0.1:8380/api/routes/delete \
-H "Content-Type: application/json" \
-d '{"path": "/api/nonexistent", "rules": [{"target": "http://127.0.0.1:8380", "weight": 100, "protocol": "http"}]}'
```
**预期输出**：
```json
{"error": "Route not found"}
```

```bash
# 失败场景：无效请求体
curl -X DELETE http://127.0.0.1:8380/api/routes/delete \
-H "Content-Type: application/json" \
-d '{"path": ""}'
```
**预期输出**：
```json
{"error": "Invalid request payload"}
```

**说明**：删除指定路由，需提供路径和规则（尽管当前实现只使用路径）。

---

##### 1.5.4 列出所有路由：`GET /api/routes/list`
```bash
# 成功场景：获取所有路由
curl -X GET http://127.0.0.1:8380/api/routes/list
```
**预期输出**（示例）：
```json
{
  "routes": {
    "/api/test": [
      {"target": "http://127.0.0.1:8081", "weight": 50, "protocol": "http"}
    ],
    "/api/v1/user": [
      {"target": "http://127.0.0.1:8381", "weight": 80, "env": "stable", "protocol": "http", "healthCheckPath": "/status"}
    ]
  }
}
```

**说明**：返回当前所有路由规则的列表。

---

#### 1.6 保存配置 API：`POST /api/config/save`
##### 测试命令
```bash
# 成功场景：保存配置到文件
curl -X POST http://127.0.0.1:8380/api/config/save
```
**预期输出**：
```json
{"message": "Configuration saved successfully"}
```

```bash
# 失败场景：文件写入权限不足（需模拟，例如移除写权限）
# chmod -w ./config/config.yaml
curl -X POST http://127.0.0.1:8380/api/config/save
```
**预期输出**（假设权限不足）：
```json
{"error": "Failed to save configuration"}
```

**说明**：将当前配置保存到 `./config/config.yaml`，成功时返回确认消息。

---

#### 1.7 动态路由测试（基于配置）
##### 测试命令
假设配置中已有路由 `/api/v1/user`（见 `config.yaml`），目标为 `http://127.0.0.1:8381`：
```bash
# 测试动态路由转发
curl -X GET http://127.0.0.1:8380/api/v1/user
```
**预期行为**：请求被转发到 `http://127.0.0.1:8381`，返回后端服务响应。

**说明**：动态路由依赖 `cfg.Routing.Rules`，需确保后端服务运行。

---

#### 注意事项
1. **端口号**：如果修改了 `config.yaml` 中的 `server.port`，需相应调整 `curl` 命令中的端口（默认 `8380`）。
2. **认证**：若 `cfg.Middleware.Auth` 为 `true`，需在请求头中添加 `Authorization: Bearer <token>`，先通过 `/login` 获取 token。
   示例：
   ```bash
   TOKEN=$(curl -s -X POST http://127.0.0.1:8380/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}' | jq -r '.token')
   curl -X POST http://127.0.0.1:8380/api/routes/add -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"path": "/api/test", "rules": [{"target": "http://127.0.0.1:8380"}]}'
   ```
3. **后端服务**：测试动态路由时，确保目标服务（如 `http://127.0.0.1:8381`）已运行。

这些命令涵盖了所有路由的测试场景。如果需要更具体的测试用例（例如特定配置下的动态路由），请提供更多细节！

---

### 2. 功能模块测试

#### 2.1 限流（Traffic）
##### 测试命令
```bash
wrk -t10 -c100 -d5s http://127.0.0.1:8380/health
```
**预期行为**：根据配置中的 QPS 和 burst 参数限制请求速率。可以通过切换 `algorithm` 值（`token_bucket` 或 `leaky_bucket`）测试不同算法的效果。

**验证方式**：
- 检查日志或 Prometheus 指标，确认请求被限制在配置的 QPS 内。

---

#### 2.2 染色（Canary）
##### 测试方法
1. **手动测试**：
    - 不带 Header：
      ```bash
      curl http://127.0.0.1:8380/api/v1/user
      ```
        - **预期**：80% 概率路由到 `stable`，20% 到 `canary`。
    - 带 Header：
      ```bash
      curl -H "X-Env: canary" http://127.0.0.1:8380/api/v1/user
      ```
        - **预期**：100% 路由到 `canary`。

2. **压力测试**：
   ```bash
   wrk -t10 -c100 -d5s http://127.0.0.1:8380/api/v1/user
   ```
    - **验证**：检查日志，确认流量分配比例接近 80:20。

3. **Header 注入验证**：
    - 在下游服务打印接收到的 `X-Env` Header，确保 `canary` 请求带有正确标记。

4. **日志验证**：
    - 检查 `gateway.log`，确认 `env` 和 `target` 的记录是否正确。

---

#### 2.3 安全（Security）
##### 测试方法
1. **JWT 鉴权**：
    - 启用 JWT（`cfg.Security.AuthMode = "jwt"` 和 `cfg.Middleware.Auth = true`）：
      ```bash
      # 获取 token
      TOKEN=$(curl -s -X POST http://127.0.0.1:8380/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}' | jq -r '.token')
      # 带 token 访问受保护路由
      curl -X GET http://127.0.0.1:8380/api/v1/user -H "Authorization: Bearer $TOKEN"
      ```
        - **预期**：成功转发到后端服务。
    - 不带 token：
      ```bash
      curl -X GET http://127.0.0.1:8380/api/v1/user
      ```
        - **预期**：返回 `401 Unauthorized`。
    - **验证**：检查日志，确认鉴权耗时 <2ms。

2. **RBAC 权限控制**：
    - 启用 RBAC（`cfg.Security.AuthMode = "rbac"` 和 `cfg.Security.RBAC.Enabled = true`）：
      ```bash
      # 获取 RBAC token
      TOKEN=$(curl -s -X POST http://127.0.0.1:8380/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}' | jq -r '.token')
      # 测试权限受限路由
      curl -X GET http://127.0.0.1:8380/api/v1/user -H "Authorization: Bearer $TOKEN"
      ```
        - **预期**：根据 `rbac_policy.csv` 中的规则，允许或拒绝访问。
    - **验证**：检查日志，确保 RBAC 规则生效。

3. **IP 黑白名单**：
    - 配置黑名单（`cfg.Security.IPBlacklist = ["192.168.1.100"]`）：
      ```bash
      # 从黑名单 IP 模拟请求（需调整客户端 IP 或代理）
      curl -X GET http://127.0.0.1:8380/health --interface 192.168.1.100
      ```
        - **预期**：返回 `403 Forbidden`。
    - 配置白名单（`cfg.Security.IPWhitelist = ["127.0.0.1"]`）：
      ```bash
      curl -X GET http://127.0.0.1:8380/health
      ```
        - **预期**：仅允许白名单 IP 访问。
    - **验证**：检查日志，确认百万级 IP 匹配性能 <5ms。

4. **防注入攻击**：
    - 启用防注入（`cfg.Middleware.AntiInjection = true`）：
      ```bash
      curl -X GET "http://127.0.0.1:8380/api/v1/user?name=<script>alert(1)</script>"
      ```
        - **预期**：返回 `400 Bad Request`，拦截 XSS 攻击。
    - 测试 SQL 注入：
      ```bash
      curl -X GET "http://127.0.0.1:8380/api/v1/user?id=1%20OR%201=1"
      ```
        - **预期**：返回 `400 Bad Request`，拦截 SQL 注入。
    - **验证**：检查日志，确保 OWASP 规则生效。

---

#### 2.4 路由（Routing）
##### 测试方法
1. **动态路由匹配**：
    - 配置 Trie 路由（`cfg.Routing.Engine = "trie"`）：
      ```bash
      curl -X GET http://127.0.0.1:8380/api/v1/user
      ```
        - **预期**：转发到 `http://127.0.0.1:8381`，延迟 <1ms。
    - 配置正则路由（例如 `/api/v2/.*`）：
      ```bash
      curl -X GET http://127.0.0.1:8380/api/v2/test
      ```
        - **预期**：匹配成功并转发。

2. **路由管理**：
    - 添加路由（见 1.5.1）：
      ```bash
      curl -X POST http://127.0.0.1:8380/api/routes/add -H "Content-Type: application/json" -d '{"path": "/api/new", "rules": [{"target": "http://127.0.0.1:8380"}]}'
      ```
        - **预期**：新路由生效。
    - 更新路由（见 1.5.2）：
      ```bash
      curl -X PUT http://127.0.0.1:8380/api/routes/update -H "Content-Type: application/json" -d '{"path": "/api/new", "rules": [{"target": "http://127.0.0.1:8081"}]}'
      ```
        - **预期**：路由目标更新。
    - 删除路由（见 1.5.3）：
      ```bash
      curl -X DELETE http://127.0.0.1:8380/api/routes/delete -H "Content-Type: application/json" -d '{"path": "/api/new", "rules": [{"target": "http://127.0.0.1:8081"}]}'
      ```
        - **预期**：路由移除。

3. **协议支持**：
    - 测试 gRPC 路由（`/api/v2/hello/*path`）：
      ```bash
      wrk -t10 -c100 -d5s http://127.0.0.1:8380/grpc/api/v3/hello\?name\=xa
      ```
        - **预期**：转发到 `127.0.0.1:8391`，返回响应。
    - 测试 WebSocket 路由（`/ws/chat`）：
      ```bash
      ws://127.0.0.1:8380/websocket/ws/chat
      ```
        - **预期**：连接成功并转发到 `ws://127.0.0.1:8392`。

4. **验证**：
    - 检查日志，确认路由匹配和转发延迟 <1ms。

---

#### 2.5 可观测性（Observability）
##### 测试方法
1. **实时监控（Prometheus）**：
    - 启用 Prometheus（`cfg.Observability.Prometheus.Enabled = true`）：
      ```bash
      curl -X GET http://127.0.0.1:8380/metrics
      ```
        - **预期**：返回 QPS、延迟等指标。
    - 访问 Grafana（`http://127.0.0.1:8350`）：
        - **预期**：仪表盘展示秒级延迟的监控数据。

2. **分布式追踪（Jaeger）**：
    - 启用 Jaeger（`cfg.Observability.Jaeger.Enabled = true`）：
      ```bash
      curl -X GET http://127.0.0.1:8380/api/v1/user
      ```
        - **预期**：请求带 Trace ID。
    - 访问 Jaeger UI（`http://127.0.0.1:8330`）：
        - **预期**：显示全链路追踪，定位瓶颈。

3. **压力测试**：
   ```bash
   wrk -t10 -c100 -d5s http://127.0.0.1:8380/health
   ```
    - **验证**：Prometheus 指标更新，Jaeger 记录完整请求链。

4. **日志验证**：
    - 检查 `gateway.log`，确认 Trace ID 被正确记录。

---

#### 2.6 负载均衡（Loadbalancer）
##### 测试方法
1. **轮询（Round Robin）**：
    - 配置 `cfg.Routing.LoadBalancer = "round_robin"`：
      ```bash
      for i in {1..5}; do curl http://127.0.0.1:8380/api/v1/user; done
      ```
        - **预期**：请求均匀分布到多个目标（如 `8381` 和 `8383`）。

2. **加权轮询（Weighted Round Robin）**：
    - 配置 `cfg.Routing.LoadBalancer = "weighted_round_robin"`（权重 80:20）：
      ```bash
      wrk -t10 -c100 -d5s http://127.0.0.1:8380/api/v1/user
      ```
        - **预期**：流量按权重分配（约 80% 到 `8381`，20% 到 `8383`）。

3. **一致性哈希（Ketama）**：
    - 配置 `cfg.Routing.LoadBalancer = "ketama"`：
      ```bash
      curl -X GET "http://127.0.0.1:8380/api/v1/user?id=1"
      curl -X GET "http://127.0.0.1:8380/api/v1/user?id=1"
      ```
        - **预期**：相同参数始终路由到同一目标。

4. **服务发现（Consul）**：
    - 启用 Consul（`cfg.Consul.Enabled = true`）：
      ```bash
      make setup-consul
      curl http://127.0.0.1:8380/api/v1/user
      ```
        - **预期**：动态感知节点状态并转发。

5. **验证**：
    - 检查日志，确认负载均衡策略生效。
    - 查看 `/status` 输出，确认 `active_targets` 和 `unhealthy_targets`。

---

## 配置说明

配置文件位于 `config/config.yaml`，关键字段包括：
- `server.port`: 默认 `8380`。
- `routing.rules`: 定义路由规则。
- `security.authmode`: 认证模式（`jwt` 或 `rbac`）。
- `traffic.ratelimit`: 限流配置。
- `observability.prometheus`: 监控设置。

示例配置请参考 `config/config.yaml`。

## 开发与调试

- **运行测试**：`make test`
- **性能测试**：`make bench`
- **查看日志**：检查 `logs/gateway.log`。

如果需要扩展功能，可参考设计文档中的插件机制或新增路由规则。