#!/bin/bash

# 定义变量
DOCKER_COMPOSE_FILE="test/docker/docker-compose.yml"
GRAFANA_URL="http://127.0.0.1:8350"

# 检查依赖工具
command -v docker-compose >/dev/null 2>&1 || { echo "需要安装 docker-compose"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "需要安装 curl"; exit 1; }

# 调用 Grafana 配置脚本
echo "设置 Grafana 配置..."
./test/docker/setup_grafana.sh || { echo "Grafana 配置失败"; exit 1; }

# 启动 Docker Compose
echo "启动 Docker Compose 服务..."
docker-compose -f "$DOCKER_COMPOSE_FILE" up -d

# 等待服务启动并验证
echo "等待 Grafana 启动并加载配置..."
sleep 10  # 增加等待时间，确保 Grafana 完全启动并加载配置
curl -s "$GRAFANA_URL/api/health" >/dev/null || { echo "Grafana 未启动"; exit 1; }
curl -s "$GRAFANA_URL/api/datasources" -u admin:admin123 | grep -q "mini-gateway-Prometheus" && echo "数据源已加载" || echo "数据源加载失败"
curl -s "$GRAFANA_URL/api/dashboards/uid/gateway-monitoring" -u admin:admin123 | grep -q "gateway-monitoring" && echo "Dashboard 已加载" || echo "Dashboard 加载失败"

echo "监控服务初始化完成，请访问 $GRAFANA_URL 查看 Dashboard，测试帐号密码为 admin/admin123"