#!/bin/bash

# 定义变量
GRAFANA_PROVISIONING_DIR="test/docker/grafana/provisioning"
DASHBOARD_SOURCE="test/docker/prometheus.dashboard.json"
DASHBOARD_DEST="test/docker/grafana/dashboards/gateway.json"

# 检查依赖工具
command -v jq >/dev/null 2>&1 || { echo "需要安装 jq 来处理 JSON"; exit 1; }

# 创建必要的目录
mkdir -p test/docker/grafana/dashboards grafana/dashboards "$GRAFANA_PROVISIONING_DIR/datasources" "$GRAFANA_PROVISIONING_DIR/dashboards" "test/grafana/dashboards"

# 配置数据源
cat <<EOF > "$GRAFANA_PROVISIONING_DIR/datasources/datasource.yml"
apiVersion: 1
datasources:
  - name: mini-gateway-Prometheus
    type: prometheus
    url: http://127.0.0.1:8390
    access: proxy
    isDefault: true
    editable: false
EOF

# 配置 Dashboard 提供者
cat <<EOF > "$GRAFANA_PROVISIONING_DIR/dashboards/dashboards.yml"
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
EOF

# 检查并复制 Dashboard 文件
if [ -f "$DASHBOARD_SOURCE" ]; then
    cp "$DASHBOARD_SOURCE" "$DASHBOARD_DEST"
    echo "Dashboard 从 $DASHBOARD_SOURCE 复制到 $DASHBOARD_DEST"
else
    echo "错误：$DASHBOARD_SOURCE 不存在"
    exit 1
fi

# 创建 preferences 文件，指定首页
cat <<EOF > "$GRAFANA_PROVISIONING_DIR/preferences.yml"
apiVersion: 1
preferences:
  homeDashboardUID: "gateway-monitoring"
EOF

echo "Grafana 数据源、Dashboard 和首页配置已生成"