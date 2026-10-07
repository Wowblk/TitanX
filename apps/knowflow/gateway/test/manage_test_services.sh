#!/bin/bash

# manage_test_services.sh
# 用于管理 mini-gateway 测试服务的启动、停止、状态检测和健康检查

# 定义服务文件路径
HTTP_SERVICE="test/service/http/http_services.go"
WEBSOCKET_SERVICE="test/service/websocket/websocket_services.go"
GRPC_SERVICE="test/service/grpc/grpc_services.go"

# 定义输出二进制文件路径
BIN_DIR="bin"
HTTP_BIN="$BIN_DIR/http_services"
WEBSOCKET_BIN="$BIN_DIR/websocket_services"
GRPC_BIN="$BIN_DIR/grpc_services"

# 日志文件
LOG_DIR="logs"
HTTP_LOG="$LOG_DIR/http_services.log"
WEBSOCKET_LOG="$LOG_DIR/websocket_services.log"
GRPC_LOG="$LOG_DIR/grpc_services.log"

# PID目录
PID_DIR=".pids"

# 确保日志、PID和二进制文件目录存在
mkdir -p "$LOG_DIR"
mkdir -p "$PID_DIR"
mkdir -p "$BIN_DIR"

# 检测系统是否支持 setsid 命令
if command -v setsid >/dev/null 2>&1; then
    USE_SETSID=1
else
    USE_SETSID=0
fi

# 当没有 setsid 时，定义递归杀死进程树的函数
kill_tree() {
    local _pid=$1
    # 递归查找并杀死子进程
    for _child in $(pgrep -P "$_pid"); do
        kill_tree "$_child"
    done
    kill -TERM "$_pid" 2>/dev/null
}

# 编译并启动服务
start_services() {
    echo "Starting all test services..."

    # 编译 HTTP 服务
    if [ -f "$HTTP_SERVICE" ]; then
        go build -o "$HTTP_BIN" "$HTTP_SERVICE"
        if [ $? -ne 0 ]; then
            echo "Failed to compile HTTP Service"
            exit 1
        fi
    else
        echo "HTTP Service source file not found"
        exit 1
    fi

    # 启动 HTTP 服务前判断是否已启动
    if [ -f "$PID_DIR/http.pid" ] && kill -0 "$(cat "$PID_DIR/http.pid")" 2>/dev/null; then
        echo "HTTP Service already running, skipping..."
    else
        if [ $USE_SETSID -eq 1 ]; then
            setsid "$HTTP_BIN" > "$HTTP_LOG" 2>&1 &
        else
            "$HTTP_BIN" > "$HTTP_LOG" 2>&1 &
        fi
        HTTP_PID=$!
        echo "$HTTP_PID" > "$PID_DIR/http.pid"
        echo "HTTP Service started with PID $HTTP_PID"
    fi

    # 编译 WebSocket 服务
    if [ -f "$WEBSOCKET_SERVICE" ]; then
        go build -o "$WEBSOCKET_BIN" "$WEBSOCKET_SERVICE"
        if [ $? -ne 0 ]; then
            echo "Failed to compile WebSocket Service"
            exit 1
        fi
    else
        echo "WebSocket Service source file not found"
        exit 1
    fi

    # 启动 WebSocket 服务前判断是否已启动
    if [ -f "$PID_DIR/websocket.pid" ] && kill -0 "$(cat "$PID_DIR/websocket.pid")" 2>/dev/null; then
        echo "WebSocket Service already running, skipping..."
    else
        if [ $USE_SETSID -eq 1 ]; then
            setsid "$WEBSOCKET_BIN" > "$WEBSOCKET_LOG" 2>&1 &
        else
            "$WEBSOCKET_BIN" > "$WEBSOCKET_LOG" 2>&1 &
        fi
        WEBSOCKET_PID=$!
        echo "$WEBSOCKET_PID" > "$PID_DIR/websocket.pid"
        echo "WebSocket Service started with PID $WEBSOCKET_PID"
    fi

    # 编译 gRPC 服务
    if [ -f "$GRPC_SERVICE" ]; then
        go build -o "$GRPC_BIN" "$GRPC_SERVICE"
        if [ $? -ne 0 ]; then
            echo "Failed to compile gRPC Service"
            exit 1
        fi
    else
        echo "gRPC Service source file not found"
        exit 1
    fi

    # 启动 gRPC 服务前判断是否已启动
    if [ -f "$PID_DIR/grpc.pid" ] && kill -0 "$(cat "$PID_DIR/grpc.pid")" 2>/dev/null; then
        echo "gRPC Service already running, skipping..."
    else
        if [ $USE_SETSID -eq 1 ]; then
            setsid "$GRPC_BIN" > "$GRPC_LOG" 2>&1 &
        else
            "$GRPC_BIN" > "$GRPC_LOG" 2>&1 &
        fi
        GRPC_PID=$!
        echo "$GRPC_PID" > "$PID_DIR/grpc.pid"
        echo "gRPC Service started with PID $GRPC_PID"
    fi

    echo "Service start-up checked. Logs are written to: $LOG_DIR"
}

# 停止服务
stop_services() {
    echo "Stopping all test services..."

    if [ -f "$PID_DIR/http.pid" ]; then
        HTTP_PID=$(cat "$PID_DIR/http.pid")
        if [ $USE_SETSID -eq 1 ]; then
            # 使用负PID关闭整个进程组
            kill -TERM -"$HTTP_PID"
        else
            kill_tree "$HTTP_PID"
        fi
        rm -f "$PID_DIR/http.pid"
        echo "HTTP Service stopped"
    else
        echo "HTTP Service not running"
    fi

    if [ -f "$PID_DIR/websocket.pid" ]; then
        WEBSOCKET_PID=$(cat "$PID_DIR/websocket.pid")
        if [ $USE_SETSID -eq 1 ]; then
            kill -TERM -"$WEBSOCKET_PID"
        else
            kill_tree "$WEBSOCKET_PID"
        fi
        rm -f "$PID_DIR/websocket.pid"
        echo "WebSocket Service stopped"
    else
        echo "WebSocket Service not running"
    fi

    if [ -f "$PID_DIR/grpc.pid" ]; then
        GRPC_PID=$(cat "$PID_DIR/grpc.pid")
        if [ $USE_SETSID -eq 1 ]; then
            kill -TERM -"$GRPC_PID"
        else
            kill_tree "$GRPC_PID"
        fi
        rm -f "$PID_DIR/grpc.pid"
        echo "gRPC Service stopped"
    else
        echo "gRPC Service not running"
    fi

    echo "All test services stopped."
}

# 检查服务状态
status_services() {
    echo "Checking test services status..."

    if [ -f "$PID_DIR/http.pid" ] && kill -0 "$(cat "$PID_DIR/http.pid")" 2>/dev/null; then
        echo "HTTP Service is running"
    else
        echo "HTTP Service is not running"
    fi

    if [ -f "$PID_DIR/websocket.pid" ] && kill -0 "$(cat "$PID_DIR/websocket.pid")" 2>/dev/null; then
        echo "WebSocket Service is running"
    else
        echo "WebSocket Service is not running"
    fi

    if [ -f "$PID_DIR/grpc.pid" ] && kill -0 "$(cat "$PID_DIR/grpc.pid")" 2>/dev/null; then
        echo "gRPC Service is running"
    else
        echo "gRPC Service is not running"
    fi
}

# 检查健康状态
health_services() {
    echo "Checking health of test services..."

    # gRPC 健康检查
    echo "gRPC Service health checking..."
    grpc_output=$(grpcurl -plaintext -d '{"name": "test"}' localhost:8391 hello.HelloService.SayHello 2>&1)
    grpc_status=$?
    echo "$grpc_output"
    if [ $grpc_status -eq 0 ]; then
        echo -e "gRPC Service health check passed\n"
    else
        echo -e "gRPC Service health check failed\n"
    fi

    # HTTP 健康检查
    echo "HTTP Service health checking..."
    http_output=$(curl -s http://127.0.0.1:8382/api/v1/order/health)
    http_status=$?
    echo "$http_output"
    if [ $http_status -eq 0 ]; then
        echo -e "HTTP Service health check passed\n"
    else
        echo -e "HTTP Service health check failed\n"
    fi

    # WebSocket 健康检查
    echo "WebSocket Service health checking..."
    ws_output=$(curl -s http://127.0.0.1:8392/health)
    ws_status=$?
    echo "$ws_output"
    if [ $ws_status -eq 0 ]; then
        echo -e "WebSocket Service health check passed\n"
    else
        echo -e "WebSocket Service health check failed\n"
    fi
}

# 主逻辑
case "$1" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    status)
        status_services
        ;;
    health)
        health_services
        ;;
    *)
        echo "Usage: $0 {start|stop|status|health}"
        exit 1
        ;;
esac

exit 0