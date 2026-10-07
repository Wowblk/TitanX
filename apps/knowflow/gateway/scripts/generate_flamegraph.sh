#!/bin/bash

# generate_flamegraph.sh
# 用于生成 mini-gateway 的火焰图，支持通过参数指定采集时间和端口

set -e

# 默认参数
DURATION=5
PORT=8380
OUTPUT_DIR="profiles"
DATA_DIR="data"
PPROF_FILE="cpu.pprof"
STACK_FILE="stack.txt"
COLLAPSED_FILE="collapsed.txt"
FLAMEGRAPH_FILE="flamegraph.svg"

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration|-d)
            DURATION="$2"
            shift 2
            ;;
        --port|-p)
            PORT="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--duration|-d <seconds>] [--port|-p <port>]"
            echo "Example: $0 --duration 30 --port 8381"
            exit 1
            ;;
    esac
done

# 验证参数
if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -le 0 ]; then
    echo "Error: Duration must be a positive integer (got: $DURATION)"
    exit 1
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Error: Port must be a valid port number between 1 and 65535 (got: $PORT)"
    exit 1
fi

# 检查依赖
check_dependency() {
    command -v "$1" >/dev/null 2>&1 || { echo "$1 is required but not installed."; exit 1; }
}
check_dependency curl
check_dependency go

# 检查 FlameGraph 工具
FLAMEGRAPH_SCRIPT=$(which flamegraph.pl 2>/dev/null || echo "")
if [ -z "$FLAMEGRAPH_SCRIPT" ]; then
    echo "flamegraph.pl not found in PATH. Please install FlameGraph tools from https://github.com/brendangregg/FlameGraph"
    exit 1
fi

# 寻找 stackcollapse-go.pl - 通常与 flamegraph.pl 在同一目录
FLAMEGRAPH_DIR=$(dirname "$FLAMEGRAPH_SCRIPT")
STACKCOLLAPSE_SCRIPT="$FLAMEGRAPH_DIR/stackcollapse-go.pl"
if [ ! -f "$STACKCOLLAPSE_SCRIPT" ]; then
    echo "stackcollapse-go.pl not found at $STACKCOLLAPSE_SCRIPT"
    echo "Please ensure you have installed the full FlameGraph toolkit"
    exit 1
fi

# 创建输出目录和数据目录
mkdir -p "$OUTPUT_DIR"
mkdir -p "$DATA_DIR"

echo "Checking pprof endpoint availability..."
if ! curl -s -o /dev/null -w "%{http_code}" "http://localhost:${PORT}/debug/pprof/" | grep -q 200; then
    echo "Error: pprof endpoint not accessible at http://localhost:${PORT}/debug/pprof/"
    exit 1
fi

echo "Collecting CPU profile for ${DURATION} seconds..."
if ! curl -o "$OUTPUT_DIR/$PPROF_FILE" "http://localhost:${PORT}/debug/pprof/profile?seconds=${DURATION}"; then
    echo "Error: Failed to collect pprof data"
    exit 1
fi

echo "Verifying pprof file..."
if [ ! -s "$OUTPUT_DIR/$PPROF_FILE" ]; then
    echo "Error: pprof file is empty or not created"
    exit 1
fi

echo "Generating stack traces..."
if ! go tool pprof -raw -output="$OUTPUT_DIR/$STACK_FILE" "$OUTPUT_DIR/$PPROF_FILE"; then
    echo "Error: Failed to generate stack traces"
    exit 1
fi

echo "Verifying stack file..."
if [ ! -s "$OUTPUT_DIR/$STACK_FILE" ]; then
    echo "Error: stack file is empty or not created"
    exit 1
fi

echo "Collapsing stacks for flamegraph..."
if ! "$STACKCOLLAPSE_SCRIPT" "$OUTPUT_DIR/$STACK_FILE" > "$OUTPUT_DIR/$COLLAPSED_FILE" 2>/tmp/stackcollapse_error.log; then
    echo "Error: Failed to collapse stack traces"
    echo "stackcollapse-go.pl error output:"
    cat /tmp/stackcollapse_error.log
    exit 1
fi

echo "Generating flamegraph..."
if ! "$FLAMEGRAPH_SCRIPT" "$OUTPUT_DIR/$COLLAPSED_FILE" > "$OUTPUT_DIR/$FLAMEGRAPH_FILE" 2>/tmp/flamegraph_error.log; then
    echo "Error: Failed to generate flamegraph"
    echo "flamegraph.pl error output:"
    cat /tmp/flamegraph_error.log
    exit 1
fi

cp "$OUTPUT_DIR/$FLAMEGRAPH_FILE" "$DATA_DIR/$FLAMEGRAPH_FILE"
echo "Flamegraph generated at $OUTPUT_DIR/$FLAMEGRAPH_FILE"
echo "File size: $(du -h "$OUTPUT_DIR/$FLAMEGRAPH_FILE" | cut -f1)"
echo "Open $OUTPUT_DIR/$FLAMEGRAPH_FILE in a browser to view the flamegraph."