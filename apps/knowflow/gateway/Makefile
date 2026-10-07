# 项目基本信息
BINARY_NAME = mini-gateway
BIN_DIR = bin
CMD_DIR = cmd/gateway
MODULE = github.com/DoraZa/mini-gateway
VERSION = 0.1.0
BUILD_TIME = $(shell date +%Y-%m-%dT%H:%M:%S%z)
GIT_COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION = $(shell go version | awk '{print $$3}')

# 编译标志
#LDFLAGS = -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT) -X main.GoVersion=$(GO_VERSION)"
LDFLAGS = -ldflags "-X main.Version=$(VERSION) -X main.GoVersion=$(GO_VERSION)"

# 工具
GO = go
GOLINT = golangci-lint
DOCKER = docker
WRK = wrk
YQ = yq

# 默认火焰图参数
DURATION ?= 10
PORT ?= $(shell $(YQ) eval '.server.port' config/config.yaml 2>/dev/null || echo "8380")

# 默认目标
.PHONY: all
all: build

# 安装依赖
.PHONY: deps
deps:
	$(GO) mod tidy
	$(GO) mod download

# 编译项目并将二进制放入 bin 目录
.PHONY: build
#build: deps
build: deps build-plugins
	@mkdir -p $(BIN_DIR)
	$(GO) build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go

.PHONY: build-plugins
build-plugins:
	@echo "Building plugins..."
	@for dir in $(wildcard plugins/*); do \
		if [ -f "$$dir/main.go" ]; then \
			echo "Building $$dir..."; \
			(cd $$dir && go build -buildmode=plugin -o ../../$(BIN_DIR)/plugins/$$(basename $$dir).so .) || exit 1; \
		fi \
	done
	@echo "Plugins built successfully"

# 运行项目
.PHONY: run
run: build
	@rm -f logs/gateway.log  # 清理日志文件
	$(BIN_DIR)/$(BINARY_NAME)

# 测试
.PHONY: test
test:
	$(GO) test -v ./...

# 格式化代码
.PHONY: fmt
fmt:
	$(GO) fmt ./...
	gofmt -s -w .
	goimports -w .

# 检查代码质量
.PHONY: lint
lint:
	$(GOLINT) run ./...

# 清理编译产物
.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	$(GO) clean

# 生成 Swagger 文档（假设使用 swag）
.PHONY: swagger
swagger:
	swag init -g $(CMD_DIR)/main.go -o api/swagger

# 构建 Docker 镜像
.PHONY: docker-build
docker-build:
	$(DOCKER) build -t $(MODULE):$(VERSION) -f Dockerfile .

# 运行 Docker 容器
.PHONY: docker-run
docker-run: docker-build
	$(DOCKER) run -p 8080:8080 $(MODULE):$(VERSION)

# 性能测试（使用 wrk）
.PHONY: bench
bench: build
	$(WRK) -t10 -c100 -d30s http://localhost:8380/health

# 安装工具（可选）
.PHONY: tools
tools:
	$(GO) install github.com/swaggo/swag/cmd/swag@latest
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	# 如果 wrk 未安装，可手动安装：https://github.com/wg/wrk

# 显示版本信息
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Go Version: $(GO_VERSION)"

.PHONY: manage-test-start
manage-test-start:
	chmod +x ./test/manage_test_services.sh
	@echo "Starting test services via script..."
	@./test/manage_test_services.sh start

.PHONY: manage-test-stop
manage-test-stop:
	chmod +x ./test/manage_test_services.sh
	@echo "Stopping test services via script..."
	@./test/manage_test_services.sh stop

.PHONY: manage-test-status
manage-test-status:
	chmod +x ./test/manage_test_services.sh
	@echo "Checking test services status via script..."
	@./test/manage_test_services.sh status

.PHONY: manage-test-health
manage-test-health:
	chmod +x ./test/manage_test_services.sh
	@echo "Checking test services health via script..."
	@./test/manage_test_services.sh health

.PHONY: setup-consul
setup-consul:
	@echo "Checking if Consul is installed..."
	@#command -v consul >/dev/null 2>&1 || { echo "Consul not found. Please install Consul first."; exit 1; }
	@#echo "Starting Consul agent in dev mode..."
	@#consul agent -dev & \
#	sleep 2; \
	echo "Pushing load balancer rules to Consul KV Store..."; \
	curl -X PUT -d '{"/api/v1/user": ["http://localhost:8381", "http://localhost:8383"], "/api/v1/order": ["http://localhost:8382"]}' http://localhost:8300/v1/kv/gateway/loadbalancer/rules; \
	echo "Consul test environment setup complete."; \
	echo "Load balancer rules:"; \
	curl http://localhost:8300/v1/kv/gateway/loadbalancer/rules?raw

.PHONY: prepare-proto
prepare-proto:
	mkdir -p proto/lib
	@if [ -d "proto/lib/googleapis" ]; then \
		echo "proto/lib/googleapis already exists, updating instead"; \
		cd proto/lib/googleapis && git pull; \
	else \
		git clone --depth 1 https://github.com/googleapis/googleapis.git proto/lib/googleapis; \
	fi
	@if [ -d "proto/lib/grpc-proto" ]; then \
		echo "proto/lib/grpc-proto already exists, updating instead"; \
		cd proto/lib/grpc-proto && git pull; \
	else \
		git clone --depth 1 https://github.com/grpc/grpc-proto.git proto/lib/grpc-proto; \
	fi

# 生成 protobuf 文件
.PHONY: proto
proto: prepare-proto
	protoc -I . \
		-I proto/lib/googleapis \
		-I proto/lib/grpc-proto \
		--go_out=./proto \
		--go_opt=paths=source_relative \
		--go-grpc_out=./proto \
		--go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=./proto \
		--grpc-gateway_opt=paths=source_relative \
		--grpc-gateway_opt generate_unbound_methods=true \
		--plugin=protoc-gen-grpc-gateway=$(shell go env GOPATH)/bin/protoc-gen-grpc-gateway \
		./proto/hello.proto

# 启动测试环境所有外部依赖
.PHONY: start-envs
start-envs:
	@echo "Starting test environment..."
	@echo "Starting Redis..."
	@docker-compose -f test/docker/docker-compose.yml up -d mg-redis
	@echo "Starting Consul..."
	@docker-compose -f test/docker/docker-compose.yml up -d mg-consul
	@echo "Starting monitoring(Grafana|Prometheus|Jaeger)..."
	chmod +x test/docker/setup_grafana.sh
	chmod +x test/docker/setup_monitoring.sh
	@./test/docker/setup_monitoring.sh

# 停止外部依赖服务
.PHONY: stop-envs
stop-envs:
	@docker-compose -f test/docker/docker-compose.yml down
	@echo "外部依赖服务已停止"
	@docker volume rm -f docker_mg-consul-data
	@docker volume rm -f docker_mg-grafana-data
	@docker volume rm -f docker_mg-redis-data
	@docker volume rm -f docker_mg-prometheus-data
	@docker volume rm -f docker_mg-jaeger-data
	@echo "外部依赖服务数据卷已删除"

# 显示可访问的 HTTP 链接
.PHONY: links
links:
	@IP=$$(hostname -I 2>/dev/null | awk '{print $$1}' || ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $$2}' | head -n 1); \
	if [ -z "$$IP" ]; then \
		IP="127.0.0.1"; \
		echo "Warning: Could not detect external IP, falling back to 127.0.0.1"; \
	fi; \
	echo "Accessible HTTP links:"; \
	echo "  - Jaeger UI: http://$$IP:8330"; \
	echo "  - Jaeger OTLP HTTP: http://$$IP:8331"; \
	echo "  - Grafana: http://$$IP:8350/d/gateway-monitoring (login: admin/admin123)"; \
	echo "  - Prometheus: http://$$IP:8390"

# 安装火焰图生成依赖
.PHONY: install-flamegraph
install-flamegraph:
	@echo "Installing FlameGraph tools..."
	@mkdir -p /tmp/flamegraph
	# 下载主要的火焰图生成工具
	@wget -q https://raw.githubusercontent.com/brendangregg/FlameGraph/master/flamegraph.pl -O /tmp/flamegraph/flamegraph.pl
	@chmod +x /tmp/flamegraph/flamegraph.pl
	# 下载Go专用的堆栈折叠工具
	@wget -q https://raw.githubusercontent.com/brendangregg/FlameGraph/master/stackcollapse-go.pl -O /tmp/flamegraph/stackcollapse-go.pl
	@chmod +x /tmp/flamegraph/stackcollapse-go.pl
	# 下载其他可能有用的折叠工具
	@wget -q https://raw.githubusercontent.com/brendangregg/FlameGraph/master/stackcollapse.pl -O /tmp/flamegraph/stackcollapse.pl
	@chmod +x /tmp/flamegraph/stackcollapse.pl
	# 安装到系统目录
	@sudo mv /tmp/flamegraph/*.pl /usr/local/bin/
	@rm -rf /tmp/flamegraph
	@echo "FlameGraph tools installed successfully."
	@echo "Available tools: flamegraph.pl, stackcollapse-go.pl, stackcollapse.pl"

# 生成火焰图快捷命令
.PHONY: flamegraph
flamegraph:
	@echo "Generating flamegraph..."
	@chmod +x scripts/generate_flamegraph.sh
	bash scripts/generate_flamegraph.sh --duration $(DURATION) --port $(PORT)
	@echo "Flamegraph generated in profiles directory."