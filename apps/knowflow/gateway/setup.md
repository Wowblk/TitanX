### 环境初始化步骤

#### 1. 更新系统包
确保系统是最新的，以避免软件包冲突或缺失依赖。
```bash
apt update && apt upgrade -y      # 对于基于 Debian 的系统（如 Ubuntu）
# 或
yum update -y                     # 对于基于 Red Hat 的系统（如 CentOS）
```

#### 2. 安装基本工具
安装编译和开发所需的基本工具。
```bash
# 对于 Ubuntu/Debian
apt install -y build-essential git curl make

# 对于 CentOS/RHEL
yum groupinstall -y "Development Tools"
yum install -y git curl make
```

#### 3. 安装 Go
Makefile 使用 Go 构建项目，因此需要安装 Go。
```bash
# 下载并安装 Go（以最新版本为例，可根据需要调整版本）
curl -LO https://golang.org/dl/go1.24.1.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
rm go1.24.1.linux-amd64.tar.gz

# 设置 Go 环境变量
echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
echo "export GOPATH=\$HOME/go" >> ~/.bashrc
echo "export PATH=\$PATH:\$GOPATH/bin" >> ~/.bashrc
source ~/.bashrc

# 验证安装
go version
```

#### 4. 安装 Docker
Makefile 中有 Docker 相关目标（如 `docker-build` 和 `docker-run`），需要安装 Docker。
```bash
# 对于 Ubuntu/Debian
# Add Docker's official GPG key:
apt-get update
apt-get install ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update

apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin


# 对于 CentOS/RHEL
yum install -y docker systemd
systemctl start docker
systemctl enable docker
usermod -aG docker $USER

# 验证安装
docker --version
```

#### 5. 安装 wrk
Makefile 中的 `bench` 目标使用 `wrk` 进行性能测试。
```bash
# 安装 wrk 依赖
apt install -y build-essential libssl-dev unzip # Ubuntu/Debian
# 或
yum install -y gcc openssl-devel unzip           # CentOS/RHEL

# 编译安装 wrk
git clone https://github.com/wg/wrk.git
cd wrk
make -j10
cp wrk /usr/local/bin/
cd .. && rm -rf wrk

# 验证安装
wrk --version
```

#### 6. 安装 golangci-lint
Makefile 中的 `lint` 目标使用 `golangci-lint` 检查代码质量。
```bash
# 安装 golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# 验证安装
golangci-lint --version
```

#### 7. 安装 swag
Makefile 中的 `swagger` 目标需要 `swag` 生成 Swagger 文档。
```bash
go install github.com/swaggo/swag/cmd/swag@latest

# 验证安装
swag --version
```

#### 8. 安装 protoc 和相关插件
Makefile 中的 `proto` 目标需要 `protoc` 及其插件来生成 protobuf 文件。
```bash
# 安装 protoc
apt install -y protobuf-compiler  # Ubuntu/Debian
# 或
yum install -y protobuf-compiler  # CentOS/RHEL

# 安装 protoc-gen-go 和 protoc-gen-go-grpc
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# 安装 protoc-gen-grpc-gateway
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest

# 验证安装
protoc --version
protoc-gen-go --version
protoc-gen-go-grpc --version
protoc-gen-grpc-gateway --version
```

#### 9. 安装 docker-compose（可选）
Makefile 中 `stop-monitoring` 使用 `docker-compose`，如果需要运行监控服务则安装。
```bash
# 安装 docker-compose
curl -L "https://github.com/docker/compose/releases/download/v2.24.6/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# 验证安装
docker-compose --version
```

#### 10. 克隆项目并初始化
假设你的项目代码托管在 Git 上（根据 MODULE = github.com/DoraZa/mini-gateway）。
```bash
# 克隆项目
git clone https://github.com/DoraZa/mini-gateway.git
cd mini-gateway

# 安装项目依赖
make deps
```

---

### 执行完整流程
完成上述环境初始化后，你可以按以下顺序运行 Makefile 中的目标，完成软件的所有流程：

1. **构建项目**
   ```bash
   make build
   ```

2. **启动外部依赖**
   ```bash
   make start-test-env
   make setup-consul # 初始化Consul里，后端节点的配置信息
   # 关闭外部依赖
   make stop-test-env
   ```

3. **启动后端服务**
   ```bash
   make manage-test-start
   # 关闭后端服务
   make manage-test-stop
   ```

4. **运行项目**
   ```bash
   make run
   ```

5. **生成 Protobuf 文件**
    ```bash
    make proto
    ```

6. **停止外部依赖（可选）**
    ```bash
    make stop-monitoring
    ```

7. **清理编译产物**
    ```bash
    make clean
    ```

---

### 注意事项
- **权限问题**：如果遇到权限问题，确保以适当的用户身份运行命令（可能需要 `sudo` 或调整文件权限）。
- **网络问题**：确保系统可以访问 GitHub、Golang.org 等站点以下载依赖。
- **版本兼容性**：上述工具版本（如 Go 1.22.1、Consul 1.18.1）是示例，可能需要根据你的需求调整。
- **磁盘空间**：确保系统有足够的磁盘空间存储依赖和编译产物。
- **防火墙**：如果在服务器上运行，可能需要开放端口（如 8080、8500 等）。