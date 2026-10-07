package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/health"
	"github.com/DoraZa/mini-gateway/internal/core/observability"
	"github.com/gin-gonic/gin"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
)

func TestSetupGRPCProxy_Response(t *testing.T) {
	// 保存全局变量原始值
	origNewGRPCClient := newGRPCClient
	origRegisterHelloServiceHandlerFunc := registerHelloServiceHandlerFunc
	// 测试结束后恢复
	defer func() {
		newGRPCClient = origNewGRPCClient
		registerHelloServiceHandlerFunc = origRegisterHelloServiceHandlerFunc
	}()

	// 在测试中覆盖 newGRPCClient，不实际建立 gRPC 连接
	newGRPCClient = func(target string, dialOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return nil, nil
	}

	// 覆盖 registerHelloServiceHandlerFunc，
	// 在 mux 上注册的处理器调用 httpResponseModifier 来设置响应头，再写入固定响应体
	registerHelloServiceHandlerFunc = func(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
		return mux.HandlePath("GET", "/hello", func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
			// 模拟 gRPC 转发时调用 ForwardResponseOption 设置响应头
			_ = httpResponseModifier(req.Context(), w, nil)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "hello world"}`))
		})
	}

	// 构造测试配置
	cfg := &config.Config{
		GRPC: config.GRPCConfig{
			Prefix: "/grpc",
		},
		Routing: config.Routing{
			Rules: map[string]config.RoutingRules{
				"/grpc/hello": {
					{
						Protocol: "grpc",
						Target:   "dummy-target",
					},
				},
			},
			LoadBalancer: "round_robin",
		},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	// 注册 gRPC 代理路由
	SetupGRPCProxy(cfg, router)

	// 初始化测试配置和健康检查（如果有需要）
	config.InitTestConfigManager()
	health.InitHealthChecker(cfg)

	// 启动 httptest 服务器承载代理服务
	ts := httptest.NewServer(router)
	defer ts.Close()

	// 请求路径为 "/grpc/hello"，内部会剥离前缀转发到 mux 上注册的 "/hello" 处理器
	reqURL := ts.URL + "/grpc/hello"

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatalf("failed to create HTTP request: %v", err)
	}
	// 模拟请求头，传播请求标识
	req.Header.Set("X-Request-ID", "test-request-id")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// 校验响应状态码
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// 校验响应头是否包含 httpResponseModifier 设置的自定义头部
	if resp.Header.Get("X-Proxy-Type") != "grpc-gateway" {
		t.Errorf("expected header X-Proxy-Type to be 'grpc-gateway', got '%s'", resp.Header.Get("X-Proxy-Type"))
	}
	if resp.Header.Get("X-Powered-By") != "mini-gateway" {
		t.Errorf("expected header X-Powered-By to be 'mini-gateway', got '%s'", resp.Header.Get("X-Powered-By"))
	}

	// 读取响应体内容
	bodyBytes := make([]byte, 1024)
	n, err := resp.Body.Read(bodyBytes)
	if err != nil && err.Error() != "EOF" {
		t.Errorf("failed to read response body: %v", err)
	}
	bodyStr := string(bodyBytes[:n])
	expectedBody := `{"message": "hello world"}`
	if !strings.Contains(bodyStr, expectedBody) {
		t.Errorf("expected response body to contain %q, got %q", expectedBody, bodyStr)
	}

	// 可选：调用 observability 指标，避免未使用告警
	_ = observability.RequestDuration

}
