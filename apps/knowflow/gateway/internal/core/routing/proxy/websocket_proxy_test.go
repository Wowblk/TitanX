package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DoraZa/mini-gateway/internal/core/health"
	"github.com/DoraZa/mini-gateway/pkg/logger"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// newTestBackendWebSocketServer 启动一个用于模拟后端 WebSocket 服务的测试服务器，采用简单回显逻辑。
func newTestBackendWebSocketServer(t *testing.T) *httptest.Server {
	upgrader := websocket.Upgrader{
		// 测试环境下允许所有跨域请求
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 后端支持任意路径，升级为 WebSocket 连接
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("后端升级 WebSocket 失败: %v", err)
		}
		defer ws.Close()

		// 简单回显客户端发送的消息
		for {
			msgType, msg, err := ws.ReadMessage()
			if err != nil {
				break
			}
			// 如果客户端关闭连接，会产生错误，此时退出循环
			if err := ws.WriteMessage(msgType, msg); err != nil {
				break
			}
		}
	}))
	return ts
}

// TestWebSocketProxy_Forward 测试 WebSocketProxy 的双向消息转发流程
func TestWebSocketProxy_Forward(t *testing.T) {
	// 初始化测试配置（假设 config.InitTestConfigManager 可初始化一个用于测试的配置）
	config.InitTestConfigManager()
	logger.InitTestLogger()
	health.InitHealthChecker(config.GetConfig())

	// 启动后端 WebSocket 测试服务器
	backendTS := newTestBackendWebSocketServer(t)
	defer backendTS.Close()

	// 将后端服务器地址由 "http" 转换为 "ws" 协议
	backendURL := "ws" + strings.TrimPrefix(backendTS.URL, "http")

	// 获取测试配置，并修改 WebSocket 路由相关配置
	cfg := config.GetConfig()
	// 设置 WebSocket 代理的前缀，例如 "/ws"
	cfg.WebSocket.Prefix = "/ws"
	// 假设 Routing 配置支持 WebSocketRules 字段，定义一个路由规则：
	// 请求 "/ws/echo" 将转发到后端目标 backendURL
	cfg.Routing.Rules = map[string]config.RoutingRules{
		"/ws/echo": {
			{
				Target:   backendURL, // 后端 WebSocket 服务地址
				Weight:   1,
				Protocol: "websocket",
				Env:      "stable",
			},
		},
	}
	// 可选：设置负载均衡器类型（此处使用默认轮询）
	cfg.Routing.LoadBalancer = "round_robin"

	// 创建 WebSocketProxy 实例
	wp := NewWebSocketProxy(cfg)

	// 创建 gin 路由，并配置 WebSocket 代理路由
	router := gin.New()
	wp.SetupWebSocketProxy(router, cfg)

	// 启动一个 httptest 服务器，用于代理服务
	proxyTS := httptest.NewServer(router)
	defer proxyTS.Close()

	// 构造客户端连接 URL：
	// 将 proxyTS 的 URL 协议转换为 "ws"，并添加路由路径 "/ws/echo"
	proxyURL := "ws" + strings.TrimPrefix(proxyTS.URL, "http") + "/ws/echo"

	// 使用默认的 WebSocket 拨号器连接代理服务
	dialer := websocket.DefaultDialer
	// 设置拨号超时，防止测试长时间阻塞
	dialer.HandshakeTimeout = 5 * time.Second
	clientConn, _, err := dialer.Dial(proxyURL, nil)
	if err != nil {
		t.Fatalf("拨号代理 WebSocket 失败: %v", err)
	}
	defer clientConn.Close()

	// 发送测试消息
	testMsg := "hello from client"
	if err := clientConn.WriteMessage(websocket.TextMessage, []byte(testMsg)); err != nil {
		t.Fatalf("写入消息失败: %v", err)
	}

	// 读取从后端回显的消息
	msgType, recvMsg, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("读取消息失败: %v", err)
	}
	if msgType != websocket.TextMessage {
		t.Errorf("预期消息类型 %d，实际得到 %d", websocket.TextMessage, msgType)
	}
	if string(recvMsg) != testMsg {
		t.Errorf("预期回显消息 %q，实际得到 %q", testMsg, string(recvMsg))
	}

	// 关闭 WebSocketProxy，释放连接池中的所有连接
	wp.Close()

	// 模拟等待一小段时间，确保后端连接关闭
	time.Sleep(100 * time.Millisecond)
}
