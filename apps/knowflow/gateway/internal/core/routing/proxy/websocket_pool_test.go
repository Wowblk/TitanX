package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/gorilla/websocket"
)

// newTestWebsocketServer 启动一个测试用 WebSocket 服务器，用于模拟升级连接并回显消息。
func newTestWebsocketServer(t *testing.T) *httptest.Server {
	upgrader := websocket.Upgrader{
		// 测试环境下允许所有跨域请求
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("failed to upgrade websocket: %v", err)
		}
		defer ws.Close()

		// 简单回显客户端发送的消息
		for {
			messageType, message, err := ws.ReadMessage()
			if err != nil {
				break
			}
			if err := ws.WriteMessage(messageType, message); err != nil {
				break
			}
		}
	}))
	return ts
}

// TestWebSocketPool_GetConn 验证 GetConn 能正确建立 WebSocket 连接，并复用已建立的连接
func TestWebSocketPool_GetConn(t *testing.T) {
	// 初始化测试配置（假设 config.InitTestConfigManager 已提供测试配置）
	config.InitTestConfigManager()

	ts := newTestWebsocketServer(t)
	defer ts.Close()

	// 将测试服务器地址从 "http://" 转换为 "ws://"
	target := "ws" + strings.TrimPrefix(ts.URL, "http")

	// 创建 WebSocketPool 实例
	pool := NewWebSocketPool(config.GetConfig())
	// 从池中获取连接
	conn1, err := pool.GetConn(target)
	if err != nil {
		t.Fatalf("GetConn returned error: %v", err)
	}
	if conn1 == nil {
		t.Fatal("Expected non-nil connection")
	}

	// 再次获取相同目标的连接，应该返回同一连接实例
	conn2, err := pool.GetConn(target)
	if err != nil {
		t.Fatalf("GetConn returned error: %v", err)
	}
	if conn1 != conn2 {
		t.Error("Expected the same connection instance on subsequent call")
	}

	// 通过写入并回显消息，确认连接正常
	testMsg := "ping"
	if err := conn1.WriteMessage(websocket.TextMessage, []byte(testMsg)); err != nil {
		t.Errorf("Failed to write message: %v", err)
	}
	_, msg, err := conn1.ReadMessage()
	if err != nil {
		t.Errorf("Failed to read message: %v", err)
	}
	if string(msg) != testMsg {
		t.Errorf("Expected echoed message %q, got %q", testMsg, string(msg))
	}
}

// TestWebSocketPool_Close 验证 Close 能正确关闭池中所有连接，并清空连接池
func TestWebSocketPool_Close(t *testing.T) {
	config.InitTestConfigManager()

	ts := newTestWebsocketServer(t)
	defer ts.Close()

	target := "ws" + strings.TrimPrefix(ts.URL, "http")
	pool := NewWebSocketPool(config.GetConfig())

	conn, err := pool.GetConn(target)
	if err != nil {
		t.Fatalf("GetConn returned error: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connection")
	}

	// 调用 Close 关闭连接池
	pool.Close()

	// 检查池中连接已被清空
	pool.mu.RLock()
	poolSize := len(pool.pool)
	pool.mu.RUnlock()
	if poolSize != 0 {
		t.Errorf("Expected pool to be empty after Close, but got %d connections", poolSize)
	}

	// 对已关闭的连接写入消息应返回错误
	err = conn.WriteMessage(websocket.TextMessage, []byte("test"))
	if err == nil {
		t.Error("Expected error when writing to closed connection, but got none")
	}
}
