package proxy

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/DoraZa/mini-gateway/pkg/util"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/health"
	"github.com/DoraZa/mini-gateway/internal/core/loadbalancer"
	"github.com/DoraZa/mini-gateway/internal/core/observability"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// websocketTracer 为 WebSocket 代理操作初始化追踪器
var websocketTracer = otel.Tracer("proxy:websocket")

// WebSocketProxy 管理 WebSocket 代理，包括连接池和负载均衡
type WebSocketProxy struct {
	pool *WebSocketPool            // WebSocket 连接池
	lb   loadbalancer.LoadBalancer // 负载均衡器
}

// NewWebSocketProxy 根据配置创建并初始化 WebSocketProxy 实例
func NewWebSocketProxy(cfg *config.Config) *WebSocketProxy {
	lb, err := loadbalancer.NewLoadBalancer(cfg.Routing.LoadBalancer, cfg)
	if err != nil {
		logger.Error("Failed to initialize load balancer",
			zap.String("type", cfg.Routing.LoadBalancer),
			zap.Error(err))
		lb = loadbalancer.NewRoundRobin() // 初始化失败时回退到轮询
	}
	return &WebSocketProxy{
		pool: NewWebSocketPool(cfg),
		lb:   lb,
	}
}

// SetupWebSocketProxy 根据提供的规则配置 WebSocket 代理路由
func (wp *WebSocketProxy) SetupWebSocketProxy(r gin.IRouter, cfg *config.Config) {
	rules := cfg.Routing.GetWebSocketRules()
	if len(rules) == 0 {
		logger.Info("No WebSocket routing rules found in configuration")
		return
	}

	poolMgr := util.NewPoolManager(cfg)

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // 可根据配置调整跨源策略
		},
	}

	for path, targetRules := range rules {
		logger.Info("Setting up WebSocket proxy route",
			zap.String("path", path),
			zap.Any("targets", targetRules))
		r.GET(path, wp.createWebSocketHandler(targetRules, upgrader, cfg, poolMgr))
	}
}

// createWebSocketHandler 创建 WebSocket 连接的处理函数
func (wp *WebSocketProxy) createWebSocketHandler(rules config.RoutingRules, upgrader websocket.Upgrader, cfg *config.Config, poolMgr *util.ObjectPoolManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 HTTP 请求头中提取追踪上下文
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))
		ctx, connectSpan := websocketTracer.Start(ctx, "WebSocket.Connect",
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer connectSpan.End()

		// 将客户端连接升级为 WebSocket
		clientConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Failed to upgrade connection")
			logger.Error("Failed to upgrade client connection to WebSocket",
				zap.String("path", c.Request.URL.Path),
				zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upgrade to WebSocket"})
			return
		}
		defer clientConn.Close()

		// 跟踪活跃的 WebSocket 连接数
		observability.ActiveWebSocketConnections.Inc()
		defer observability.ActiveWebSocketConnections.Dec()

		// 使用对象池管理器获取目标切片
		targets := poolMgr.GetTargets(len(rules))
		defer poolMgr.PutTargets(targets)

		for _, rule := range rules {
			targets = append(targets, rule.Target)
		}
		target := wp.lb.SelectTarget(targets, c.Request)
		if target == "" {
			connectSpan.SetStatus(codes.Error, "No available target")
			logger.Warn("No available WebSocket target found",
				zap.String("path", c.Request.URL.Path))
			clientConn.WriteMessage(websocket.TextMessage, []byte("No available target"))
			return
		}
		logger.Debug("Selected WebSocket target by load balancer",
			zap.String("target", target))

		// 验证目标是否为有效的 WebSocket URL
		targetURL, err := url.Parse(target)
		if err != nil || (targetURL.Scheme != "ws" && targetURL.Scheme != "wss") {
			health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Invalid backend URL")
			logger.Error("Invalid WebSocket target URL detected",
				zap.String("target", target),
				zap.Error(err))
			clientConn.WriteMessage(websocket.TextMessage, []byte("Invalid target address"))
			return
		}

		// 调整请求路径，去除 WebSocket 前缀
		originalPath := c.Request.URL.Path
		wsPrefix := cfg.WebSocket.Prefix
		adjustedPath := strings.TrimPrefix(originalPath, wsPrefix)
		if adjustedPath == originalPath {
			logger.Warn("Request path lacks WebSocket prefix, no adjustment applied",
				zap.String("path", originalPath),
				zap.String("prefix", wsPrefix))
		} else {
			logger.Info("Adjusted WebSocket path by removing prefix",
				zap.String("originalPath", originalPath),
				zap.String("adjustedPath", adjustedPath),
				zap.String("prefix", wsPrefix))
		}

		// 构造完整的转发目标 URL
		fullTarget := target
		if adjustedPath != "" && adjustedPath != "/" {
			targetURL.Path = path.Join(targetURL.Path, adjustedPath)
			fullTarget = targetURL.String()
		}
		logger.Debug("Determined final WebSocket forwarding target",
			zap.String("fullTarget", fullTarget))

		// 从连接池获取或创建后端 WebSocket 连接
		backendConn, err := wp.pool.GetConn(fullTarget)
		if err != nil {
			health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Failed to connect to backend")
			logger.Error("Failed to establish backend WebSocket connection",
				zap.String("fullTarget", fullTarget),
				zap.Error(err))
			clientConn.WriteMessage(websocket.TextMessage, []byte("Backend connection failed"))
			return
		}

		// 双向转发客户端与后端之间的消息
		errCh := make(chan error, 2)
		go wp.forwardMessages(ctx, clientConn, backendConn, "client-to-backend", errCh)
		go wp.forwardMessages(ctx, backendConn, clientConn, "backend-to-client", errCh)

		if err := <-errCh; err != nil {
			health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Message forwarding failed")
			logger.Error("WebSocket message forwarding failed",
				zap.String("path", c.Request.URL.Path),
				zap.String("fullTarget", fullTarget),
				zap.Error(err))
		}
	}
}

// forwardMessages 在两个 WebSocket 连接之间转发消息
func (wp *WebSocketProxy) forwardMessages(ctx context.Context, from, to *websocket.Conn, direction string, errCh chan<- error) {
	for {
		_, span := websocketTracer.Start(ctx, "WebSocket.Message",
			trace.WithAttributes(attribute.String("direction", direction)))
		msgType, msg, err := from.ReadMessage()
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to read message")
			span.End()
			errCh <- err
			return
		}
		err = to.WriteMessage(msgType, msg)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to write message")
			span.End()
			errCh <- err
			return
		}
		span.SetStatus(codes.Ok, "Message forwarded successfully")
		health.GetGlobalHealthChecker().UpdateRequestCount(to.LocalAddr().String(), true)
		span.End()
	}
}

// Close 关闭 WebSocket 代理并释放资源
func (wp *WebSocketProxy) Close() {
	wp.pool.Close()
	logger.Info("WebSocket proxy closed successfully")
}
