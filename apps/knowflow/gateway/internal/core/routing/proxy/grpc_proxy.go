package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/health"
	"github.com/DoraZa/mini-gateway/internal/core/observability"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/DoraZa/mini-gateway/proto/proto"
	"github.com/gin-gonic/gin"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"
)

// grpcTracer 为 gRPC 代理初始化追踪器
var grpcTracer = otel.Tracer("proxy:grpc")

// 新增：允许测试时注入自定义 gRPC 连接创建和处理器注册逻辑
var newGRPCClient = func(target string, dialOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.Dial(target, dialOpts...)
}

var registerHelloServiceHandlerFunc = proto.RegisterHelloServiceHandler

// SetupGRPCProxy 配置 HTTP 到 gRPC 的反向代理
func SetupGRPCProxy(cfg *config.Config, r gin.IRouter) {
	mux := runtime.NewServeMux(
		runtime.WithErrorHandler(httpErrorHandler()),
		runtime.WithForwardResponseOption(httpResponseModifier),
	)

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()), // 本地测试用，生产环境需启用 TLS
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
	}

	// 遍历 gRPC 路由规则
	for route, rules := range cfg.Routing.GetGrpcRules() {
		for _, rule := range rules {
			if rule.Protocol != "grpc" {
				continue
			}

			conn, err := newGRPCClient(rule.Target, dialOpts...)
			if err != nil {
				logger.Error("Failed to establish gRPC connection",
					zap.String("target", rule.Target),
					zap.Error(err))
				continue
			}

			// 在设置期间注册 gRPC 服务处理器
			if err := registerHelloServiceHandlerFunc(context.Background(), mux, conn); err != nil {
				logger.Error("Failed to register gRPC service handler",
					zap.String("target", rule.Target),
					zap.Error(err))
				conn.Close()
				continue
			}
			logger.Info("Successfully registered gRPC service handler",
				zap.String("path", route),
				zap.String("target", rule.Target))
		}

		// 处理带有上下文传播的传入请求
		r.Any(route, func(c *gin.Context) {
			ctx, span := grpcTracer.Start(c.Request.Context(), "GRPCProxy.Handle",
				trace.WithAttributes(
					attribute.String("http.method", c.Request.Method),
					attribute.String("http.path", c.Request.URL.Path),
					attribute.String("grpc.prefix", cfg.GRPC.Prefix),
				))
			defer span.End()

			span.SetAttributes(attribute.String("grpc.routing.path", c.Request.URL.Path))

			req := c.Request
			// 规范化 URL，避免不必要的重定向
			if strings.HasSuffix(req.URL.Path, "/") {
				req.URL.Path = strings.TrimSuffix(req.URL.Path, "/")
			}

			originalPath := req.URL.Path
			grpcPrefix := cfg.GRPC.Prefix
			adjustedPath := strings.TrimPrefix(originalPath, grpcPrefix)
			if adjustedPath == originalPath {
				logger.Warn("Request path lacks gRPC prefix, no adjustment applied",
					zap.String("path", originalPath),
					zap.String("prefix", grpcPrefix))
			} else {
				logger.Info("Adjusted gRPC request path by removing prefix",
					zap.String("originalPath", originalPath),
					zap.String("adjustedPath", adjustedPath),
					zap.String("prefix", grpcPrefix))
				req.URL.Path = adjustedPath
			}

			// 将元数据传播到请求上下文中
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("request-id", c.GetHeader("X-Request-ID")))
			req = req.WithContext(ctx)

			start := time.Now()
			recorder := &statusRecorder{ResponseWriter: c.Writer, Status: http.StatusOK}
			mux.ServeHTTP(recorder, req)

			// 从路由规则中识别目标
			target := ""
			for _, rule := range cfg.Routing.GetGrpcRules()[route] {
				if rule.Protocol == "grpc" {
					target = rule.Target
					break
				}
			}
			health.GetGlobalHealthChecker().UpdateRequestCount(target, recorder.Status < http.StatusBadRequest)

			// 记录请求延迟
			duration := time.Since(start).Seconds()
			observability.RequestDuration.WithLabelValues(c.Request.Method, c.Request.URL.Path).Observe(duration)
			span.SetStatus(codes.Ok, "gRPC proxy completed successfully")
		})
		logger.Info("gRPC proxy route configured successfully",
			zap.String("path", route))
	}
}

// statusRecorder 捕获 HTTP 响应状态码
type statusRecorder struct {
	gin.ResponseWriter
	Status int
}

// WriteHeader 重写 WriteHeader 以捕获状态码
func (r *statusRecorder) WriteHeader(code int) {
	r.Status = code
	r.ResponseWriter.WriteHeader(code)
}

// httpErrorHandler 自定义 gRPC 请求的错误处理
func httpErrorHandler() runtime.ErrorHandlerFunc {
	return func(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
		st, _ := status.FromError(err)
		statusCode := fmt.Sprintf("%d", st.Code())
		path := r.URL.Path

		observability.GRPCCallsTotal.WithLabelValues(path, statusCode).Inc()
		logger.Error("gRPC request processing failed",
			zap.String("path", path),
			zap.String("statusCode", statusCode),
			zap.String("error", st.Message()))

		runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
	}
}

// httpResponseModifier 为 HTTP 响应添加自定义头部
func httpResponseModifier(ctx context.Context, w http.ResponseWriter, _ gproto.Message) error {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		logger.Info("Metadata found in request context",
			zap.Any("metadata", md))
	} else {
		logger.Warn("No metadata found in request context")
	}
	w.Header().Set("X-Proxy-Type", "grpc-gateway")
	w.Header().Set("X-Powered-By", "mini-gateway")
	return nil
}
