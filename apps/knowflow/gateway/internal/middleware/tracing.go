package middleware

import (
	"time"

	"go.opentelemetry.io/otel/codes"

	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Tracing 返回分布式追踪中间件
func Tracing() gin.HandlerFunc {
	return func(c *gin.Context) {
		tracer := otel.Tracer("mini-gateway")

		// 从请求头提取追踪上下文
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		// 开始一个新的 Span
		ctx, span := tracer.Start(ctx, "Request:Enter",
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.path", c.Request.URL.Path),
				attribute.String("http.host", c.Request.Host),
			),
		)
		defer span.End()

		// 将追踪上下文注入请求
		c.Request = c.Request.WithContext(ctx)
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(c.Request.Header))

		// 记录 Trace ID 到日志
		spanCtx := span.SpanContext()
		if spanCtx.HasTraceID() {
			traceID := spanCtx.TraceID().String()
			c.Set("trace_id", traceID)
			logger.WithTrace(traceID).Info("Request received",
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
			)
		}

		// 记录请求开始时间
		start := time.Now()

		// 处理请求
		c.Next()

		// 记录响应状态和延迟
		status := c.Writer.Status()
		duration := time.Since(start).Seconds()
		span.SetAttributes(
			attribute.Int("http.status_code", status),
			attribute.Float64("http.duration_seconds", duration),
		)

		if len(c.Errors) > 0 {
			span.RecordError(c.Errors[0])
			span.SetStatus(codes.Error, c.Errors[0].Error())
		}
	}
}
