package observability

import (
	"context"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.uber.org/zap"
)

// InitTracing 初始化分布式追踪（使用 Jaeger），根据配置决定是否启用
// 返回一个清理资源的关闭函数
func InitTracing(cfg *config.Config) func(context.Context) error {
	if !cfg.Observability.Jaeger.Enabled {
		logger.Info("Jaeger tracing is disabled in configuration")
		return func(ctx context.Context) error { return nil } // 无操作的关闭函数
	}
	logger.Info("Jaeger tracing is enabled in configuration")

	// 创建 OTLP HTTP 导出器，用于将追踪数据发送到 Jaeger
	exporter, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint(cfg.Observability.Jaeger.Endpoint),
		otlptracehttp.WithURLPath("/v1/traces"),
		otlptracehttp.WithInsecure(), // 本地测试禁用 TLS，生产环境需配置
	)
	if err != nil {
		logger.Error("Failed to initialize OTLP exporter",
			zap.String("endpoint", cfg.Observability.Jaeger.Endpoint),
			zap.Error(err))
		panic(err) // 致命错误，生产环境建议优雅处理
	}

	// 根据配置选择采样器
	var sampler sdktrace.Sampler
	switch cfg.Observability.Jaeger.Sampler {
	case "always":
		sampler = sdktrace.AlwaysSample()
	case "ratio":
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.Observability.Jaeger.SampleRatio))
	default:
		sampler = sdktrace.AlwaysSample()
		logger.Warn("Unknown sampler type detected, defaulting to 'always'",
			zap.String("sampler", cfg.Observability.Jaeger.Sampler))
	}

	// 定义服务资源信息
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("mini-gateway"),
			semconv.ServiceVersionKey.String("0.1.0"), // 可从全局版本变量获取
		),
	)
	if err != nil {
		logger.Error("Failed to create tracing resource",
			zap.Error(err))
		panic(err) // 致命错误，生产环境建议优雅处理
	}

	// 初始化 TracerProvider，包含导出器、资源和采样器
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// 设置全局 TracerProvider 和 TextMapPropagator 用于追踪传播
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("Distributed tracing initialized successfully",
		zap.String("endpoint", cfg.Observability.Jaeger.Endpoint),
		zap.String("sampler", cfg.Observability.Jaeger.Sampler),
		zap.Float64("sampleRatio", cfg.Observability.Jaeger.SampleRatio))

	return tp.Shutdown // 返回清理函数以释放资源
}
