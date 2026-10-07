package traffic

import (
	"net/http"
	"sync"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/observability"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// breakerTimeSlidingTracer 为时间滑动窗口熔断器模块初始化追踪器
var breakerTimeSlidingTracer = otel.Tracer("breaker:time-sliding")

// RequestStat 捕获单个请求的状态
type RequestStat struct {
	Success   bool          // 请求是否成功
	Latency   time.Duration // 请求处理时长
	Timestamp time.Time     // 请求完成时间
}

// TimeSlidingWindow 实现基于时间的滑动窗口，用于请求统计
type TimeSlidingWindow struct {
	requests []RequestStat // 最近请求	// 最近请求统计列表
	mutex    sync.RWMutex  // 互斥锁，确保线程安全
	duration time.Duration // 窗口持续时间
}

// NewTimeSlidingWindow 创建新的时间滑动窗口
func NewTimeSlidingWindow(duration time.Duration) *TimeSlidingWindow {
	sw := &TimeSlidingWindow{
		requests: make([]RequestStat, 0),
		duration: duration,
	}
	go sw.cleanup() // 启动后台清理协程
	return sw
}

// Update 向滑动窗口添加新的请求统计
func (sw *TimeSlidingWindow) Update(stat RequestStat) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	sw.requests = append(sw.requests, stat)
}

// cleanup 定期清理窗口中过期的请求统计
func (sw *TimeSlidingWindow) cleanup() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		sw.mutex.Lock()
		now := time.Now()
		var validRequests []RequestStat
		for _, stat := range sw.requests {
			if now.Sub(stat.Timestamp) <= sw.duration {
				validRequests = append(validRequests, stat)
			}
		}
		sw.requests = validRequests
		sw.mutex.Unlock()
	}
}

// ErrorRate 计算窗口内的当前错误率
func (sw *TimeSlidingWindow) ErrorRate() float64 {
	sw.mutex.RLock()
	defer sw.mutex.RUnlock()
	if len(sw.requests) == 0 {
		return 0
	}
	var total, failed int
	for _, stat := range sw.requests {
		total++
		if !stat.Success {
			failed++
		}
	}
	return float64(failed) / float64(total)
}

// AvgLatency 计算窗口内请求的平均延迟
func (sw *TimeSlidingWindow) AvgLatency() time.Duration {
	sw.mutex.RLock()
	defer sw.mutex.RUnlock()
	if len(sw.requests) == 0 {
		return 0
	}
	var totalLatency time.Duration
	for _, stat := range sw.requests {
		totalLatency += stat.Latency
	}
	return totalLatency / time.Duration(len(sw.requests))
}

// Prometheus 指标用于熔断器可观测性
var (
	// errorRateGauge 跟踪每个路由的错误率
	errorRateGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gateway_error_rate",
			Help: "Error rate of requests per route",
		},
		[]string{"path"},
	)

	// latencyGauge 跟踪每个路由的平均延迟（单位：秒）
	latencyGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gateway_avg_latency_seconds",
			Help: "Average latency of requests per route in seconds",
		},
		[]string{"path"},
	)
)

// init 注册 Prometheus 指标
func init() {
	prometheus.MustRegister(errorRateGauge, latencyGauge)
}

// Breaker 返回用于熔断和降级的 Gin 中间件
func Breaker() gin.HandlerFunc {
	cfg := config.GetConfig()
	if !cfg.Middleware.Breaker || !cfg.Traffic.Breaker.Enabled {
		return func(c *gin.Context) {
			c.Next() // 如果熔断器未启用，则跳过
		}
	}

	// 为每个路由配置 Hystrix
	for path := range cfg.Routing.Rules {
		hystrix.ConfigureCommand(path, hystrix.CommandConfig{
			Timeout:                cfg.Traffic.Breaker.Timeout,
			MaxConcurrentRequests:  cfg.Traffic.Breaker.MaxConcurrent,
			RequestVolumeThreshold: cfg.Traffic.Breaker.MinRequests,
			SleepWindow:            cfg.Traffic.Breaker.SleepWindow,
			ErrorPercentThreshold:  int(cfg.Traffic.Breaker.ErrorRate * 100),
		})
	}

	// 初始化时间滑动窗口用于请求统计
	window := NewTimeSlidingWindow(time.Duration(cfg.Traffic.Breaker.WindowDuration) * time.Second)

	return func(c *gin.Context) {
		// 开始追踪熔断器检查
		_, span := breakerTimeSlidingTracer.Start(c.Request.Context(), "Breaker.Check",
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		start := time.Now()
		path := c.Request.URL.Path

		// 在 Hystrix 熔断器中执行请求
		err := hystrix.Do(path, func() error {
			c.Next() // 处理下游请求
			return c.Err()
		}, func(err error) error {
			// 熔断打开时的回退逻辑
			logger.Warn("Circuit breaker triggered for route",
				zap.String("path", path),
				zap.Error(err))
			span.SetStatus(codes.Error, "Circuit breaker open")
			span.SetAttributes(attribute.String("breakerState", "open"))
			observability.BreakerTrips.WithLabelValues(path).Inc()
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Service temporarily unavailable"})
			c.Abort()
			return nil // 表示回退已处理错误
		})

		// 在滑动窗口中记录请求统计
		latency := time.Since(start)
		success := err == nil && c.Writer.Status() < http.StatusBadRequest
		window.Update(RequestStat{
			Success:   success,
			Latency:   latency,
			Timestamp: time.Now(),
		})

		// 更新 Prometheus 指标
		errorRate := window.ErrorRate()
		avgLatency := window.AvgLatency()
		errorRateGauge.WithLabelValues(path).Set(errorRate)
		latencyGauge.WithLabelValues(path).Set(float64(avgLatency) / float64(time.Second))
		span.SetStatus(codes.Ok, "Request processed successfully")

		// 记录请求统计用于调试
		logger.Debug("Updated request statistics",
			zap.String("path", path),
			zap.Bool("success", success),
			zap.Duration("latency", latency),
			zap.Float64("errorRate", errorRate),
			zap.Duration("avgLatency", avgLatency))
	}
}

// DisableBreakerHandler 处理关闭指定路径熔断器的请求
func DisableBreakerHandler(c *gin.Context) {
	var request struct {
		Path string `json:"path" binding:"required"`
	}

	// 解析请求体
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: path is required"})
		return
	}

	// 检查路径是否有效
	cfg := config.GetConfig()
	if _, exists := cfg.Routing.Rules[request.Path]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Path not found in routing rules"})
		return
	}

	// 强制关闭熔断器
	// Hystrix 不提供直接关闭熔断器的 API，可以通过重置统计数据来间接实现
	hystrix.ConfigureCommand(request.Path, hystrix.CommandConfig{
		Timeout:                cfg.Traffic.Breaker.Timeout,
		MaxConcurrentRequests:  cfg.Traffic.Breaker.MaxConcurrent,
		RequestVolumeThreshold: cfg.Traffic.Breaker.MinRequests,
		SleepWindow:            cfg.Traffic.Breaker.SleepWindow,
		ErrorPercentThreshold:  0, // 将错误阈值设为 0，避免触发熔断
	})

	// 记录操作
	logger.Info("Circuit breaker disabled manually",
		zap.String("path", request.Path),
		zap.String("action", "disable"))

	// 更新可观测性指标（可选）
	errorRateGauge.WithLabelValues(request.Path).Set(0)

	c.JSON(http.StatusOK, gin.H{
		"message": "Circuit breaker disabled for path: " + request.Path,
	})
}
