package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// 定义全局 Prometheus 指标用于可观测性
var (
	// RequestsTotal 跟踪网关处理的请求总数，按方法、路径和状态码分类
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_requests_total",
			Help: "Total number of requests processed by the gateway",
		},
		[]string{"method", "path", "status"},
	)

	// RequestDuration 测量请求延迟分布（单位：秒），按方法和路径分类
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_request_duration_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets, // 默认桶：0.005, 0.01, 0.025, ..., 10
		},
		[]string{"method", "path"},
	)

	// RateLimitRejections 统计因限流拒绝的请求数，按路径分类
	RateLimitRejections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_rate_limit_rejections_total",
			Help: "Total number of requests rejected due to rate limiting",
		},
		[]string{"path"},
	)

	// BreakerTrips 统计熔断器触发的次数，按路径分类
	BreakerTrips = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_breaker_trips_total",
			Help: "Total number of circuit breaker trips",
		},
		[]string{"path"},
	)

	// ActiveWebSocketConnections 跟踪当前活跃的 WebSocket 连接数
	ActiveWebSocketConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_websocket_connections_active",
			Help: "Number of active WebSocket connections",
		},
	)

	// JwtAuthFailures 统计 JWT 认证失败的次数，按路径分类
	JwtAuthFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_jwt_auth_failures_total",
			Help: "Total number of JWT authentication failures",
		},
		[]string{"path"},
	)

	// IPAclRejections 统计因 IP 访问控制列表拒绝的请求数，按路径和 IP 分类
	IPAclRejections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_ip_acl_rejections_total",
			Help: "Total number of requests rejected by IP ACL",
		},
		[]string{"path", "ip"},
	)

	// AntiInjectionBlocks 统计因检测到注入行为而阻止的请求数，按路径分类
	AntiInjectionBlocks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_anti_injection_blocks_total",
			Help: "Total number of requests blocked due to injection detection",
		},
		[]string{"path"},
	)

	// CacheHits 统计缓存命中的次数，按路径分类
	CacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_cache_hits_total",
			Help: "Total number of cache hits",
		},
		[]string{"method", "path", "taget"},
	)

	// CacheMisses 统计缓存未命中的次数，按路径分类
	CacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_cache_misses_total",
			Help: "Total number of cache misses",
		},
		[]string{"method", "path", "taget"},
	)

	// GRPCCallsTotal 跟踪处理的 gRPC 调用总数，按路径和状态分类
	GRPCCallsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_grpc_calls_total",
			Help: "Total number of gRPC calls processed by the gateway",
		},
		[]string{"path", "status"},
	)

	// MemoryAllocations 跟踪网关内存分配情况，按类型分类
	MemoryAllocations = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gateway_memory_allocations_bytes",
			Help: "Memory allocation in bytes by the gateway",
		},
		[]string{"type"}, // 类型可以是：heap, stack, system 等
	)

	// metricsInitialized 确保指标只初始化一次
	metricsInitialized bool
)

// InitMetrics 初始化所有 Prometheus 指标（如果尚未初始化）
func InitMetrics() {
	if metricsInitialized {
		return // 防止重复初始化
	}

	// 通过 promauto 在包级别自动注册指标，标记为已初始化
	metricsInitialized = true
}

// RegisterCustomCounter 注册自定义 Counter 指标
func RegisterCustomCounter(name, help string, labels []string) *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_" + name,
			Help: help,
		},
		labels,
	)
}

// RegisterCustomGauge 注册自定义 Gauge 指标
func RegisterCustomGauge(name, help string) prometheus.Gauge {
	return promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_" + name,
			Help: help,
		},
	)
}

// RegisterCustomHistogram 注册自定义 Histogram 指标
func RegisterCustomHistogram(name, help string, labels []string, buckets []float64) *prometheus.HistogramVec {
	if buckets == nil {
		buckets = prometheus.DefBuckets // 未指定时使用默认桶
	}
	return promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_" + name,
			Help:    help,
			Buckets: buckets,
		},
		labels,
	)
}

// ResetMetrics 重置所有指标到初始状态（用于测试或特殊场景）
func ResetMetrics() {
	RequestsTotal.Reset()
	RequestDuration.Reset()
	RateLimitRejections.Reset()
	BreakerTrips.Reset()
	ActiveWebSocketConnections.Set(0)
	JwtAuthFailures.Reset()
	IPAclRejections.Reset()
	AntiInjectionBlocks.Reset()
	CacheHits.Reset()
	CacheMisses.Reset()
	GRPCCallsTotal.Reset()
	MemoryAllocations.Reset() // 重置内存分配指标
}
