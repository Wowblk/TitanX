package traffic

import (
	"net/http"
	"sync"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/observability"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var leakyBucketTracer = otel.Tracer("ratelimit:leaky-bucket")

// MultiDimensionalLeakyBucket 管理多维度限流
type MultiDimensionalLeakyBucket struct {
	globalLimiter *LeakyBucketLimiter
	ipLimiters    sync.Map // map[string]*LeakyBucketLimiter
	routeLimiters sync.Map // map[string]*LeakyBucketLimiter
	config        *config.Config
	mutex         sync.Mutex
}

// LeakyBucketLimiter 实现漏桶限流器
type LeakyBucketLimiter struct {
	capacity int           // 桶容量（突发限制）
	rate     float64       // 漏出速率（每秒请求数，QPS）
	queue    chan struct{} // 表示桶队列的通道
	mutex    sync.Mutex    // 确保队列操作的线程安全
	stopChan chan struct{} // 信号通道，用于停止漏出协程
}

func NewMultiDimensionalLeakyBucket(cfg *config.Config) *MultiDimensionalLeakyBucket {
	mdl := &MultiDimensionalLeakyBucket{
		config: cfg,
	}

	// 初始化全局限流器
	if cfg.Traffic.RateLimit.Enabled {
		mdl.globalLimiter = NewLeakyBucketLimiter(cfg.Traffic.RateLimit.QPS, cfg.Traffic.RateLimit.Burst)
	}

	return mdl
}

func NewLeakyBucketLimiter(qps, burst int) *LeakyBucketLimiter {
	l := &LeakyBucketLimiter{
		capacity: burst,
		rate:     float64(qps),
		queue:    make(chan struct{}, burst),
		stopChan: make(chan struct{}),
	}
	go l.startLeak()
	logger.Info("LeakyBucketLimiter initialized",
		zap.Int("qps", qps),
		zap.Int("burst", burst))
	return l
}

func (l *LeakyBucketLimiter) startLeak() {
	ticker := time.NewTicker(time.Second / time.Duration(l.rate))
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.mutex.Lock()
			if len(l.queue) > 0 {
				select {
				case <-l.queue:
				default:
				}
			}
			l.mutex.Unlock()
		case <-l.stopChan:
			logger.Info("LeakyBucketLimiter leak routine stopped")
			return
		}
	}
}

func (l *LeakyBucketLimiter) Allow() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	select {
	case l.queue <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *LeakyBucketLimiter) Stop() {
	close(l.stopChan)
}

// getOrCreateLimiter 获取或创建特定维度的限流器
func (mdl *MultiDimensionalLeakyBucket) getOrCreateLimiter(dimension, key string, qps, burst int) *LeakyBucketLimiter {
	var limiterMap *sync.Map
	if dimension == "ip" {
		limiterMap = &mdl.ipLimiters
	} else if dimension == "route" {
		limiterMap = &mdl.routeLimiters
	}

	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*LeakyBucketLimiter)
	}

	mdl.mutex.Lock()
	defer mdl.mutex.Unlock()

	// 双重检查
	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*LeakyBucketLimiter)
	}

	limiter := NewLeakyBucketLimiter(qps, burst)
	limiterMap.Store(key, limiter)
	return limiter
}

func LeakyBucketRateLimit() gin.HandlerFunc {
	cfg := config.GetConfig()
	mdl := NewMultiDimensionalLeakyBucket(cfg)

	return func(c *gin.Context) {
		if !cfg.Traffic.RateLimit.Enabled {
			c.Next()
			return
		}

		_, span := leakyBucketTracer.Start(c.Request.Context(), "RateLimit.LeakyBucket",
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		// 检查全局限流
		if mdl.globalLimiter != nil && !mdl.globalLimiter.Allow() {
			rejectRequest(c, span, "global", "", cfg.Traffic.RateLimit.QPS, cfg.Traffic.RateLimit.Burst)
			return
		}

		// 检查IP限流（这里假设配置中增加了IP限流规则）
		clientIP := c.ClientIP()
		ipQPS := cfg.Traffic.RateLimit.QPS / 2 // 示例：IP限流为全局的一半
		ipBurst := cfg.Traffic.RateLimit.Burst / 2
		ipLimiter := mdl.getOrCreateLimiter("ip", clientIP, ipQPS, ipBurst)
		if !ipLimiter.Allow() {
			rejectRequest(c, span, "ip", clientIP, ipQPS, ipBurst)
			return
		}

		// 检查路由限流（这里假设配置中增加了路由限流规则）
		route := c.Request.URL.Path
		routeQPS := cfg.Traffic.RateLimit.QPS // 示例：使用全局QPS
		routeBurst := cfg.Traffic.RateLimit.Burst
		routeLimiter := mdl.getOrCreateLimiter("route", route, routeQPS, routeBurst)
		if !routeLimiter.Allow() {
			rejectRequest(c, span, "route", route, routeQPS, routeBurst)
			return
		}

		span.SetStatus(codes.Ok, "Request allowed by leaky bucket")
		c.Next()
	}
}

func rejectRequest(c *gin.Context, span trace.Span, dimension, key string, qps, burst int) {
	logger.Warn("Rate limit exceeded with leaky bucket",
		zap.String("dimension", dimension),
		zap.String("key", key),
		zap.String("clientIP", c.ClientIP()),
		zap.String("path", c.Request.URL.Path),
		zap.Int("qps", qps),
		zap.Int("burst", burst))
	span.SetStatus(codes.Error, "Rate limit exceeded")
	observability.RateLimitRejections.WithLabelValues(c.Request.URL.Path).Inc()

	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":     "Request rate limit exceeded",
		"dimension": dimension,
		"key":       key,
		"qps":       qps,
		"burst":     burst,
	})
	c.Abort()
}

func CleanupLeakyBucket(mdl *MultiDimensionalLeakyBucket) {
	if mdl.globalLimiter != nil {
		mdl.globalLimiter.Stop()
	}
	mdl.ipLimiters.Range(func(key, value interface{}) bool {
		value.(*LeakyBucketLimiter).Stop()
		return true
	})
	mdl.routeLimiters.Range(func(key, value interface{}) bool {
		value.(*LeakyBucketLimiter).Stop()
		return true
	})
	logger.Info("MultiDimensionalLeakyBucket resources cleaned up")
}
