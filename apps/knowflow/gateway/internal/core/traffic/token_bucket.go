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
	uberRatelimit "go.uber.org/ratelimit"
	"go.uber.org/zap"
)

var tokenBucketTracer = otel.Tracer("ratelimit:token-bucket")

// MultiDimensionalTokenBucket 管理多维度限流
type MultiDimensionalTokenBucket struct {
	globalLimiter *TokenBucketLimiter
	ipLimiters    sync.Map // map[string]*TokenBucketLimiter
	routeLimiters sync.Map // map[string]*TokenBucketLimiter
	config        *config.Config
	mutex         sync.Mutex
}

type TokenBucketLimiter struct {
	limiter uberRatelimit.Limiter
}

func NewMultiDimensionalTokenBucket(cfg *config.Config) *MultiDimensionalTokenBucket {
	mdt := &MultiDimensionalTokenBucket{
		config: cfg,
	}

	if cfg.Traffic.RateLimit.Enabled {
		mdt.globalLimiter = NewTokenBucketLimiter(cfg.Traffic.RateLimit.QPS, cfg.Traffic.RateLimit.Burst)
	}

	return mdt
}

func NewTokenBucketLimiter(qps, burst int) *TokenBucketLimiter {
	l := &TokenBucketLimiter{
		limiter: uberRatelimit.New(qps, uberRatelimit.WithSlack(burst)),
	}
	logger.Info("TokenBucketLimiter initialized",
		zap.Int("qps", qps),
		zap.Int("burst", burst))
	return l
}

func (tbl *TokenBucketLimiter) Take() time.Time {
	return tbl.limiter.Take()
}

func (mdt *MultiDimensionalTokenBucket) getOrCreateLimiter(dimension, key string, qps, burst int) *TokenBucketLimiter {
	var limiterMap *sync.Map
	if dimension == "ip" {
		limiterMap = &mdt.ipLimiters
	} else if dimension == "route" {
		limiterMap = &mdt.routeLimiters
	}

	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*TokenBucketLimiter)
	}

	mdt.mutex.Lock()
	defer mdt.mutex.Unlock()

	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*TokenBucketLimiter)
	}

	limiter := NewTokenBucketLimiter(qps, burst)
	limiterMap.Store(key, limiter)
	return limiter
}

func TokenBucketRateLimit() gin.HandlerFunc {
	cfg := config.GetConfig()
	mdt := NewMultiDimensionalTokenBucket(cfg)

	return func(c *gin.Context) {
		if !cfg.Traffic.RateLimit.Enabled {
			c.Next()
			return
		}

		_, span := tokenBucketTracer.Start(c.Request.Context(), "RateLimit.TokenBucket",
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		// 检查全局限流
		if mdt.globalLimiter != nil {
			if !checkLimit(mdt.globalLimiter, c, span, "global", "") {
				return
			}
		}

		// 检查IP限流
		clientIP := c.ClientIP()
		ipQPS := cfg.Traffic.RateLimit.QPS / 2
		ipBurst := cfg.Traffic.RateLimit.Burst / 2
		ipLimiter := mdt.getOrCreateLimiter("ip", clientIP, ipQPS, ipBurst)
		if !checkLimit(ipLimiter, c, span, "ip", clientIP) {
			return
		}

		// 检查路由限流
		route := c.Request.URL.Path
		routeQPS := cfg.Traffic.RateLimit.QPS
		routeBurst := cfg.Traffic.RateLimit.Burst
		routeLimiter := mdt.getOrCreateLimiter("route", route, routeQPS, routeBurst)
		if !checkLimit(routeLimiter, c, span, "route", route) {
			return
		}

		span.SetStatus(codes.Ok, "Request allowed by token bucket")
		c.Next()
	}
}

func checkLimit(limiter *TokenBucketLimiter, c *gin.Context, span trace.Span, dimension, key string) bool {
	now := time.Now()
	takeTime := limiter.Take()
	waitDuration := takeTime.Sub(now)

	if waitDuration > 0 {
		logger.Warn("Rate limit exceeded with token bucket",
			zap.String("dimension", dimension),
			zap.String("key", key),
			zap.String("clientIP", c.ClientIP()),
			zap.String("path", c.Request.URL.Path),
			zap.Duration("waitDuration", waitDuration))
		span.SetStatus(codes.Error, "Rate limit exceeded")
		observability.RateLimitRejections.WithLabelValues(c.Request.URL.Path).Inc()

		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":      "Request rate limit exceeded",
			"dimension":  dimension,
			"key":        key,
			"waitTimeMs": waitDuration.Milliseconds(),
		})
		c.Abort()
		return false
	}
	return true
}
