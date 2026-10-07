package traffic

import (
	"testing"
	"time"

	"github.com/DoraZa/mini-gateway/pkg/logger"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func initTest() {
	// 初始化日志和配置
	gin.SetMode(gin.TestMode)
	logger.InitTestLogger()
	config.InitTestConfigManager()
	newLeakyTestConfig()
}

func newLeakyTestConfig() *config.Config {
	return &config.Config{
		Traffic: config.Traffic{
			RateLimit: config.TrafficRateLimit{
				Enabled:   true,
				QPS:       10,
				Burst:     20,
				Algorithm: "leaky_bucket",
				IPLimits: map[string]config.TrafficRateLimit{
					"192.168.1.1": {QPS: 5, Burst: 10, Enabled: true},
				},
				RouteLimits: map[string]config.TrafficRateLimit{
					"/api/v1/user": {QPS: 8, Burst: 15, Enabled: true},
				},
			},
		},
	}
}

func TestLeakyBucketLimiter(t *testing.T) {
	initTest()
	limiter := NewLeakyBucketLimiter(10, 20)
	defer limiter.Stop()

	// 测试初始容量
	for i := 0; i < 20; i++ {
		assert.True(t, limiter.Allow(), "Should allow request within capacity")
	}
	assert.False(t, limiter.Allow(), "Should reject when capacity exceeded")

	// 等待漏出
	time.Sleep(150 * time.Millisecond) // 10 QPS -> 100ms per request
	assert.True(t, limiter.Allow(), "Should allow after leak")
}

func TestMultiDimensionalLeakyBucket_Global(t *testing.T) {
	initTest()

	mdl := NewMultiDimensionalLeakyBucket(config.GetConfig())
	defer CleanupLeakyBucket(mdl)

	for i := 0; i < 20; i++ {
		assert.True(t, mdl.globalLimiter.Allow(), "Global limiter should allow within burst")
	}
	assert.False(t, mdl.globalLimiter.Allow(), "Global limiter should reject when burst exceeded")
}

func TestMultiDimensionalLeakyBucket_IP(t *testing.T) {
	initTest()

	mdl := NewMultiDimensionalLeakyBucket(config.GetConfig())
	defer CleanupLeakyBucket(mdl)

	ipLimiter := mdl.getOrCreateLimiter("ip", "192.168.1.1", 5, 10)
	for i := 0; i < 10; i++ {
		assert.True(t, ipLimiter.Allow(), "IP limiter should allow within burst")
	}
	assert.False(t, ipLimiter.Allow(), "IP limiter should reject when burst exceeded")
}

func TestMultiDimensionalLeakyBucket_Route(t *testing.T) {
	initTest()
	mdl := NewMultiDimensionalLeakyBucket(config.GetConfig())
	defer CleanupLeakyBucket(mdl)

	routeLimiter := mdl.getOrCreateLimiter("route", "/api/v1/user", 8, 15)
	for i := 0; i < 15; i++ {
		assert.True(t, routeLimiter.Allow(), "Route limiter should allow within burst")
	}
	assert.False(t, routeLimiter.Allow(), "Route limiter should reject when burst exceeded")
}
