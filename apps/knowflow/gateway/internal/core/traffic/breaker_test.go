package traffic

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// newBreakerTestConfig 创建用于测试熔断器的配置
func newBreakerTestConfig() *config.Config {
	// 根据实际项目中 config.Config 的定义调整各字段
	return &config.Config{
		Middleware: config.Middleware{Breaker: true},
		Traffic: config.Traffic{
			Breaker: config.TrafficBreaker{
				Enabled:        true,
				Timeout:        1000, // 毫秒
				MaxConcurrent:  10,
				MinRequests:    5,
				SleepWindow:    5000, // 毫秒
				ErrorRate:      0.5,  // 50%
				WindowDuration: 2,    // 秒
			},
		},
		Routing: config.Routing{
			Rules: map[string]config.RoutingRules{
				"/test": nil,
			},
		},
	}
}

// initBreakerTestConfig 初始化测试配置
func initBreakerTestConfig() {
	// 如果 config 包没有 SetConfig 方法，请确保在测试中能够正确设置全局配置
	config.SetConfig(newBreakerTestConfig())
}

//
// TimeSlidingWindow 测试
//

// TestTimeSlidingWindow_ErrorRate 验证错误率与平均延迟计算
func TestTimeSlidingWindow_ErrorRate(t *testing.T) {
	window := NewTimeSlidingWindow(2 * time.Second)
	// 模拟 4 个请求，其中 2 个失败、2 个成功
	now := time.Now()
	window.Update(RequestStat{Success: true, Latency: 100 * time.Millisecond, Timestamp: now})
	window.Update(RequestStat{Success: false, Latency: 200 * time.Millisecond, Timestamp: now})
	window.Update(RequestStat{Success: true, Latency: 150 * time.Millisecond, Timestamp: now})
	window.Update(RequestStat{Success: false, Latency: 250 * time.Millisecond, Timestamp: now})

	errorRate := window.ErrorRate()
	assert.Equal(t, 0.5, errorRate, "错误率应为 50%%")

	avgLatency := window.AvgLatency()
	expectedLatency := (100*time.Millisecond + 200*time.Millisecond + 150*time.Millisecond + 250*time.Millisecond) / 4
	assert.Equal(t, expectedLatency, avgLatency, "平均延迟应计算正确")
}

// TestTimeSlidingWindow_Cleanup 验证过期统计数据被清理
func TestTimeSlidingWindow_Cleanup(t *testing.T) {
	// 使用 2 秒窗口，便于测试：过期记录为 3 秒前，近期记录为当前时间
	window := NewTimeSlidingWindow(2 * time.Second)
	now := time.Now()
	// 添加一个过期的请求统计（3 秒前）
	window.Update(RequestStat{Success: true, Latency: 100 * time.Millisecond, Timestamp: now.Add(-3 * time.Second)})
	// 添加一个近期的请求统计（当前）
	window.Update(RequestStat{Success: false, Latency: 200 * time.Millisecond, Timestamp: now})
	// 等待 2 秒让后台清理协程运行
	time.Sleep(2 * time.Second)
	// 此时窗口内仅应保留近期记录，错误率为 1（即失败率 100%）
	errorRate := window.ErrorRate()
	assert.Equal(t, 1.0, errorRate, "清理后错误率应反映仅近期失败请求")
}

//
// Breaker 中间件测试
//

// TestBreakerMiddleware_Success 模拟成功处理场景
func TestBreakerMiddleware_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initBreakerTestConfig()

	router := gin.New()
	router.Use(Breaker())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "成功请求应返回 200")
	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	assert.NoError(t, err, "返回的 JSON 应合法")
	assert.Equal(t, "success", body["message"], "返回信息应为 'success'")
}

// TestBreakerMiddleware_Fallback 模拟触发熔断时的回退逻辑
func TestBreakerMiddleware_Fallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initBreakerTestConfig()

	// 为测试目的，配置一个较短超时的 Hystrix 命令，便于触发回退
	hystrix.ConfigureCommand("/test", hystrix.CommandConfig{
		Timeout:                100, // 100ms 超时
		MaxConcurrentRequests:  1,
		RequestVolumeThreshold: 1,
		SleepWindow:            500,
		ErrorPercentThreshold:  1,
	})

	router := gin.New()
	router.Use(Breaker())
	// 模拟处理过程中返回错误
	router.GET("/test", func(c *gin.Context) {
		c.AbortWithError(http.StatusInternalServerError, errors.New("test error"))
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 当熔断触发时，回退逻辑应返回 503
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "熔断回退应返回 503")
	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	assert.NoError(t, err, "返回的 JSON 应合法")
	assert.Equal(t, "Service temporarily unavailable", body["error"], "回退返回的错误信息应正确")
}
