package middleware

import (
	"bytes"
	"net/http"

	"github.com/DoraZa/mini-gateway/internal/core/observability"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/health" // 引入 health 包
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func CacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.GetConfig().Caching.Enabled {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		method := c.Request.Method
		rule := config.GetConfig().GetCacheRuleByPath(path)

		if rule == nil || rule.Method != method {
			c.Next()
			return
		}

		// 获取目标主机（假设从路由规则中提取第一个目标）
		target := ""
		if rules, ok := config.GetConfig().Routing.Rules[path]; ok && len(rules) > 0 {
			host, err := health.NormalizeTarget(rules[0])
			if err == nil {
				target = host
			}
		}

		// 增加请求计数并检查阈值
		count := health.GetGlobalHealthChecker().IncrementRequestCount(c.Request.Context(), path, rule.TTL)
		logger.Debug("Request count", zap.String("path", path), zap.Int64("count", count))

		// 检查缓存
		if content, found := health.GetGlobalHealthChecker().CheckCache(c.Request.Context(), method, path, target); found {
			observability.CacheHits.WithLabelValues(method, path, target).Inc()
			c.String(http.StatusOK, content)
			c.Abort()
			return
		}

		if count < int64(rule.Threshold) {
			c.Next()
			return
		}

		// 捕获响应并缓存
		writer := &responseWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		c.Next()

		observability.CacheMisses.WithLabelValues(method, path, target).Inc()
		if c.Writer.Status() == http.StatusOK {
			content := writer.body.String()
			err := health.GetGlobalHealthChecker().SetCache(c.Request.Context(), method, path, content, rule.TTL)
			if err != nil {
				logger.Error("Failed to cache response", zap.Error(err))
			}
		}
	}
}

// responseWriter 用于捕获响应内容
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.body == nil {
		w.body = bytes.NewBuffer(nil)
	}
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}
