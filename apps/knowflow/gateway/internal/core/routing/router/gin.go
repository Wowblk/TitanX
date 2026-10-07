package router

import (
	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/routing/proxy"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// GinRouter 管理 Gin 框架的 HTTP 路由设置
type GinRouter struct {
}

// NewGinRouter 创建并初始化 GinRouter 实例
func NewGinRouter() *GinRouter {
	logger.Info("GinRouter initialized")
	return &GinRouter{}
}

// Setup 在提供的 Gin 路由器中配置 HTTP 路由规则
func (gr *GinRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	// 为每个路径注册路由规则
	for path, targetRules := range rules {
		logger.Info("Registering HTTP route",
			zap.String("path", path),
			zap.Any("targets", targetRules))

		r.Any(path, httpProxy.CreateHTTPHandler(targetRules))
	}
}
