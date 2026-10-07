package router

import (
	"context"
	"net/http"
	"regexp"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/routing/proxy"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// regexpTracer 为正则路由模块初始化追踪器
var regexpTracer = otel.Tracer("router:regexp")

// RegexpRouter 使用正则表达式和负载均衡处理路由逻辑
type RegexpRouter struct {
	rules map[string]*regexp.Regexp // 路径到正则表达式的映射
	cfg   *config.Config            // 存储配置以访问路由规则
}

// NewRegexpRouter 根据配置创建并初始化 RegexpRouter 实例
func NewRegexpRouter(cfg *config.Config) *RegexpRouter {
	router := &RegexpRouter{
		rules: make(map[string]*regexp.Regexp),
		cfg:   cfg,
	}
	return router
}

// registerRule 编译并注册单个路由规则
func (rr *RegexpRouter) registerRule(path string) {
	pattern := "^" + path + "$" // 为精确匹配添加锚点
	re, err := regexp.Compile(pattern)
	if err != nil {
		logger.Error("Failed to compile regular expression for route",
			zap.String("path", path),
			zap.Error(err))
		return
	}
	rr.rules[path] = re
	logger.Info("Successfully registered route in RegexpRouter",
		zap.String("path", path),
		zap.Any("targets", rr.cfg.Routing.Rules[path]))
}

// Match 查找与给定路径匹配的路由规则
func (rr *RegexpRouter) Match(ctx context.Context, path string) (config.RoutingRules, bool) {
	ctx, span := trieRegexpTracer.Start(ctx, "RegexpRouter.Match",
		trace.WithAttributes(attribute.String("path", path)))
	defer span.End()

	for pattern, re := range rr.rules {
		if re.MatchString(path) {
			return rr.cfg.Routing.Rules[pattern], true
		}
	}
	return nil, false
}

// Setup 根据配置在 Gin 路由器中设置 HTTP 路由规则
func (rr *RegexpRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	// 初始化时注册路由规则
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}
	for path := range rules {
		rr.registerRule(path)
	}

	// 中间件：处理路由匹配和代理转发
	r.Use(func(c *gin.Context) {
		ctx, span := regexpTracer.Start(c.Request.Context(), "Routing.Match",
			trace.WithAttributes(attribute.String("type", "Regexp")),
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		path := c.Request.URL.Path
		targetRules, found := rr.Match(ctx, path)

		if !found {
			logger.Warn("No matching route found",
				zap.String("path", path),
				zap.String("method", c.Request.Method))
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
			c.Abort()
			span.SetStatus(codes.Error, "Route not found")
			return
		}

		span.SetAttributes(attribute.String("matched_target", targetRules[0].Target))
		span.SetStatus(codes.Ok, "Route matched successfully")
		logger.Info("Successfully matched route",
			zap.String("path", path),
			zap.Any("rules", targetRules))

		c.Request = c.Request.WithContext(ctx)
		httpProxy.CreateHTTPHandler(targetRules)(c)
	})
}
