package proxy

import (
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/DoraZa/mini-gateway/pkg/util"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/health"
	"github.com/DoraZa/mini-gateway/internal/core/loadbalancer"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	defaultEnv = "stable" // 默认环境
	canaryEnv  = "canary" // 金丝雀环境
)

// httpTracer 为 HTTP 代理初始化追踪器
var httpTracer = otel.Tracer("proxy:http")

// HTTPProxy 管理 HTTP 代理功能
type HTTPProxy struct {
	httpPool        *HTTPConnectionPool       // HTTP 连接池
	loadBalancer    loadbalancer.LoadBalancer // 负载均衡器
	objectPool      *util.ObjectPoolManager   // 对象池管理器
	httpPoolEnabled bool                      // 是否启用 HTTP 连接池

	selectTargetFunc  func(c *gin.Context, rules config.RoutingRules) (string, string)
	proxyWithPoolFunc func(c *gin.Context, target, env string)
}

// NewHTTPProxy 创建并初始化 HTTPProxy 实例
func NewHTTPProxy(cfg *config.Config) *HTTPProxy {
	lb := initializeLoadBalancer(cfg)
	logPoolStatus(cfg.Performance.HttpPoolEnabled)
	logGrayscaleStatus(cfg.Routing.Grayscale)

	return &HTTPProxy{
		httpPool:        NewHTTPConnectionPool(cfg),
		loadBalancer:    lb,
		objectPool:      util.NewPoolManager(cfg),
		httpPoolEnabled: cfg.Performance.HttpPoolEnabled,
	}
}

// logGrayscaleStatus 记录灰度发布配置状态
func logGrayscaleStatus(grayscale config.Grayscale) {
	logger.Info("Grayscale configuration status",
		zap.Bool("enabled", grayscale.Enabled),
		zap.Bool("weightedRandom", grayscale.WeightedRandom),
		zap.String("defaultEnv", grayscale.DefaultEnv),
		zap.String("canaryEnv", grayscale.CanaryEnv))
}

func (hp *HTTPProxy) GetLoadBalancerType() string {
	if hp == nil || hp.loadBalancer == nil {
		return ""
	}
	return hp.loadBalancer.Type()
}

// RefreshLoadBalancer 刷新负载均衡器
func (hp *HTTPProxy) RefreshLoadBalancer(cfg *config.Config) {
	hp.loadBalancer = initializeLoadBalancer(cfg)
	logger.Info("HTTPProxy load balancer refreshed",
		zap.String("loadBalancerType", cfg.Routing.LoadBalancer))
}

// SetupHTTPProxy 配置 HTTP 代理路由
func (hp *HTTPProxy) SetupHTTPProxy(r gin.IRouter, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	for path, targetRules := range rules {
		logger.Info("Configuring HTTP proxy route",
			zap.String("path", path),
			zap.Any("targets", targetRules))
		r.Any(path, hp.CreateHTTPHandler(targetRules))
	}
}

// CreateHTTPHandler 创建 HTTP 请求处理函数
func (hp *HTTPProxy) CreateHTTPHandler(rules config.RoutingRules) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.Handle",
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.path", c.Request.URL.Path),
			))
		defer span.End()

		c.Request = c.Request.WithContext(ctx)
		target, selectedEnv := hp.getSelectTarget(c, rules)
		if target == "" {
			handleNoTarget(c, span, c.Request.URL.Path, getEnvFromHeader(c))
			return
		}

		span.SetAttributes(attribute.String("proxy.target", target))
		if hp.httpPoolEnabled {
			hp.getProxyWithPool(c, target, selectedEnv)
		} else {
			hp.proxyDirect(c, target, selectedEnv)
		}
	}
}

// proxyDirect 使用直接代理方式转发请求
func (hp *HTTPProxy) proxyDirect(c *gin.Context, target, env string) {
	_, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.Handle.Direct",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	targetURL, err := url.Parse(target)
	if err != nil {
		handleProxyError(c, span, target, "Invalid target URL", err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = hp.createDirector(targetURL, env)
	proxy.ErrorHandler = hp.createErrorHandler(target, span)

	logger.Info("Routing HTTP request",
		zap.String("path", c.Request.URL.Path),
		zap.String("target", target),
		zap.String("env", env),
		zap.String("method", c.Request.Method))

	// 包装 c.Writer，使其满足 http.CloseNotifier 接口要求
	wrappedWriter := &closeNotifyResponseWriter{c.Writer}
	proxy.ServeHTTP(wrappedWriter, c.Request)
	span.SetStatus(codes.Ok, "HTTP proxy completed successfully")
	health.GetGlobalHealthChecker().UpdateRequestCount(target, true)
}

// proxyWithPool 使用连接池代理转发请求
func (hp *HTTPProxy) proxyWithPool(c *gin.Context, target, env string) {
	_, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.Handle.Pool",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	client, err := hp.httpPool.GetClient(target)
	if err != nil {
		handleProxyError(c, span, target, "Failed to get HTTP client", err)
		return
	}
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	hp.prepareFastHTTPRequest(c, req, target, env)

	if err := client.Do(req, resp); err != nil {
		handleProxyError(c, span, target, "Backend service unavailable", err)
		return
	}

	hp.writeFastHTTPResponse(c, resp)
	span.SetStatus(codes.Ok, "HTTP proxy completed successfully")
	health.GetGlobalHealthChecker().UpdateRequestCount(target, true)
}

// initializeLoadBalancer 初始化负载均衡器
func initializeLoadBalancer(cfg *config.Config) loadbalancer.LoadBalancer {
	lb, err := loadbalancer.NewLoadBalancer(cfg.Routing.LoadBalancer, cfg)
	if err != nil {
		logger.Error("Failed to initialize load balancer",
			zap.Error(err))
		return loadbalancer.NewRoundRobin()
	}
	return lb
}

// logPoolStatus 记录连接池状态
func logPoolStatus(enabled bool) {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	logger.Info("HTTP TCP connection pool status",
		zap.String("status", status))
}

// getEnvFromHeader 从请求头中获取环境信息
func getEnvFromHeader(c *gin.Context) string {
	if env := c.GetHeader("X-Env"); env != "" {
		return env
	}
	return defaultEnv
}

// filterRules 根据环境过滤路由规则
func (hp *HTTPProxy) filterRules(rules config.RoutingRules, env string) config.RoutingRules {
	filtered := hp.objectPool.GetRules(len(rules))
	if env == canaryEnv {
		for _, rule := range rules {
			if rule.Env == canaryEnv {
				filtered = append(filtered, rule)
			}
		}
		if len(filtered) == 0 {
			logger.Warn("No canary targets available, falling back to all rules",
				zap.String("path", rules[0].Target)) // 假设 rules 不为空
			return rules
		}
		return filtered
	}
	return append(filtered, rules...)
}

// extractTargets 从规则中提取目标列表
func (hp *HTTPProxy) extractTargets(rules config.RoutingRules) []string {
	targets := hp.objectPool.GetTargets(len(rules))
	for _, rule := range rules {
		targets = append(targets, rule.Target)
	}
	return targets
}

// selectTarget 选择目标并返回目标和环境
func (hp *HTTPProxy) selectTarget(c *gin.Context, rules config.RoutingRules) (string, string) {
	ctx, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.selectTarget",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	c.Request = c.Request.WithContext(ctx)
	cfg := config.GetConfig()
	grayscale := cfg.Routing.Grayscale
	if !grayscale.Enabled {
		return hp.selectWithLoadBalancer(c, rules)
	}

	// 灰度发布启用时的逻辑
	env := getEnvFromHeader(c)
	targetRules := hp.filterRulesWithFallback(rules, env, grayscale)
	defer hp.objectPool.PutRules(targetRules)

	targets := hp.extractTargets(targetRules)
	defer hp.objectPool.PutTargets(targets)

	if grayscale.Enabled && grayscale.WeightedRandom && len(targetRules) > 1 {
		return hp.selectWithWeightedRandom(targetRules, c.Request.URL.Path)
	}
	return hp.selectWithLoadBalancer(c, targetRules, targetRules[0].Env)
}

// selectWithWeightedRandom 使用权重随机选择目标
func (hp *HTTPProxy) selectWithWeightedRandom(rules config.RoutingRules, path string) (string, string) {
	selectedRule := WeightedRandomSelect(rules)
	if selectedRule == nil {
		logger.Warn("Weighted random selection failed, using first rule",
			zap.String("path", path))
		return rules[0].Target, rules[0].Env
	}
	logger.Info("Target selected via weighted random",
		zap.String("path", path),
		zap.String("target", selectedRule.Target),
		zap.String("env", selectedRule.Env),
		zap.Int("weight", selectedRule.Weight))
	return selectedRule.Target, selectedRule.Env
}

// selectWithLoadBalancer 使用负载均衡器选择目标
func (hp *HTTPProxy) selectWithLoadBalancer(c *gin.Context, rules config.RoutingRules, envOverride ...string) (string, string) {
	ctx, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.selectWithLoadBalancer",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	var targets []string

	targets = hp.extractTargets(rules)
	defer hp.objectPool.PutTargets(targets)

	c.Request = c.Request.WithContext(ctx)

	target := hp.loadBalancer.SelectTarget(targets, c.Request)
	if target == "" {
		return "", ""
	}

	selectedEnv := defaultEnv
	if len(envOverride) > 0 {
		selectedEnv = envOverride[0]
	} else {
		for _, rule := range rules {
			if rule.Target == target {
				selectedEnv = rule.Env
				break
			}
		}
	}

	logger.Info("Target selected via load balancer",
		zap.String("path", c.Request.URL.Path),
		zap.String("target", target),
		zap.String("env", selectedEnv))
	return target, selectedEnv
}

// filterRulesWithFallback 根据环境过滤规则，并提供回退逻辑
func (hp *HTTPProxy) filterRulesWithFallback(rules config.RoutingRules, env string, grayscale config.Grayscale) config.RoutingRules {
	filtered := hp.filterRules(rules, env)
	if len(filtered) == 0 && env == grayscale.CanaryEnv {
		logger.Warn("No canary targets available, falling back to default env",
			zap.String("path", rules[0].Target)) // 假设 rules 不为空
		return hp.filterRules(rules, grayscale.DefaultEnv)
	}
	return filtered
}

// handleNoTarget 处理无可用目标的情况
func handleNoTarget(c *gin.Context, span trace.Span, path, env string) {
	span.SetStatus(codes.Error, "No available target")
	logger.Warn("No target available for request",
		zap.String("path", path),
		zap.String("env", env))
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "No available target"})
}

// handleProxyError 处理代理错误
func handleProxyError(c *gin.Context, span trace.Span, target, msg string, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, "Proxy error")
	health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
	logger.Error("HTTP proxy request failed",
		zap.String("target", target),
		zap.String("message", msg),
		zap.Error(err))
	c.JSON(http.StatusBadGateway, gin.H{"error": msg})
}

// createDirector 创建代理请求的 Director 函数
func (hp *HTTPProxy) createDirector(targetURL *url.URL, env string) func(*http.Request) {
	return func(req *http.Request) {
		defaultDirector(targetURL)(req)
		if env == canaryEnv {
			req.Header.Set("X-Env", canaryEnv)
		}
	}
}

// createErrorHandler 创建代理错误处理函数
func (hp *HTTPProxy) createErrorHandler(target string, span trace.Span) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Proxy error")
		health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
		logger.Error("HTTP proxy request failed",
			zap.String("path", r.URL.Path),
			zap.String("target", target),
			zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Bad Gateway"))
	}
}

// prepareFastHTTPRequest 准备 FastHTTP 请求
func (hp *HTTPProxy) prepareFastHTTPRequest(c *gin.Context, req *fasthttp.Request, target, env string) {
	targetHost, err := normalizeTarget(target)
	if err != nil {
		targetHost = target
	}
	scheme := "http"
	if targetURL, err := url.Parse(target); err == nil && targetURL.Scheme != "" {
		scheme = targetURL.Scheme
	}
	reqURI := scheme + "://" + targetHost + c.Request.URL.Path
	if c.Request.URL.RawQuery != "" {
		reqURI += "?" + c.Request.URL.RawQuery
	}
	req.SetRequestURI(reqURI)
	req.Header.SetMethod(c.Request.Method)

	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if env == canaryEnv {
		req.Header.Set("X-Env", canaryEnv)
	}
	if c.Request.Body != nil {
		if body, err := c.GetRawData(); err == nil {
			req.SetBody(body)
		}
	}
}

// writeFastHTTPResponse 写入 FastHTTP 响应
func (hp *HTTPProxy) writeFastHTTPResponse(c *gin.Context, resp *fasthttp.Response) {
	c.Status(resp.StatusCode())
	resp.Header.VisitAll(func(key, value []byte) {
		c.Header(string(key), string(value))
	})
	c.Writer.Write(resp.Body())
}

// defaultDirector 创建默认的代理请求 Director 函数，用于将请求转发到目标 URL
func defaultDirector(targetURL *url.URL) func(req *http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme                               // 设置目标协议
		req.URL.Host = targetURL.Host                                   // 设置目标主机
		req.URL.Path = SingleJoiningSlash(targetURL.Path, req.URL.Path) // 合并路径
		req.Host = targetURL.Host                                       // 设置 Host 头
		forwardedURL := req.URL.String()                                // 获取完整转发 URL
		logger.Debug("Forwarding proxy request",
			zap.String("originalPath", req.URL.Path),
			zap.String("forwardedURL", forwardedURL),
		)
	}
}

// SingleJoiningSlash 合并两个路径段，确保它们之间恰好有一个斜杠
func SingleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/") // 检查 a 是否以斜杠结尾
	bslash := strings.HasPrefix(b, "/") // 检查 b 是否以斜杠开头
	switch {
	case aslash && bslash:
		// 如果 a 已带斜杠且 b 以斜杠开头，移除 b 的前导斜杠
		return a + b[1:]
	case !aslash && !bslash:
		// 如果两者均无斜杠，添加一个斜杠
		return a + "/" + b
	}
	// 如果两者之间已有一个斜杠，直接拼接
	return a + b
}

// WeightedRandomSelect 根据权重随机选择一个路由规则
func WeightedRandomSelect(rules config.RoutingRules) *config.RoutingRule {
	if len(rules) == 0 {
		return nil
	}
	if len(rules) == 1 {
		return &rules[0]
	}

	// 计算总权重
	totalWeight := 0
	for _, rule := range rules {
		totalWeight += rule.Weight
	}

	// 随机选择
	rand.Seed(time.Now().UnixNano()) // 初始化随机种子
	randomWeight := rand.Intn(totalWeight)

	// 根据权重区间选择目标
	cumulativeWeight := 0
	for i, rule := range rules {
		cumulativeWeight += rule.Weight
		if randomWeight < cumulativeWeight {
			return &rules[i]
		}
	}
	return &rules[len(rules)-1] // 兜底
}

// 辅助方法：根据是否注入了自定义逻辑来选择目标
func (hp *HTTPProxy) getSelectTarget(c *gin.Context, rules config.RoutingRules) (string, string) {
	if hp.selectTargetFunc != nil {
		return hp.selectTargetFunc(c, rules)
	}
	return hp.selectTarget(c, rules)
}

// 辅助方法：根据是否注入了自定义逻辑来执行连接池代理
func (hp *HTTPProxy) getProxyWithPool(c *gin.Context, target, env string) {
	if hp.proxyWithPoolFunc != nil {
		hp.proxyWithPoolFunc(c, target, env)
	} else {
		hp.proxyWithPool(c, target, env)
	}
}

// closeNotifyResponseWriter 包装了 gin.ResponseWriter，并实现 http.CloseNotifier 接口
type closeNotifyResponseWriter struct {
	gin.ResponseWriter
}

func (w *closeNotifyResponseWriter) CloseNotify() <-chan bool {
	// 返回一个空通道即可，不会被使用到
	return make(chan bool)
}
