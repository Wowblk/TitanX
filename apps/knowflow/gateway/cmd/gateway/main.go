package main

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof" // 导入 pprof 包
	"os"
	"os/signal"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/samber/lo"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/health"
	"github.com/DoraZa/mini-gateway/internal/core/loadbalancer"
	"github.com/DoraZa/mini-gateway/internal/core/observability"
	"github.com/DoraZa/mini-gateway/internal/core/routing"
	"github.com/DoraZa/mini-gateway/internal/core/routing/proxy"
	"github.com/DoraZa/mini-gateway/internal/core/security"
	"github.com/DoraZa/mini-gateway/internal/core/traffic"
	"github.com/DoraZa/mini-gateway/internal/middleware"
	"github.com/DoraZa/mini-gateway/internal/middleware/auth"
	"github.com/DoraZa/mini-gateway/pkg/cache"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/DoraZa/mini-gateway/plugins"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	Version   string // 版本号
	BuildTime string // 构建时间
	GitCommit string // Git 提交哈希
	GoVersion string // Go 版本

	startTime = time.Now() // 程序启动时间
	server    *Server      // 全局 Server 实例
)

func main() {
	configMgr := config.InitConfig() // 初始化配置管理器
	server = initServer(configMgr)   // 初始化服务

	go refreshConfig(server, configMgr) // 启动配置刷新监听协程
	server.start()                      // 启动服务
}

// Server 结构体封装服务相关组件
type Server struct {
	Router         *gin.Engine                 // Gin 路由引擎
	ConfigMgr      *config.ConfigManager       // 配置管理器
	TracingCleanup func(context.Context) error // 分布式追踪清理函数
	LoadBalancer   loadbalancer.LoadBalancer   // 负载均衡器
	HTTPProxy      *proxy.HTTPProxy            // HTTP 代理
}

// initServer 初始化服务实例
func initServer(configMgr *config.ConfigManager) *Server {
	cfg := configMgr.GetConfig() // 获取当前配置
	// 初始化日志
	logger.Init(logger.Config{
		Level:      cfg.Logger.Level,
		FilePath:   cfg.Logger.FilePath,
		MaxSize:    cfg.Logger.MaxSize,
		MaxBackups: cfg.Logger.MaxBackups,
		MaxAge:     cfg.Logger.MaxAge,
		Compress:   cfg.Logger.Compress,
	})

	validateConfig(cfg)           // 验证配置有效性
	cache.Init(cfg)               // 初始化缓存
	observability.InitMetrics()   // 初始化监控指标
	health.InitHealthChecker(cfg) // 初始化健康检查

	s := &Server{
		Router:    setupGinRouter(cfg), // 设置 Gin 路由器
		ConfigMgr: configMgr,
	}

	// 如果启用了 RBAC 认证，则初始化 RBAC
	if cfg.Security.AuthMode == "rbac" && cfg.Security.RBAC.Enabled {
		security.InitRBAC(cfg)
	}
	s.setupMiddleware(cfg) // 配置中间件
	s.setupHTTPProxy(cfg)  // 配置 HTTP 代理
	s.setupRoutes(cfg)     // 配置路由

	return s
}

// setupRoutes 配置所有路由，简洁调用独立处理函数
func (s *Server) setupRoutes(cfg *config.Config) {
	// 基本路由
	s.Router.GET("/health", s.handleHealth) // 健康检查路由
	s.Router.GET("/status", s.handleStatus) // 状态检查路由
	s.Router.POST("/login", s.handleLogin)  // 登录路由

	// 添加 pprof 调试路由
	if cfg.Server.PprofEnabled { // 假设在 config 中添加了 PprofEnabled 字段
		s.Router.GET("/debug/pprof/*profile", gin.WrapH(http.DefaultServeMux))
		logger.Info("pprof endpoints enabled at /debug/pprof")
	}

	// 添加关闭熔断器的 API
	s.Router.POST("/breaker/disable", traffic.DisableBreakerHandler)

	// Prometheus 监控路由
	if cfg.Observability.Prometheus.Enabled {
		s.Router.GET(cfg.Observability.Prometheus.Path, gin.WrapH(promhttp.Handler()))
	}

	// 文件服务路由
	fileServerRouter := routing.NewFileServerRouter(cfg)
	fileServerRouter.Setup(s.Router, cfg)

	// 路由管理 API
	routeGroup := s.Router.Group("/api/routes")
	{
		routeGroup.POST("/add", s.handleAddRoute)         // 添加路由
		routeGroup.PUT("/update", s.handleUpdateRoute)    // 更新路由
		routeGroup.DELETE("/delete", s.handleDeleteRoute) // 删除路由
		routeGroup.GET("/list", s.handleListRoutes)       // 列出所有路由
	}

	// 保存配置 API
	s.Router.POST("/api/config/save", s.handleSaveConfig)

	// 动态路由
	logger.Info("设置动态路由", zap.Any("routing_rules", cfg.Routing.Rules))
	protected := s.Router.Group("/")
	if cfg.Middleware.Auth {
		protected.Use(auth.Auth()) // 应用认证中间件
	}
	routing.Setup(protected, s.HTTPProxy, cfg)
	logger.Info("动态路由设置完成")
}

// handleHealth 处理健康检查请求
func (s *Server) handleHealth(c *gin.Context) {
	logger.Info("收到健康检查请求", zap.String("clientIP", c.ClientIP()))
	c.JSON(200, gin.H{"status": "ok"})
}

// handleStatus 处理状态检查请求
func (s *Server) handleStatus(c *gin.Context) {
	logger.Info("收到状态检查请求", zap.String("clientIP", c.ClientIP()))

	var statusReq struct {
		Reset bool `json:"reset" form:"reset"`
	}
	if err := c.ShouldBindQuery(&statusReq); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}
	if statusReq.Reset {
		health.GetGlobalHealthChecker().ResetAllStats()
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	gatewayStatus := GatewayStatus{
		Uptime:         time.Since(startTime).String(),
		Version:        Version,
		MemoryAlloc:    m.Alloc,
		GoroutineCount: runtime.NumGoroutine(),
	}

	backendStats := health.GetGlobalHealthChecker().GetAllStats()
	cachedStats := s.getCachedPathStats(backendStats)
	pluginStatus := getPluginStatus()

	cfg := s.ConfigMgr.GetConfig()
	configSummary := ConfigSummary{
		Server: ServerConfigSummary{
			Port:    cfg.Server.Port,
			GinMode: cfg.Server.GinMode,
		},
		Logger: LoggerConfigSummary{
			Level: cfg.Logger.Level,
		},
		Middleware: MiddlewareConfigSummary{
			RateLimit:     cfg.Middleware.RateLimit,
			IPAcl:         cfg.Middleware.IPAcl,
			AntiInjection: cfg.Middleware.AntiInjection,
			Auth:          cfg.Middleware.Auth,
			Breaker:       cfg.Middleware.Breaker,
			Tracing:       cfg.Middleware.Tracing,
		},
		Routing: RoutingConfigSummary{
			Engine:            cfg.Routing.Engine,
			LoadBalancer:      cfg.Routing.LoadBalancer,
			HeartbeatInterval: cfg.Routing.HeartbeatInterval,
		},
		Security: SecurityConfigSummary{
			AuthMode:    cfg.Security.AuthMode,
			JWTEnabled:  cfg.Security.JWT.Enabled,
			RBACEnabled: cfg.Security.RBAC.Enabled,
		},
		Cache: CacheConfigSummary{
			Addr:           cfg.Cache.Addr,
			EnabledCaching: cfg.Caching.Enabled,
		},
		Traffic: TrafficConfigSummary{
			RateLimit: TrafficRateLimitSummary{
				Enabled:   cfg.Traffic.RateLimit.Enabled,
				QPS:       cfg.Traffic.RateLimit.QPS,
				Algorithm: cfg.Traffic.RateLimit.Algorithm,
			},
			Breaker: TrafficBreakerSummary{
				Enabled: cfg.Traffic.Breaker.Enabled,
			},
		},
		Observability: ObservabilityConfigSummary{
			PrometheusEnabled: cfg.Observability.Prometheus.Enabled,
			PrometheusAddr:    cfg.Observability.Prometheus.HttpEndpoint,
			GrafanaAddr:       cfg.Observability.Grafana.HttpEndpoint,
			JaegerEnabled:     cfg.Observability.Jaeger.Enabled,
			JaegerAddr:        cfg.Observability.Jaeger.HttpEndpoint,
		},
	}

	c.HTML(200, "status.html", gin.H{
		"Gateway":       gatewayStatus,
		"BackendStats":  backendStats,
		"CachedStats":   cachedStats,
		"Plugins":       pluginStatus,
		"ConfigSummary": configSummary,
	})
}

// handleLogin 处理登录请求
func (s *Server) handleLogin(c *gin.Context) {
	var creds struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&creds); err != nil {
		logger.Warn("无效的登录请求", zap.Error(err))
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	if creds.Username != "admin" || creds.Password != "password" {
		logger.Warn("登录失败", zap.String("username", creds.Username))
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	cfg := s.ConfigMgr.GetConfig()
	switch cfg.Security.AuthMode {
	case "jwt":
		token, err := security.GenerateToken(creds.Username)
		if err != nil {
			logger.Error("生成 JWT token 失败", zap.Error(err))
			c.JSON(500, gin.H{"error": "Server error"})
			return
		}
		c.JSON(200, gin.H{"token": token})
	case "rbac":
		token, err := security.GenerateRBACLoginToken(creds.Username)
		if err != nil {
			logger.Error("生成 RBAC token 失败", zap.Error(err))
			c.JSON(500, gin.H{"error": "Server error"})
			return
		}
		c.JSON(200, gin.H{"token": token, "username": creds.Username})
	default:
		c.JSON(200, gin.H{"message": "Login successful", "username": creds.Username})
	}
}

// handleAddRoute 处理添加路由请求
func (s *Server) handleAddRoute(c *gin.Context) {
	var route struct {
		Path  string              `json:"path" binding:"required"`
		Rules config.RoutingRules `json:"rules" binding:"required"`
	}
	if err := c.ShouldBindJSON(&route); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	cfg := s.ConfigMgr.GetConfig()
	if cfg.Routing.Rules == nil {
		cfg.Routing.Rules = make(map[string]config.RoutingRules)
	}

	if _, exists := cfg.Routing.Rules[route.Path]; exists {
		c.JSON(409, gin.H{"error": "Route already exists"})
		return
	}

	cfg.Routing.Rules[route.Path] = route.Rules
	s.ConfigMgr.UpdateConfig(cfg)
	logger.Info("路由已添加", zap.String("path", route.Path), zap.Any("rules", route.Rules))
	c.JSON(200, gin.H{"message": "Route added successfully"})
}

// handleUpdateRoute 处理更新路由请求
func (s *Server) handleUpdateRoute(c *gin.Context) {
	var route struct {
		Path  string              `json:"path" binding:"required"`
		Rules config.RoutingRules `json:"rules" binding:"required"`
	}
	if err := c.ShouldBindJSON(&route); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	path, rules := route.Path, route.Rules

	cfg := s.ConfigMgr.GetConfig()
	if _, exists := cfg.Routing.Rules[path]; !exists {
		c.JSON(404, gin.H{"error": "Route not found"})
		return
	}

	cfg.Routing.Rules[path] = rules
	s.ConfigMgr.UpdateConfig(cfg)
	logger.Info("路由已更新", zap.String("path", path), zap.Any("rules", rules))
	c.JSON(200, gin.H{"message": "Route updated successfully"})
}

// handleDeleteRoute 处理删除路由请求
func (s *Server) handleDeleteRoute(c *gin.Context) {
	var route struct {
		Path  string              `json:"path" binding:"required"`
		Rules config.RoutingRules `json:"rules" binding:"required"`
	}
	if err := c.ShouldBindJSON(&route); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request payload"})
		return
	}

	path := route.Path
	cfg := s.ConfigMgr.GetConfig()

	if _, exists := cfg.Routing.Rules[path]; !exists {
		c.JSON(404, gin.H{"error": "Route not found"})
		return
	}

	delete(cfg.Routing.Rules, path)
	s.ConfigMgr.UpdateConfig(cfg)
	logger.Info("路由已删除", zap.String("path", path))
	c.JSON(200, gin.H{"message": "Route deleted successfully"})
}

// handleListRoutes 处理列出所有路由请求
func (s *Server) handleListRoutes(c *gin.Context) {
	cfg := s.ConfigMgr.GetConfig()
	c.JSON(200, gin.H{"routes": cfg.Routing.Rules})
}

// handleSaveConfig 处理保存配置请求
func (s *Server) handleSaveConfig(c *gin.Context) {
	cfg := s.ConfigMgr.GetConfig()
	err := s.ConfigMgr.SaveConfigToFile(cfg, "./config/config.yaml")
	if err != nil {
		logger.Error("保存配置失败", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to save configuration"})
		return
	}
	logger.Info("配置已保存到文件")
	c.JSON(200, gin.H{"message": "Configuration saved successfully"})
}

// setupMiddleware 配置中间件
func (s *Server) setupMiddleware(cfg *config.Config) {
	s.Router = setupGinRouter(cfg)

	s.Router.Use(middleware.CacheMiddleware()) // 启用缓存中间件

	plugins.LoadPlugins(s.Router, cfg) // 加载自定义插件

	if cfg.Middleware.IPAcl {
		security.InitIPRules(cfg)
		s.Router.Use(security.IPAcl()) // IP 访问控制
	}
	if cfg.Middleware.AntiInjection {
		s.Router.Use(security.AntiInjection()) // 防注入攻击
	}

	if cfg.Middleware.RateLimit {
		switch cfg.Traffic.RateLimit.Algorithm {
		case "token_bucket":
			s.Router.Use(traffic.TokenBucketRateLimit()) // 令牌桶限流
		case "leaky_bucket":
			s.Router.Use(traffic.LeakyBucketRateLimit()) // 漏桶限流
		default:
			logger.Error("未知的限流算法", zap.String("algorithm", cfg.Traffic.RateLimit.Algorithm))
			os.Exit(1)
		}
	}
	if cfg.Middleware.Breaker {
		s.Router.Use(traffic.Breaker()) // 熔断器
	}

	if cfg.Middleware.Tracing {
		cleanup := observability.InitTracing(cfg)
		s.TracingCleanup = cleanup
		s.Router.Use(middleware.Tracing()) // 分布式追踪
	}
}

// setupHTTPProxy 配置 HTTP 代理
func (s *Server) setupHTTPProxy(cfg *config.Config) {
	s.HTTPProxy = proxy.NewHTTPProxy(cfg)
	logger.Info("HTTP 代理已初始化，负载均衡类型", zap.String("type", cfg.Routing.LoadBalancer))
}

// refreshConfig 刷新配置
func refreshConfig(server *Server, configMgr *config.ConfigManager) {
	for newCfg := range configMgr.ConfigChan {
		logger.Info("正在刷新服务配置")
		server.setupMiddleware(newCfg)
		server.setupRoutes(newCfg)
		server.HTTPProxy.RefreshLoadBalancer(newCfg)
		health.GetGlobalHealthChecker().RefreshTargets(newCfg)
		logger.Info("服务配置刷新成功")
	}
}

// start 启动服务
func (s *Server) start() {
	cfg := s.ConfigMgr.GetConfig()
	logStartupInfo(cfg)

	listenAddr := ":" + cfg.Server.Port
	logger.Info("服务开始监听", zap.String("address", listenAddr))
	go func() {
		if err := s.Router.Run(listenAddr); err != nil {
			logger.Error("启动服务失败", zap.Error(err))
			os.Exit(1)
		}
	}()
	go StartMemoryMonitoring()

	s.gracefulShutdown()
}

// logStartupInfo 记录服务启动信息
func logStartupInfo(cfg *config.Config) {
	logger.Info("启动 mini-gateway",
		zap.String("port", cfg.Server.Port),
		zap.String("version", Version),
		zap.String("buildTime", BuildTime),
		zap.String("gitCommit", GitCommit),
		zap.String("goVersion", GoVersion),
		zap.Any("routingRules", cfg.Routing.Rules),
		zap.String("authMode", cfg.Security.AuthMode),
		zap.Bool("rbacEnabled", cfg.Security.RBAC.Enabled),
	)

	logger.Info("中间件状态",
		zap.Bool("RateLimit", cfg.Middleware.RateLimit),
		zap.Bool("IPAcl", cfg.Middleware.IPAcl),
		zap.Bool("AntiInjection", cfg.Middleware.AntiInjection),
		zap.Bool("Breaker", cfg.Middleware.Breaker),
		zap.Bool("Tracing", cfg.Middleware.Tracing),
	)
}

// gracefulShutdown 优雅关闭服务
func (s *Server) gracefulShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("正在关闭服务...")

	if s.TracingCleanup != nil {
		if err := s.TracingCleanup(context.Background()); err != nil {
			logger.Error("关闭追踪提供者失败", zap.Error(err))
		}
	}
	health.GetGlobalHealthChecker().Close()
}

// setupGinRouter 初始化 Gin 路由器
func setupGinRouter(cfg *config.Config) *gin.Engine {
	gin.SetMode(cfg.Server.GinMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestMetricsMiddleware())
	r.LoadHTMLGlob("templates/*") // 加载 templates 目录下的所有模板
	return r
}

// validateConfig 验证配置
func validateConfig(cfg *config.Config) {
	if cfg.Routing.LoadBalancer != "consul" && (cfg.Routing.Rules == nil || len(cfg.Routing.Rules) == 0) {
		logger.Error("路由规则为空或未定义")
		os.Exit(1)
	}
}

// GatewayStatus 网关自身状态
type GatewayStatus struct {
	Uptime         string `json:"uptime"`
	Version        string `json:"version"`
	MemoryAlloc    uint64 `json:"memory_alloc_bytes"`
	GoroutineCount int    `json:"goroutine_count"`
}

// getUnhealthyTargets 获取不可用目标列表
func (s *Server) getUnhealthyTargets() []string {
	var unhealthy []string
	stats := health.GetGlobalHealthChecker().GetAllStats()
	for _, stat := range stats {
		if stat.ProbeFailureCount > stat.ProbeSuccessCount {
			unhealthy = append(unhealthy, stat.URL)
		}
	}
	return unhealthy
}

func (s *Server) getCachedPathStats(backendStats []health.TargetStatus) []*cache.PathCount {

	var paths []string
	for path := range config.GetConfig().Routing.Rules {
		paths = append(paths, path)
	}

	pathCounts, getErr := cache.BatchGetPathReqCount(context.Background(), paths)
	if getErr != nil {
		logger.Error("获取缓存路径统计失败", zap.Error(getErr))
		return nil
	}

	pathCountMap := make(map[string]*cache.PathCount)
	for idx, pathCount := range pathCounts {
		pathCountMap[pathCount.Path] = &pathCounts[idx]
	}
	for _, backendStat := range backendStats {
		if _, ok := pathCountMap[backendStat.Rule]; !ok {
			continue
		}
		count := pathCountMap[backendStat.Rule].Count
		count -= backendStat.RequestCount
		if count <= 0 {
			count = 0
		}
		pathCountMap[backendStat.Rule].Count = count
	}

	sort.Slice(pathCounts, func(i, j int) bool {
		return pathCounts[i].Path < pathCounts[j].Path
	})

	ps := lo.Values(pathCountMap)

	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Path < ps[j].Path
	})
	return ps
}

// PluginStatus 插件状态
type PluginStatus struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// getPluginStatus 获取插件状态
func getPluginStatus() []PluginStatus {
	var status []PluginStatus
	loadedPlugins := plugins.GetLoadedPlugins()
	for _, p := range loadedPlugins {
		status = append(status, PluginStatus{
			Name:        p.PluginInfo().Name,
			Description: p.PluginInfo().Description,
			Version:     p.PluginInfo().Version.String(),
			Enabled:     true,
		})
	}
	sort.Slice(status, func(i, j int) bool {
		return status[i].Name < status[j].Name
	})
	return status
}

// requestMetricsMiddleware 全局请求监控中间件
func requestMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		method := c.Request.Method
		path := c.Request.URL.Path

		c.Next()

		status := fmt.Sprintf("%d", c.Writer.Status())
		observability.RequestsTotal.WithLabelValues(method, path, status).Inc()
		duration := time.Since(start).Seconds()
		observability.RequestDuration.WithLabelValues(method, path).Observe(duration)
	}
}

type ConfigSummary struct {
	Server        ServerConfigSummary        `json:"server"`
	Logger        LoggerConfigSummary        `json:"logger"`
	Middleware    MiddlewareConfigSummary    `json:"middleware"`
	Routing       RoutingConfigSummary       `json:"routing"`
	Security      SecurityConfigSummary      `json:"security"`
	Cache         CacheConfigSummary         `json:"cache"`
	Traffic       TrafficConfigSummary       `json:"traffic"`
	Observability ObservabilityConfigSummary `json:"observability"`
}

type ServerConfigSummary struct {
	Port    string `json:"port"`
	GinMode string `json:"gin_mode"`
}

type LoggerConfigSummary struct {
	Level string `json:"level"`
}

type MiddlewareConfigSummary struct {
	RateLimit     bool `json:"rate_limit"`
	IPAcl         bool `json:"ip_acl"`
	AntiInjection bool `json:"anti_injection"`
	Auth          bool `json:"auth"`
	Breaker       bool `json:"breaker"`
	Tracing       bool `json:"tracing"`
}

type RoutingConfigSummary struct {
	Engine            string `json:"engine"`
	LoadBalancer      string `json:"load_balancer"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
}

type SecurityConfigSummary struct {
	AuthMode    string `json:"auth_mode"`
	JWTEnabled  bool   `json:"jwt_enabled"`
	RBACEnabled bool   `json:"rbac_enabled"`
}

type CacheConfigSummary struct {
	Addr           string `json:"addr"`
	EnabledCaching bool   `json:"enabled_caching"`
}

type TrafficConfigSummary struct {
	RateLimit TrafficRateLimitSummary `json:"rate_limit"`
	Breaker   TrafficBreakerSummary   `json:"breaker"`
}

type TrafficRateLimitSummary struct {
	Enabled   bool   `json:"enabled"`
	QPS       int    `json:"qps"`
	Algorithm string `json:"algorithm"`
}

type TrafficBreakerSummary struct {
	Enabled bool `json:"enabled"`
}

type ObservabilityConfigSummary struct {
	PrometheusEnabled bool   `json:"prometheus_enabled"`
	PrometheusAddr    string `json:"prometheus_addr"`
	GrafanaAddr       string `json:"grafana_addr"`
	JaegerEnabled     bool   `json:"jaeger_enabled"`
	JaegerAddr        string `json:"jaeger_addr"`
}

func StartMemoryMonitoring() {
	// 启动一个后台 goroutine 来收集内存指标
	go func() {
		ticker := time.NewTicker(5 * time.Second) // 每5秒收集一次
		defer ticker.Stop()

		for range ticker.C {
			CollectMemoryMetrics()
		}
	}()
}

func CollectMemoryMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m) // 读取当前的内存统计

	// 更新各种类型的内存分配指标
	observability.MemoryAllocations.WithLabelValues("heap").Set(float64(m.HeapAlloc))         // 当前分配的堆内存
	observability.MemoryAllocations.WithLabelValues("heap_sys").Set(float64(m.HeapSys))       // 从系统获取的堆内存
	observability.MemoryAllocations.WithLabelValues("heap_idle").Set(float64(m.HeapIdle))     // 空闲的堆内存
	observability.MemoryAllocations.WithLabelValues("heap_inuse").Set(float64(m.HeapInuse))   // 使用中的堆内存
	observability.MemoryAllocations.WithLabelValues("stack").Set(float64(m.StackInuse))       // 栈内存使用
	observability.MemoryAllocations.WithLabelValues("sys").Set(float64(m.Sys))                // 系统内存总量
	observability.MemoryAllocations.WithLabelValues("total_alloc").Set(float64(m.TotalAlloc)) // 累计分配的内存
	observability.MemoryAllocations.WithLabelValues("num_gc").Set(float64(m.NumGC))           // GC周期数
}
