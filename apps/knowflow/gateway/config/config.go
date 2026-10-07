package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"

	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/spf13/viper"
)

var configMgr *ConfigManager

// ConfigManager 管理配置及其变更通知
type ConfigManager struct {
	config *Config
	mutex  sync.RWMutex

	ConfigChan chan *Config // 用于通知配置变更
}

// Config 定义网关的配置结构体
type Config struct {
	Server        Server        `mapstructure:"server"`
	Routing       Routing       `mapstructure:"routing"`
	Security      Security      `mapstructure:"security"`
	Traffic       Traffic       `mapstructure:"traffic"`
	Observability Observability `mapstructure:"observability"`
	Plugin        Plugin        `mapstructure:"plugin"`
	Logger        Logger        `mapstructure:"logger"`
	Cache         Cache         `mapstructure:"cache"`
	Caching       Caching       `mapstructure:"caching"`
	Consul        Consul        `mapstructure:"consul"`
	Middleware    Middleware    `mapstructure:"middleware"`
	GRPC          GRPCConfig    `mapstructure:"grpc"`
	WebSocket     WebSocket     `mapstructure:"websocket"`
	FileServer    FileServer    `mapstructure:"fileServer"`
	Performance   Performance   `mapstructure:"performance"`
}

// InitConfig 初始化配置并返回 ConfigManager
func InitConfig() *ConfigManager {
	cfg := &Config{}

	v := viper.New()
	v.SetConfigFile("config/config.yaml")
	v.SetConfigType("yaml")
	setDefaultValues(v)

	if err := v.ReadInConfig(); err != nil {
		logger.Error("Failed to read configuration file", zap.Error(err))
		os.Exit(1)
	}
	if err := v.Unmarshal(cfg); err != nil {
		logger.Error("Failed to unmarshal configuration", zap.Error(err))
		os.Exit(1)
	}

	if err := validateGRPCConfig(cfg); err != nil {
		logger.Error("gRPC configuration validation failed", zap.Error(err))
		os.Exit(1)
	}
	if err := validateWebSocketConfig(cfg); err != nil {
		logger.Error("WebSocket configuration validation failed", zap.Error(err))
		os.Exit(1)
	}

	configMgr = &ConfigManager{
		config:     cfg,
		ConfigChan: make(chan *Config, 1), // 缓冲通道，避免阻塞
		mutex:      sync.RWMutex{},
	}

	// 监听配置文件变化以实现热更新
	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		logger.Info("Configuration file changed", zap.String("file", e.Name))
		newCfg := &Config{}

		newV := viper.New()
		newV.SetConfigFile(e.Name)
		newV.SetConfigType("yaml")
		setDefaultValues(newV)

		if err := newV.ReadInConfig(); err != nil {
			logger.Error("Failed to read configuration file", zap.Error(err))
			os.Exit(1)
		}
		if err := newV.Unmarshal(newCfg); err != nil {
			logger.Error("Failed to unmarshal configuration", zap.Error(err))
			os.Exit(1)
		}

		if err := viper.Unmarshal(newCfg); err != nil {
			logger.Error("Failed to reload configuration", zap.Error(err))
			return
		}
		if err := validateGRPCConfig(newCfg); err != nil {
			logger.Error("gRPC configuration validation failed on reload", zap.Error(err))
			return
		}
		if err := validateWebSocketConfig(newCfg); err != nil {
			logger.Error("WebSocket configuration validation failed on reload", zap.Error(err))
			return
		}

		configMgr.mutex.Lock()
		configMgr.config = newCfg
		configMgr.mutex.Unlock()

		// 通知配置变更
		select {
		case configMgr.ConfigChan <- newCfg:
			logger.Info("Configuration reload notification sent")
		default:
			logger.Warn("Config channel full, skipping notification")
		}
	})

	return configMgr
}

// Grayscale 灰度发布配置
type Grayscale struct {
	Enabled        bool   `mapstructure:"enabled"`        // 是否启用灰度发布
	WeightedRandom bool   `mapstructure:"weightedRandom"` // 是否在灰度发布中使用权重随机路由
	DefaultEnv     string `mapstructure:"defaultEnv"`     // 默认环境（如 "stable"）
	CanaryEnv      string `mapstructure:"canaryEnv"`      // 灰度环境（如 "canary"）
}

// Plugin 插件配置
type Plugin struct {
	Dir     string   `mapstructure:"dir"`     // 插件目录
	Plugins []string `mapstructure:"plugins"` // 插件列表
}

// FileServer 文件服务器配置
type FileServer struct {
	StaticFilePath  string `mapstructure:"staticFilePath"`  // 静态文件路径
	EnabledFastHttp bool   `mapstructure:"enabledFastHttp"` // 是否启用 fasthttp
}

// Performance 性能相关配置
type Performance struct {
	MemoryPool      MemoryPool `mapstructure:"memoryPool"`
	MaxConnsPerHost int        `mapstructure:"maxConnsPerHost"` // 每个目标的最大连接数
	HttpPoolEnabled bool       `mapstructure:"httpPoolEnabled"` // 是否启用 HTTP 连接池
}

// MemoryPool 内存池配置
type MemoryPool struct {
	Enabled         bool `mapstructure:"enabled"`
	TargetsCapacity int  `mapstructure:"targetsCapacity"`
	RulesCapacity   int  `mapstructure:"rulesCapacity"`
}

// Consul Consul 服务发现配置
type Consul struct {
	Enabled bool   `mapstructure:"enabled"`
	Addr    string `mapstructure:"addr"`
}

// WebSocket WebSocket 配置
type WebSocket struct {
	Enabled      bool          `mapstructure:"enabled"`
	MaxIdleConns int           `mapstructure:"maxIdleConns"`
	IdleTimeout  time.Duration `mapstructure:"idleTimeout"`
	Prefix       string        `mapstructure:"prefix"`
}

// GetWebSocketRules 获取 WebSocket 路由规则
func (r Routing) GetWebSocketRules() map[string]RoutingRules {
	wsRules := make(map[string]RoutingRules)
	for path, rules := range r.Rules {
		var filteredRules RoutingRules
		for _, rule := range rules {
			if rule.Protocol == "websocket" {
				filteredRules = append(filteredRules, rule)
			}
		}
		if len(filteredRules) > 0 {
			wsRules[path] = filteredRules
		}
	}
	return wsRules
}

// GRPCConfig gRPC 配置
type GRPCConfig struct {
	Enabled         bool     `mapstructure:"enabled"`
	Prefix          string   `mapstructure:"prefix"`
	HealthCheckPath string   `mapstructure:"healthCheckPath"`
	Reflection      bool     `mapstructure:"reflection"`
	AllowedOrigins  []string `mapstructure:"allowedOrigins"`
}

// Middleware 中间件开关配置
type Middleware struct {
	RateLimit     bool `mapstructure:"rateLimit"`
	IPAcl         bool `mapstructure:"ipAcl"`
	AntiInjection bool `mapstructure:"antiInjection"`
	Auth          bool `mapstructure:"auth"`
	Breaker       bool `mapstructure:"breaker"`
	Tracing       bool `mapstructure:"tracing"`
}

// Caching 业务缓存策略配置
type Caching struct {
	Enabled bool          `mapstructure:"enabled"`
	Rules   []CachingRule `mapstructure:"rules"`
}

// CachingRule 定义单个缓存规则
type CachingRule struct {
	Path      string        `mapstructure:"path"`
	Method    string        `mapstructure:"method"`
	Threshold int           `mapstructure:"threshold"`
	TTL       time.Duration `mapstructure:"ttl"`
}

// Cache 缓存配置
type Cache struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// RoutingRule 路由规则定义
type RoutingRule struct {
	Target          string `mapstructure:"target"`
	Weight          int    `mapstructure:"weight"`
	Env             string `mapstructure:"env"`
	Protocol        string `mapstructure:"protocol"`
	HealthCheckPath string `mapstructure:"healthCheckPath"`
}

type RoutingRules []RoutingRule

// HasGrpcRule 检查是否存在 gRPC 规则
func (i RoutingRules) HasGrpcRule() bool {
	for _, rule := range i {
		if rule.Protocol == "grpc" {
			return true
		}
	}
	return false
}

// HasWebsocketRule 检查是否存在 WebSocket 规则
func (i RoutingRules) HasWebsocketRule() bool {
	for _, rule := range i {
		if rule.Protocol == "websocket" {
			return true
		}
	}
	return false
}

// Routing 路由配置
type Routing struct {
	Rules             map[string]RoutingRules `mapstructure:"rules"`
	Engine            string                  `mapstructure:"engine"`
	LoadBalancer      string                  `mapstructure:"loadBalancer"`
	HeartbeatInterval int                     `mapstructure:"heartbeatInterval"`
	Grayscale         Grayscale               `mapstructure:"grayscale"`
}

// GetGrpcRules 获取 gRPC 路由规则
func (i Routing) GetGrpcRules() map[string]RoutingRules {
	grpcRules := make(map[string]RoutingRules)
	for path, rules := range i.Rules {
		if rules.HasGrpcRule() {
			grpcRules[path] = rules
		}
	}
	return grpcRules
}

// GetHTTPRules 获取 HTTP 路由规则
func (i Routing) GetHTTPRules() map[string]RoutingRules {
	httpRules := make(map[string]RoutingRules)
	for path, rules := range i.Rules {
		if !rules.HasGrpcRule() && !rules.HasWebsocketRule() {
			httpRules[path] = rules
		}
	}
	return httpRules
}

// Server 服务器配置
type Server struct {
	Port         string `mapstructure:"port"`
	GinMode      string `mapstructure:"ginMode"`
	PprofEnabled bool   `mapstructure:"pprofenabled"`
}

// JWT JWT 认证配置
type JWT struct {
	Secret    string `mapstructure:"secret"`
	ExpiresIn int    `mapstructure:"expiresIn"`
	Enabled   bool   `mapstructure:"enabled"`
}

// Security 安全相关配置
type Security struct {
	AuthMode     string   `mapstructure:"authMode"`
	JWT          JWT      `mapstructure:"jwt"`
	RBAC         RBAC     `mapstructure:"rbac"`
	IPBlacklist  []string `mapstructure:"ipBlacklist"`
	IPWhitelist  []string `mapstructure:"ipWhitelist"`
	IPUpdateMode string   `mapstructure:"ipUpdateMode"`
}

// RBAC RBAC 权限配置
type RBAC struct {
	Enabled    bool   `mapstructure:"enabled"`
	ModelPath  string `mapstructure:"modelPath"`
	PolicyPath string `mapstructure:"policyPath"`
}

// TrafficRateLimit 流量限流配置
type TrafficRateLimit struct {
	Enabled     bool                        `mapstructure:"enabled"`
	QPS         int                         `mapstructure:"qps"`
	Burst       int                         `mapstructure:"burst"`
	Algorithm   string                      `mapstructure:"algorithm"`
	IPLimits    map[string]TrafficRateLimit `mapstructure:"ip_limits"`    // IP维度限流
	RouteLimits map[string]TrafficRateLimit `mapstructure:"route_limits"` // 路由维度限流
}

// TrafficBreaker 熔断器配置
type TrafficBreaker struct {
	Enabled        bool    `mapstructure:"enabled"`
	ErrorRate      float64 `mapstructure:"errorRate"`
	Timeout        int     `mapstructure:"timeout"`
	MinRequests    int     `mapstructure:"minRequests"`
	SleepWindow    int     `mapstructure:"sleepWindow"`
	MaxConcurrent  int     `mapstructure:"maxConcurrent"`
	WindowSize     int     `mapstructure:"windowSize"`
	WindowDuration int     `mapstructure:"windowDuration"`
}

// Traffic 流量控制配置
type Traffic struct {
	RateLimit TrafficRateLimit `mapstructure:"rateLimit"`
	Breaker   TrafficBreaker   `mapstructure:"breaker"`
}

// Observability 可观测性配置
type Observability struct {
	Prometheus Prometheus `mapstructure:"prometheus"`
	Grafana    Grafana    `mapstructure:"grafana"`
	Jaeger     Jaeger     `mapstructure:"jaeger"`
}

// Grafana 配置
type Grafana struct {
	HttpEndpoint string `mapstructure:"httpEndpoint"`
}

// Prometheus 配置
type Prometheus struct {
	Enabled      bool   `mapstructure:"enabled"`
	Path         string `mapstructure:"path"`
	HttpEndpoint string `mapstructure:"httpEndpoint"`
}

// Jaeger 追踪配置
type Jaeger struct {
	Enabled      bool    `mapstructure:"enabled"`
	Endpoint     string  `mapstructure:"endpoint"`
	HttpEndpoint string  `mapstructure:"httpEndpoint"`
	Sampler      string  `mapstructure:"sampler"`
	SampleRatio  float64 `mapstructure:"sampleRatio"`
}

// Logger 日志配置
type Logger struct {
	Level      string `mapstructure:"level"`
	FilePath   string `mapstructure:"filePath"`
	MaxSize    int    `mapstructure:"maxSize"`
	MaxBackups int    `mapstructure:"maxBackups"`
	MaxAge     int    `mapstructure:"maxAge"`
	Compress   bool   `mapstructure:"compress"`
}

// GetConfig 获取当前配置（线程安全）
func (cm *ConfigManager) GetConfig() *Config {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return cm.config
}

// GetConfig 获取当前全局配置实例（线程安全）
func GetConfig() *Config {
	return configMgr.GetConfig()
}

// SetConfig 获取当前全局配置实例（线程安全）
func SetConfig(c *Config) {
	configMgr.mutex.Lock()
	defer configMgr.mutex.Unlock()
	configMgr.config = c
}

// InitTestConfigManager 初始化测试配置管理器
func InitTestConfigManager() {
	configMgr = &ConfigManager{
		config: &Config{
			Routing: Routing{
				LoadBalancer: "round_robin",
			},
			Traffic: Traffic{
				RateLimit: TrafficRateLimit{
					Enabled:   true,
					QPS:       10,
					Burst:     20,
					Algorithm: "leaky_bucket",
					IPLimits: map[string]TrafficRateLimit{
						"192.168.1.1": {QPS: 5, Burst: 10, Enabled: true},
					},
					RouteLimits: map[string]TrafficRateLimit{
						"/api/v1/user": {QPS: 8, Burst: 15, Enabled: true},
					},
				},
				Breaker: TrafficBreaker{},
			},
		},
		ConfigChan: make(chan *Config, 1), // 缓冲通道，避免阻塞
		mutex:      sync.RWMutex{},
	}
}

// setDefaultValues 设置默认配置值
func setDefaultValues(v *viper.Viper) {
	v.SetDefault("server.port", "8080")
	v.SetDefault("server.ginMode", "release")
	v.SetDefault("server.pprofenabled", false)

	v.SetDefault("plugin.dir", "bin/plugins")
	v.SetDefault("plugin.plugins", []string{"log"})

	v.SetDefault("routing.engine", "gin")
	v.SetDefault("routing.loadBalancer", "round-robin")
	v.SetDefault("routing.heartbeatInterval", 30)

	v.SetDefault("middleware.rateLimit", true)
	v.SetDefault("middleware.ipAcl", true)
	v.SetDefault("middleware.antiInjection", true)
	v.SetDefault("middleware.auth", true)
	v.SetDefault("middleware.breaker", true)

	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)

	v.SetDefault("consul.enabled", false)
	v.SetDefault("consul.addr", "localhost:8500")

	v.SetDefault("security.jwt.secret", "default-secret-key")
	v.SetDefault("security.jwt.expiresIn", 3600)
	v.SetDefault("security.authMode", "none")
	v.SetDefault("security.rbac.enabled", false)
	v.SetDefault("security.rbac.modelPath", "config/data/rbac_model.conf")
	v.SetDefault("security.rbac.policyPath", "config/data/rbac_policy.csv")
	v.SetDefault("security.ipUpdateMode", "override")

	v.SetDefault("traffic.rateLimit.enabled", true)
	v.SetDefault("traffic.rateLimit.qps", 1000)
	v.SetDefault("traffic.rateLimit.burst", 2000)
	v.SetDefault("traffic.rateLimit.algorithm", "token_bucket")
	v.SetDefault("traffic.breaker.enabled", true)
	v.SetDefault("traffic.breaker.errorRate", 0.5)
	v.SetDefault("traffic.breaker.timeout", 1000)
	v.SetDefault("traffic.breaker.minRequests", 20)
	v.SetDefault("traffic.breaker.sleepWindow", 5000)
	v.SetDefault("traffic.breaker.maxConcurrent", 100)
	v.SetDefault("traffic.breaker.windowSize", 100)
	v.SetDefault("traffic.breaker.windowDuration", 10)

	v.SetDefault("observability.prometheus.enabled", true)
	v.SetDefault("observability.prometheus.path", "/metrics")
	v.SetDefault("observability.jaeger.enabled", false)
	v.SetDefault("observability.jaeger.endpoint", "http://localhost:14268/api/traces")
	v.SetDefault("observability.jaeger.sampler", "always")
	v.SetDefault("observability.jaeger.sampleRatio", 1.0)

	v.SetDefault("logger.level", "info")
	v.SetDefault("logger.filePath", "logs/gateway.log")
	v.SetDefault("logger.maxSize", 100)
	v.SetDefault("logger.maxBackups", 10)
	v.SetDefault("logger.maxAge", 30)
	v.SetDefault("logger.compress", true)

	v.SetDefault("grpc.enabled", true)
	v.SetDefault("grpc.healthCheckPath", "/grpc/health")
	v.SetDefault("grpc.reflection", false)
	v.SetDefault("grpc.allowedOrigins", []string{"*"})
	v.SetDefault("grpc.prefix", "/grpc")

	v.SetDefault("websocket.enabled", true)
	v.SetDefault("websocket.maxIdleConns", 100)
	v.SetDefault("websocket.idleTimeout", 60*time.Second)
	v.SetDefault("websocket.prefix", "/websocket")

	v.SetDefault("performance.memoryPool.enabled", false)
	v.SetDefault("performance.memoryPool.targetsCapacity", 100)
	v.SetDefault("performance.memoryPool.rulesCapacity", 100)
	v.SetDefault("performance.maxConnsPerHost", 512)
	v.SetDefault("performance.httpPoolEnabled", true)

	v.SetDefault("fileServer.staticFilePath", "./data")
	v.SetDefault("fileServer.enabledFastHttp", true)
}

// validateWebSocketConfig 验证 WebSocket 配置
func validateWebSocketConfig(cfg *Config) error {
	if cfg.WebSocket.Enabled {
		if cfg.WebSocket.Prefix == "" || len(cfg.WebSocket.Prefix) < 5 {
			return fmt.Errorf("WebSocket prefix is empty or too short: %s", cfg.WebSocket.Prefix)
		}
		if strings.ContainsAny(cfg.WebSocket.Prefix, "..*?") {
			return fmt.Errorf("WebSocket prefix contains invalid characters: %s", cfg.WebSocket.Prefix)
		}

		wsRules := cfg.Routing.GetWebSocketRules()
		if len(wsRules) == 0 {
			return fmt.Errorf("WebSocket is enabled but no WebSocket routing rules are configured")
		}

		if cfg.WebSocket.MaxIdleConns < 0 {
			return fmt.Errorf("WebSocket maxIdleConns cannot be negative: %d", cfg.WebSocket.MaxIdleConns)
		}
		if cfg.WebSocket.IdleTimeout <= 0 {
			return fmt.Errorf("WebSocket idleTimeout must be positive: %s", cfg.WebSocket.IdleTimeout)
		}

		for path, rules := range wsRules {
			for _, rule := range rules {
				if !strings.HasPrefix(rule.Target, "ws://") && !strings.HasPrefix(rule.Target, "wss://") {
					return fmt.Errorf("WebSocket route %s target %s must start with ws:// or wss://", path, rule.Target)
				}
				if _, err := url.Parse(rule.Target); err != nil {
					return fmt.Errorf("WebSocket route %s target %s has invalid format: %v", path, rule.Target, err)
				}
			}
		}
	}
	return nil
}

// validateGRPCConfig 验证 gRPC 配置
func validateGRPCConfig(cfg *Config) error {
	if cfg.GRPC.Enabled {
		if cfg.GRPC.Prefix == "" || len(cfg.GRPC.Prefix) < 5 {
			return fmt.Errorf("gRPC prefix is empty or too short: %s", cfg.GRPC.Prefix)
		}
		if strings.ContainsAny(cfg.GRPC.Prefix, "..*?") {
			return fmt.Errorf("gRPC prefix contains invalid characters: %s", cfg.GRPC.Prefix)
		}

		grpcRules := cfg.Routing.GetGrpcRules()
		if len(grpcRules) == 0 {
			return fmt.Errorf("gRPC is enabled but no gRPC routing rules are configured")
		}

		for _, origin := range cfg.GRPC.AllowedOrigins {
			if origin == "*" {
				logger.Warn("gRPC allows all origins, which may pose a security risk")
			} else if _, err := url.Parse(origin); err != nil {
				return fmt.Errorf("gRPC allowedOrigins contains invalid URL: %s", origin)
			}
		}
	}
	return nil
}

// GetCacheRuleByPath 根据路径获取缓存规则
func (c *Config) GetCacheRuleByPath(path string) *CachingRule {
	for _, rule := range c.Caching.Rules {
		if rule.Path == path {
			return &rule
		}
	}
	return nil
}

// SaveConfigToFile 将配置保存到文件并保证字段顺序
func (cm *ConfigManager) SaveConfigToFile(cfg *Config, filePath string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 使用 yaml.MapSlice 保持字段顺序
	orderedData := yaml.MapSlice{
		{Key: "server", Value: cfg.Server},
		{Key: "logger", Value: cfg.Logger},
		{Key: "middleware", Value: cfg.Middleware},
		{Key: "grpc", Value: cfg.GRPC},
		{Key: "websocket", Value: cfg.WebSocket},
		{Key: "routing", Value: cfg.Routing},
		{Key: "security", Value: cfg.Security},
		{Key: "cache", Value: cfg.Cache},
		{Key: "caching", Value: cfg.Caching},
		{Key: "consul", Value: cfg.Consul},
		{Key: "traffic", Value: cfg.Traffic},
		{Key: "observability", Value: cfg.Observability},
		{Key: "plugin", Value: cfg.Plugin},
		{Key: "performance", Value: cfg.Performance},
		{Key: "fileServer", Value: cfg.FileServer},
	}

	// 序列化为 YAML 格式
	out, err := yaml.Marshal(orderedData)
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(filePath, out, 0644); err != nil {
		return err
	}

	logger.Info("配置已保存到文件", zap.String("path", filePath))
	return nil
}

// UpdateConfig 更新配置并通知监听者
func (cm *ConfigManager) UpdateConfig(cfg *Config) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.config = cfg
	cm.ConfigChan <- cfg
}
