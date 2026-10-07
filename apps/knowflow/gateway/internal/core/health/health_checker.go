package health

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"net/url"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/cache" // 引入 Redis 包
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gorilla/websocket"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// TargetStatus 后端目标的状态信息
type TargetStatus struct {
	Rule              string    `json:"rule"`
	URL               string    `json:"url"`
	Protocol          string    `json:"protocol"`
	RequestCount      int64     `json:"request_count"`
	SuccessCount      int64     `json:"success_count"`
	CacheHitCount     int64     `json:"cache_hit_count"`
	FailureCount      int64     `json:"failure_count"`
	ProbeRequestCount int64     `json:"probe_request_count"`
	ProbeSuccessCount int64     `json:"probe_success_count"`
	ProbeFailureCount int64     `json:"probe_failure_count"`
	LastProbeTime     time.Time `json:"last_probe_time"`
	LastRequestTime   time.Time `json:"last_request_time"`
}

// HealthChecker 健康检查服务
type HealthChecker struct {
	healthPaths map[string]string
	mu          sync.RWMutex
	cfg         *config.Config
	cleanupCh   chan struct{}
	ctx         context.Context
}

// Redis key 前缀
const (
	healthStatsPrefix = "mg:health:stats:"    // 健康检查状态
	cachePrefix       = "mg:cache:"           // 缓存内容
	reqCountPrefix    = "mg:cache:req_count:" // 请求计数
)

// GetHealthStatsKey 生成目标的健康状态 Redis 键
func GetHealthStatsKey(target string) string {
	return healthStatsPrefix + target
}

// GetCacheKey 生成缓存内容的 Redis 键
func GetCacheKey(method, path string) string {
	return cachePrefix + method + ":" + path
}

// GetPathReqCountKey 生成路径请求计数的 Redis 键
func GetPathReqCountKey(path string) string {
	return reqCountPrefix + path
}

var (
	globalHealthChecker *HealthChecker
	once                sync.Once
)

// GetGlobalHealthChecker 获取全局健康检查实例
func GetGlobalHealthChecker() *HealthChecker {
	return globalHealthChecker
}

// InitHealthChecker 创建并初始化健康检查服务
func InitHealthChecker(cfg *config.Config) *HealthChecker {
	logger.Info("Initializing health checker service")
	checker := &HealthChecker{
		healthPaths: make(map[string]string),
		cfg:         cfg,
		cleanupCh:   make(chan struct{}),
		ctx:         context.Background(),
	}

	// 清空 Redis 中所有健康检查和缓存相关键
	err := checker.clearRedisKeys()
	if err != nil {
		logger.Error("Failed to clear Redis keys", zap.Error(err))
	} else {
		logger.Info("Cleared all existing health stats and cache keys from Redis")
	}

	checker.RefreshTargets(cfg)
	go checker.startHeartbeat()

	once.Do(func() {
		globalHealthChecker = checker
	})
	return checker
}

// clearRedisKeys 清空 Redis 中所有相关键
func (h *HealthChecker) clearRedisKeys() error {
	patterns := []string{
		healthStatsPrefix + "*",
		cachePrefix + "*",
		reqCountPrefix + "*",
	}
	for _, pattern := range patterns {
		keys, err := cache.Client.Keys(h.ctx, pattern).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			pipe := cache.Client.Pipeline()
			for _, key := range keys {
				pipe.Del(h.ctx, key)
			}
			_, err = pipe.Exec(h.ctx)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// RefreshTargets 刷新目标健康检查路径并初始化 Redis 数据
func (h *HealthChecker) RefreshTargets(cfg *config.Config) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cfg = cfg
	h.healthPaths = make(map[string]string)

	for ruleName, rules := range cfg.Routing.Rules {
		for _, rule := range rules {
			host, err := NormalizeTarget(rule)
			if err != nil {
				logger.Error("Invalid target address",
					zap.String("target", rule.Target),
					zap.Error(err))
				continue
			}

			if rule.HealthCheckPath != "" {
				h.healthPaths[host] = rule.HealthCheckPath
			} else {
				h.healthPaths[host] = "/health"
			}

			stat := TargetStatus{
				Rule:              ruleName,
				URL:               rule.Target,
				Protocol:          rule.Protocol,
				RequestCount:      0,
				SuccessCount:      0,
				FailureCount:      0,
				ProbeRequestCount: 0,
				ProbeSuccessCount: 0,
				ProbeFailureCount: 0,
				LastProbeTime:     time.Time{},
			}
			err = h.saveToRedis(host, &stat)
			if err != nil {
				logger.Error("Failed to initialize target in Redis",
					zap.String("target", host), zap.Error(err))
			} else {
				logger.Info("Initialized new health check target in Redis",
					zap.String("target", host),
					zap.String("protocol", rule.Protocol),
					zap.String("healthCheckPath", h.healthPaths[host]))
			}
		}
	}
	logger.Info("Health checker targets refreshed",
		zap.Int("totalTargets", len(h.healthPaths)))
}

// saveToRedis 保存目标状态到 Redis
func (h *HealthChecker) saveToRedis(target string, stat *TargetStatus) error {
	key := GetHealthStatsKey(target)
	data := map[string]interface{}{
		"rule":                stat.Rule,
		"url":                 stat.URL,
		"protocol":            stat.Protocol,
		"request_count":       stat.RequestCount,
		"success_count":       stat.SuccessCount,
		"cache_hit_count":     stat.CacheHitCount,
		"failure_count":       stat.FailureCount,
		"probe_request_count": stat.ProbeRequestCount,
		"probe_success_count": stat.ProbeSuccessCount,
		"probe_failure_count": stat.ProbeFailureCount,
		"last_probe_time":     stat.LastProbeTime.Unix(),
		"last_request_time":   stat.LastRequestTime.Unix(),
	}
	return cache.Client.HMSet(h.ctx, key, data).Err()
}

// loadFromRedis 从 Redis 加载目标状态
func (h *HealthChecker) loadFromRedis(target string) (*TargetStatus, error) {
	key := GetHealthStatsKey(target)
	data, err := cache.Client.HGetAll(h.ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	stat := &TargetStatus{
		Rule:     data["rule"],
		URL:      data["url"],
		Protocol: data["protocol"],
	}
	if v, err := strconv.ParseInt(data["request_count"], 10, 64); err == nil {
		stat.RequestCount = v
	}
	if v, err := strconv.ParseInt(data["success_count"], 10, 64); err == nil {
		stat.SuccessCount = v
	}
	if v, err := strconv.ParseInt(data["cache_hit_count"], 10, 64); err == nil {
		stat.CacheHitCount = v
	}
	if v, err := strconv.ParseInt(data["failure_count"], 10, 64); err == nil {
		stat.FailureCount = v
	}
	if v, err := strconv.ParseInt(data["probe_request_count"], 10, 64); err == nil {
		stat.ProbeRequestCount = v
	}
	if v, err := strconv.ParseInt(data["probe_success_count"], 10, 64); err == nil {
		stat.ProbeSuccessCount = v
	}
	if v, err := strconv.ParseInt(data["probe_failure_count"], 10, 64); err == nil {
		stat.ProbeFailureCount = v
	}
	if v, err := strconv.ParseInt(data["last_probe_time"], 10, 64); err == nil {
		stat.LastProbeTime = time.Unix(v, 0)
	}
	if v, err := strconv.ParseInt(data["last_request_time"], 10, 64); err == nil {
		stat.LastRequestTime = time.Unix(v, 0)
	}
	return stat, nil
}

// CheckCache 检查缓存是否存在并返回内容，同时更新缓存命中计数
func (h *HealthChecker) CheckCache(ctx context.Context, method, path, target string) (string, bool) {
	if cache.Client == nil {
		logger.Warn("Redis client not initialized, skipping cache check")
		return "", false
	}

	key := GetCacheKey(method, path)
	content, err := cache.Client.Get(ctx, key).Result()
	if err == redis.Nil {
		logger.Debug("Cache miss", zap.String("key", key))
		return "", false
	} else if err != nil {
		logger.Error("Failed to check cache", zap.Error(err), zap.String("key", key))
		return "", false
	}

	// 更新缓存命中计数
	h.mu.Lock()
	defer h.mu.Unlock()
	if stat, err := h.loadFromRedis(target); err == nil && stat != nil {
		stat.CacheHitCount++
		h.saveToRedis(target, stat)
	}

	logger.Debug("Cache hit", zap.String("key", key))
	return content, true
}

// SetCache 设置缓存内容并指定过期时间
func (h *HealthChecker) SetCache(ctx context.Context, method, path string, content string, ttl time.Duration) error {
	if cache.Client == nil {
		logger.Warn("Redis client not initialized, skipping cache set")
		return fmt.Errorf("redis client not initialized")
	}

	key := GetCacheKey(method, path)
	err := cache.Client.Set(ctx, key, content, ttl).Err()
	if err != nil {
		logger.Error("Failed to set cache", zap.Error(err), zap.String("key", key), zap.Duration("ttl", ttl))
		return err
	}

	logger.Debug("Cache set successfully", zap.String("key", key), zap.Duration("ttl", ttl))
	return nil
}

// IncrementRequestCount 增加指定路径的请求计数，返回当前计数
func (h *HealthChecker) IncrementRequestCount(ctx context.Context, path string, ttl time.Duration) int64 {
	key := GetPathReqCountKey(path)
	script := redis.NewScript(`
		local key = KEYS[1]
		local ttl = ARGV[1]
		local count = redis.call('INCR', key)
		redis.call('EXPIRE', key, ttl)
		return count
	`)
	count, err := script.Run(ctx, cache.Client, []string{key}, ttl.Seconds()).Int64()
	if err != nil {
		logger.Error("Failed to increment request count with Lua", zap.Error(err), zap.String("key", key))
		return 0
	}
	return count
}

// NormalizeTarget 规范化目标地址
func NormalizeTarget(target config.RoutingRule) (string, error) {
	if target.Protocol == "grpc" {
		return target.Target, nil
	}
	u, err := url.Parse(target.Target)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

// NormalizeTargetHost 规范化目标主机地址
func NormalizeTargetHost(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return target, err
	}
	return u.Host, nil
}

// startHeartbeat 开始周期性心跳检测
func (h *HealthChecker) startHeartbeat() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.cleanupCh:
			logger.Info("Stopping heartbeat checks")
			return
		case <-ticker.C:
			h.mu.RLock()
			heartbeatInterval := 30 * time.Second
			if h.cfg.Routing.HeartbeatInterval > 0 {
				heartbeatInterval = time.Duration(h.cfg.Routing.HeartbeatInterval) * time.Second
			}
			h.mu.RUnlock()

			h.performHeartbeatCheck()
			ticker.Reset(heartbeatInterval)
		}
	}
}

// performHeartbeatCheck 执行一次心跳检测
func (h *HealthChecker) performHeartbeatCheck() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	logger.Info("Starting heartbeat check",
		zap.Int("targetCount", len(h.healthPaths)),
		zap.String("timestamp", time.Now().Format("2006-01-02 15:04:05")))

	for target, healthPath := range h.healthPaths {
		stat, err := h.loadFromRedis(target)
		if err != nil || stat == nil {
			logger.Warn("Failed to load target stats from Redis",
				zap.String("target", target), zap.Error(err))
			continue
		}

		now := time.Now()
		stat.LastProbeTime = now
		stat.ProbeRequestCount++

		switch stat.Protocol {
		case "http", "":
			h.checkHTTP(target, healthPath, stat)
		case "grpc":
			h.checkGRPC(target, stat)
		case "websocket":
			h.checkWebSocket(stat.URL, healthPath, stat)
		default:
			logger.Warn("Unsupported protocol, skipping health check",
				zap.String("protocol", stat.Protocol),
				zap.String("target", target))
		}

		// 保存更新后的状态到 Redis
		err = h.saveToRedis(target, stat)
		if err != nil {
			logger.Error("Failed to save target stats to Redis",
				zap.String("target", target), zap.Error(err))
		}
	}
}

// checkHTTP 检查 HTTP 目标健康状态
func (h *HealthChecker) checkHTTP(target, healthPath string, stat *TargetStatus) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://" + target + healthPath)
	req.Header.SetMethod("HEAD")

	client := &fasthttp.Client{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	err := client.DoTimeout(req, resp, 5*time.Second)
	if err != nil || resp.StatusCode() >= 400 {
		stat.ProbeFailureCount++
		logger.Warn("HTTP heartbeat check failed",
			zap.String("target", target),
			zap.String("healthPath", healthPath),
			zap.Error(err),
			zap.Int("statusCode", resp.StatusCode()))
		return
	}
	stat.ProbeSuccessCount++
	logger.Info("HTTP heartbeat check succeeded",
		zap.String("target", target),
		zap.String("healthPath", healthPath))
}

// checkGRPC 检查 gRPC 目标健康状态
func (h *HealthChecker) checkGRPC(target string, stat *TargetStatus) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, target, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		stat.ProbeFailureCount++
		logger.Warn("gRPC dial failed",
			zap.String("target", target),
			zap.Error(err))
		return
	}
	defer conn.Close()

	healthPath, ok := h.healthPaths[target]
	if !ok {
		healthPath = "" // 默认检查整个服务器
	}

	client := grpc_health_v1.NewHealthClient(conn)
	serviceName := healthPath
	if serviceName == "/health" {
		serviceName = "" // 检查整个服务器
	}

	resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: serviceName})
	if err != nil || (resp != nil && resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING) {
		stat.ProbeFailureCount++
		var statusStr string
		if resp != nil {
			statusStr = resp.GetStatus().String()
		} else {
			statusStr = "UNKNOWN"
		}
		logger.Warn("gRPC health check failed",
			zap.String("target", target),
			zap.String("service", serviceName),
			zap.Error(err),
			zap.String("status", statusStr))
		return
	}

	stat.ProbeSuccessCount++
	logger.Info("gRPC health check succeeded",
		zap.String("target", target),
		zap.String("service", serviceName))
}

// checkWebSocket 检查 WebSocket 目标健康状态
func (h *HealthChecker) checkWebSocket(target, healthPath string, stat *TargetStatus) {
	dialer := websocket.DefaultDialer
	fullURL := target + healthPath
	conn, _, err := dialer.Dial(fullURL, nil)
	if err != nil {
		stat.ProbeFailureCount++
		logger.Warn("WebSocket heartbeat check failed",
			zap.String("target", target),
			zap.String("healthPath", healthPath),
			zap.String("fullURL", fullURL),
			zap.Error(err))
		return
	}
	defer conn.Close()
	stat.ProbeSuccessCount++
	logger.Info("WebSocket heartbeat check succeeded",
		zap.String("target", target),
		zap.String("healthPath", healthPath),
		zap.String("fullURL", fullURL))
}

// UpdateRequestCount 更新业务请求计数
func (h *HealthChecker) UpdateRequestCount(target string, success bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	host, _ := NormalizeTargetHost(target)
	stat, err := h.loadFromRedis(host)
	if err != nil || stat == nil {
		logger.Warn("Target not found in Redis, unable to update request count",
			zap.String("target", target), zap.Error(err))
		return
	}

	stat.RequestCount++
	if success {
		stat.SuccessCount++
	} else {
		stat.FailureCount++
	}
	stat.LastRequestTime = time.Now()

	err = h.saveToRedis(host, stat)
	if err != nil {
		logger.Error("Failed to update target stats in Redis",
			zap.String("target", host), zap.Error(err))
	}
}

// ResetAllStats 重置所有后端目标的状态信息
func (h *HealthChecker) ResetAllStats() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for target := range h.healthPaths {
		stat, err := h.loadFromRedis(target)
		if err != nil || stat == nil {
			continue
		}
		stat.RequestCount = 0
		stat.SuccessCount = 0
		stat.FailureCount = 0
		stat.ProbeRequestCount = 0
		stat.ProbeSuccessCount = 0
		stat.ProbeFailureCount = 0
		stat.LastProbeTime = time.Time{}
		err = h.saveToRedis(target, stat)
		if err != nil {
			logger.Error("Failed to reset target stats in Redis",
				zap.String("target", target), zap.Error(err))
		}
	}
	logger.Info("All target stats reset")
}

// GetAllStats 获取所有后端目标的状态信息
func (h *HealthChecker) GetAllStats() []TargetStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var stats []TargetStatus
	for target := range h.healthPaths {
		stat, err := h.loadFromRedis(target)
		if err != nil {
			logger.Error("Failed to load target stats from Redis",
				zap.String("target", target), zap.Error(err))
			continue
		}
		if stat != nil {
			stats = append(stats, *stat)
		}
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Protocol == stats[j].Protocol {
			return stats[i].URL < stats[j].URL
		}
		if stats[i].Rule == stats[j].Rule {
			return stats[i].Protocol < stats[j].Protocol
		}
		return stats[i].Rule < stats[j].Rule
	})
	return stats
}

// Close 关闭健康检查服务
func (h *HealthChecker) Close() {
	close(h.cleanupCh)
	logger.Info("Health checker service closed")
}
