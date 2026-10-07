package proxy

import (
	"net/url"
	"sync"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

const (
	defaultMaxIdleConnDuration = 30 * time.Second // 默认最大空闲连接持续时间
	defaultReadTimeout         = 5 * time.Second  // 默认读取超时
	defaultWriteTimeout        = 5 * time.Second  // 默认写入超时
)

// HTTPConnectionPool 管理 TCP 连接池
type HTTPConnectionPool struct {
	clients   sync.Map // map[string]*fasthttp.HostClient，使用 sync.Map 提升并发性能
	cfg       *config.Config
	cleanupCh chan struct{} // 清理信号通道
}

// NewHTTPConnectionPool 创建并初始化连接池实例
func NewHTTPConnectionPool(cfg *config.Config) *HTTPConnectionPool {
	pool := &HTTPConnectionPool{
		cfg:       cfg,
		cleanupCh: make(chan struct{}),
	}

	if cfg.Performance.HttpPoolEnabled {
		pool.initializePool(cfg)
	} else {
		logger.Info("HTTP connection pool disabled in configuration")
	}
	return pool
}

// initializePool 根据配置初始化连接池中的目标
func (p *HTTPConnectionPool) initializePool(cfg *config.Config) {
	var initializedCount int
	rules := cfg.Routing.GetHTTPRules()

	for _, targetRules := range rules {
		for _, rule := range targetRules {
			if host, err := normalizeTarget(rule.Target); err != nil {
				logger.Error("Invalid target address detected",
					zap.String("target", rule.Target),
					zap.Error(err))
			} else if _, loaded := p.clients.LoadOrStore(host, p.newHostClient(host)); !loaded {
				initializedCount++
				logger.Info("Initialized HostClient for target",
					zap.String("host", host))
			}
		}
	}

	logger.Info("HTTP connection pool initialized successfully",
		zap.Int("initializedTargets", initializedCount))
}

// GetClient 获取或创建指定目标的 HostClient
func (p *HTTPConnectionPool) GetClient(target string) (*fasthttp.HostClient, error) {
	host, err := normalizeTarget(target)
	if err != nil {
		logger.Error("Failed to normalize target address",
			zap.String("target", target),
			zap.Error(err))
		return nil, err
	}

	if client, ok := p.clients.Load(host); ok {
		return client.(*fasthttp.HostClient), nil
	}

	client, _ := p.clients.LoadOrStore(host, p.newHostClient(host))
	logger.Info("Dynamically created new HostClient",
		zap.String("host", host))
	return client.(*fasthttp.HostClient), nil
}

// normalizeTarget 从目标 URL 中提取 host:port
func normalizeTarget(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return target, nil // 处理目标已是 host:port 的情况
	}
	return u.Host, nil
}

// Close 关闭连接池
func (p *HTTPConnectionPool) Close() {
	close(p.cleanupCh)
	p.clients.Range(func(key, value interface{}) bool {
		p.clients.Delete(key)
		return true
	})
	logger.Info("HTTP connection pool closed")
}

// newHostClient 创建新的 HostClient 并应用配置设置
func (p *HTTPConnectionPool) newHostClient(addr string) *fasthttp.HostClient {
	return &fasthttp.HostClient{
		Addr:                addr,
		MaxConns:            p.cfg.Performance.MaxConnsPerHost,
		MaxIdleConnDuration: defaultMaxIdleConnDuration,
		ReadTimeout:         defaultReadTimeout,
		WriteTimeout:        defaultWriteTimeout,
	}
}
