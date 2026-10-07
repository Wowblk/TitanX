package proxy

import (
	"sync"
	"time"

	"github.com/DoraZa/mini-gateway/pkg/util"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// WebSocketPool 管理 WebSocket 连接池
type WebSocketPool struct {
	pool      map[string]*websocket.Conn // 目标地址到连接的映射
	mu        sync.RWMutex               // 读写锁，确保并发安全
	maxIdle   int                        // 允许的最大空闲连接数
	idleTime  time.Duration              // 空闲连接关闭的超时时间
	dialer    *websocket.Dialer          // WebSocket 拨号器
	poolMgr   *util.ObjectPoolManager    // 可重用对象池管理器
	cleanupCh chan struct{}              // 清理终止信号通道
}

// NewWebSocketPool 根据配置创建并初始化 WebSocket 连接池
func NewWebSocketPool(cfg *config.Config) *WebSocketPool {
	pool := &WebSocketPool{
		pool:      make(map[string]*websocket.Conn),
		maxIdle:   cfg.WebSocket.MaxIdleConns, // 未指定时默认为 10
		idleTime:  cfg.WebSocket.IdleTimeout,  // 未指定时默认为 5 分钟
		dialer:    websocket.DefaultDialer,
		cleanupCh: make(chan struct{}),
		poolMgr:   util.NewPoolManager(cfg), // 初始化对象池管理器
	}
	go pool.startCleanup() // 启动后台清理协程
	logger.Info("WebSocket connection pool initialized",
		zap.Int("maxIdle", pool.maxIdle),
		zap.Duration("idleTimeout", pool.idleTime))
	return pool
}

// GetConn 获取现有 WebSocket 连接或为目标创建新连接
func (p *WebSocketPool) GetConn(target string) (*websocket.Conn, error) {
	p.mu.RLock()
	if conn, ok := p.pool[target]; ok && conn != nil {
		p.mu.RUnlock()
		return conn, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// 双重检查锁，避免竞争条件
	if conn, ok := p.pool[target]; ok && conn != nil {
		return conn, nil
	}

	// 建立新的 WebSocket 连接
	conn, resp, err := p.dialer.Dial(target, nil)
	if err != nil {
		logger.Error("Failed to establish WebSocket connection",
			zap.String("target", target),
			zap.Error(err))
		if resp != nil {
			logger.Debug("WebSocket handshake response",
				zap.Int("statusCode", resp.StatusCode))
		}
		return nil, err
	}

	p.pool[target] = conn
	logger.Info("Successfully established WebSocket connection",
		zap.String("target", target))
	return conn, nil
}

// ReleaseConn 标记连接为待释放，实际清理由清理协程处理
func (p *WebSocketPool) ReleaseConn(target string) {
	// 不立即操作，依赖清理协程管理连接关闭
}

// Close 关闭连接池并清理所有活跃连接
func (p *WebSocketPool) Close() {
	close(p.cleanupCh) // 通知清理协程停止
	p.mu.Lock()
	defer p.mu.Unlock()

	for target, conn := range p.pool {
		if err := conn.Close(); err != nil {
			logger.Warn("Failed to close WebSocket connection",
				zap.String("target", target),
				zap.Error(err))
		}
		delete(p.pool, target)
	}
	logger.Info("WebSocket connection pool closed",
		zap.Int("closedConnections", len(p.pool)))
}

// startCleanup 定期清理超出 maxIdle 限制的空闲连接
func (p *WebSocketPool) startCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.cleanupCh:
			logger.Info("WebSocket pool cleanup routine stopped")
			return // 清理通道关闭时退出
		case <-ticker.C:
			p.mu.Lock()
			if len(p.pool) <= p.maxIdle {
				p.mu.Unlock()
				continue // 如果连接数在限制内，跳过清理
			}

			// 使用对象池管理器获取可重用切片
			targets := p.poolMgr.GetTargets(len(p.pool))
			for target := range p.pool {
				targets = append(targets, target)
			}

			// 关闭连接直到符合 maxIdle 限制
			for _, target := range targets {
				if len(p.pool) <= p.maxIdle {
					break
				}
				if conn, ok := p.pool[target]; ok {
					if err := conn.Close(); err != nil {
						logger.Warn("Failed to close idle WebSocket connection",
							zap.String("target", target),
							zap.Error(err))
					}
					delete(p.pool, target)
					logger.Info("Successfully closed idle WebSocket connection",
						zap.String("target", target))
				}
			}

			// 将切片归还对象池
			p.poolMgr.PutTargets(targets)
			p.mu.Unlock()
		}
	}
}
