package security

import (
	"context"
	"net/http"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/observability"
	"github.com/DoraZa/mini-gateway/pkg/cache"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	blacklistKey = "mg:ip_blacklist" // Cache 中 IP 黑名单的键
	whitelistKey = "mg:ip_whitelist" // Cache 中 IP 白名单的键
)

// InitIPRules 将 IP 黑白名单初始化到 Cache
func InitIPRules(cfg *config.Config) {
	ctx := context.Background()

	// 根据 IPUpdateMode 决定覆盖还是追加
	if cfg.Security.IPUpdateMode == "override" {
		err := cache.Client.Del(ctx, blacklistKey, whitelistKey).Err()
		if err != nil {
			logger.Error("Failed to clear IP rules in Cache",
				zap.Error(err))
		} else {
			logger.Info("Existing IP rules cleared in override mode")
		}
	}

	// 初始化白名单
	if len(cfg.Security.IPWhitelist) > 0 {
		for _, ip := range cfg.Security.IPWhitelist {
			err := cache.Client.HSet(ctx, whitelistKey, ip, "true").Err()
			if err != nil {
				logger.Error("Failed to initialize IP whitelist in Cache",
					zap.String("ip", ip),
					zap.Error(err))
			}
		}
		logger.Info("IP whitelist initialized successfully",
			zap.Strings("ips", cfg.Security.IPWhitelist))
	}

	// 初始化黑名单
	if len(cfg.Security.IPBlacklist) > 0 {
		for _, ip := range cfg.Security.IPBlacklist {
			err := cache.Client.HSet(ctx, blacklistKey, ip, "true").Err()
			if err != nil {
				logger.Error("Failed to initialize IP blacklist in Cache",
					zap.String("ip", ip),
					zap.Error(err))
			}
		}
		logger.Info("IP blacklist initialized successfully",
			zap.Strings("ips", cfg.Security.IPBlacklist))
	}
}

// IPAcl 中间件实现 IP 黑白名单检查
func IPAcl() gin.HandlerFunc {
	cfg := config.GetConfig()
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		ctx := context.Background()

		allowed, err := CheckIPAccess(ctx, clientIP, cfg)
		if err != nil {
			logger.Error("Failed to check IP access",
				zap.String("ip", clientIP),
				zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}

		if !allowed {
			logger.Warn("IP access denied",
				zap.String("ip", clientIP))
			observability.IPAclRejections.WithLabelValues(c.Request.URL.Path, clientIP).Inc()
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied by IP policy"})
			c.Abort()
			return
		}

		logger.Debug("IP access permitted",
			zap.String("ip", clientIP))
		c.Next()
	}
}

// CheckIPAccess 检查 IP 是否被允许访问
func CheckIPAccess(ctx context.Context, ip string, cfg *config.Config) (bool, error) {
	// 检查白名单（优先级最高）
	if len(cfg.Security.IPWhitelist) > 0 {
		isWhitelisted, err := cache.Client.HGet(ctx, whitelistKey, ip).Bool()
		if err != nil && err != redis.Nil {
			return false, err
		}
		if isWhitelisted {
			return true, nil
		}
		return false, nil // 白名单模式下，未列入白名单的 IP 被拒绝
	}

	// 检查黑名单
	if len(cfg.Security.IPBlacklist) > 0 {
		isBlacklisted, err := cache.Client.HGet(ctx, blacklistKey, ip).Bool()
		if err != nil && err != redis.Nil {
			return false, err
		}
		if isBlacklisted {
			return false, nil
		}
	}

	return true, nil // 无白名单且不在黑名单时允许
}
