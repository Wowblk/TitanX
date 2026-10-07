package security

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/casbin/casbin/v2"
	"github.com/denisbrodbeck/machineid"
	"go.uber.org/zap"
)

var (
	enforcer   *casbin.Enforcer          // Casbin 权限执行器
	tokenStore = make(map[string]string) // 存储 RBAC 登录 Token 的映射
)

// InitRBAC 初始化 Casbin RBAC 规则
func InitRBAC(cfg *config.Config) error {
	// 从 CSV 文件加载策略
	e, err := casbin.NewEnforcer(cfg.Security.RBAC.ModelPath, cfg.Security.RBAC.PolicyPath)
	if err != nil {
		logger.Error("Failed to initialize Casbin enforcer",
			zap.String("modelPath", cfg.Security.RBAC.ModelPath),
			zap.String("policyPath", cfg.Security.RBAC.PolicyPath),
			zap.Error(err))
		return err // 致命错误，生产环境可考虑优雅处理
	}
	enforcer = e

	// 获取已加载的策略用于调试
	loadedPolicies, err := enforcer.GetPolicy()
	if err != nil {
		logger.Warn("Failed to retrieve loaded RBAC policies",
			zap.Error(err))
	}
	logger.Info("RBAC initialized successfully",
		zap.Bool("enabled", cfg.Security.RBAC.Enabled),
		zap.String("modelPath", cfg.Security.RBAC.ModelPath),
		zap.String("policyPath", cfg.Security.RBAC.PolicyPath),
		zap.Any("loadedPolicies", loadedPolicies))
	return nil
}

// GenerateRBACLoginToken 生成基于机器 ID 的 RBAC 登录 Token
func GenerateRBACLoginToken(username string) (string, error) {
	// 获取机器唯一 ID
	machineID, err := machineid.ProtectedID("mini-gateway")
	if err != nil {
		logger.Error("Failed to obtain machine ID",
			zap.Error(err))
		return "", err
	}

	// 组合机器 ID、用户名和时间戳
	rawToken := fmt.Sprintf("%s-%s-%d", machineID, username, time.Now().UnixNano())

	// 计算 SHA256 哈希并编码为 Base64
	hash := sha256.Sum256([]byte(rawToken))
	token := base64.URLEncoding.EncodeToString(hash[:])

	// 存储 Token
	tokenStore[token] = username
	logger.Debug("RBAC login token generated successfully",
		zap.String("username", username),
		zap.String("token", token))

	return token, nil
}

// ValidateRBACLoginToken 验证 RBAC 登录 Token
func ValidateRBACLoginToken(token string) (string, bool) {
	// 生产环境需要考虑 Token 过期和撤销机制，以及分布式存储
	username, exists := tokenStore[token]
	if !exists {
		logger.Warn("RBAC login token validation failed",
			zap.String("token", token))
		return "", false
	}
	logger.Debug("RBAC login token validated successfully",
		zap.String("token", token),
		zap.String("username", username))
	return username, true
}

// CheckPermission 检查用户权限
func CheckPermission(sub, obj, act string) bool {
	if enforcer == nil {
		logger.Warn("Casbin enforcer not initialized, permission check aborted")
		return false
	}
	ok, err := enforcer.Enforce(sub, obj, act)
	if err != nil {
		logger.Error("Failed to enforce RBAC permission",
			zap.String("subject", sub),
			zap.String("object", obj),
			zap.String("action", act),
			zap.Error(err))
		return false
	}
	if !ok {
		logger.Debug("Permission denied by RBAC policy",
			zap.String("subject", sub),
			zap.String("object", obj),
			zap.String("action", act))
	}
	return ok
}
