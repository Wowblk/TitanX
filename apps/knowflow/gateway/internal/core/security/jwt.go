package security

import (
	"fmt"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var jwtSecret string // JWT 密钥，全局变量

// Claims 自定义 JWT Claims 结构
type Claims struct {
	Username string `json:"username"` // 用户名
	Age      string `json:"age"`
	Platform string `json:"platform"`
	jwt.RegisteredClaims
}

// InitJWT 初始化 JWT 配置
func InitJWT(cfg *config.Config) {
	jwtSecret = cfg.Security.JWT.Secret
	if jwtSecret == "" {
		logger.Warn("JWT secret not configured, defaulting to placeholder")
		jwtSecret = "default-secret-key" // 测试用默认密钥，生产环境需配置强密钥
	}
	logger.Info("JWT configuration initialized",
		zap.Bool("customSecret", cfg.Security.JWT.Secret != ""))
}

// GenerateToken 生成 JWT Token
func GenerateToken(username string) (string, error) {
	cfg := config.GetConfig()
	if jwtSecret == "" {
		InitJWT(cfg)
	}

	expirationTime := time.Now().Add(time.Duration(cfg.Security.JWT.ExpiresIn) * time.Second)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // 过期时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // 签发时间
			Subject:   username,                           // 主题（用户名）
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		logger.Error("Failed to generate JWT token",
			zap.String("username", username),
			zap.Error(err))
		return "", err
	}

	logger.Debug("JWT token generated successfully",
		zap.String("username", username),
		zap.Time("expiresAt", expirationTime))
	return signedToken, nil
}

// ValidateToken 验证 JWT Token
func ValidateToken(tokenString string) (*Claims, error) {
	if jwtSecret == "" {
		InitJWT(config.GetConfig())
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			logger.Warn("Invalid JWT signing method",
				zap.Any("algorithm", token.Header["alg"]))
			return nil, err
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		logger.Warn("Failed to parse JWT token",
			zap.Error(err))
		return nil, err
	}

	if !token.Valid {
		logger.Warn("JWT token validation failed",
			zap.String("token", tokenString))
		return nil, fmt.Errorf("invalid JWT token")
	}

	logger.Debug("JWT token validated successfully",
		zap.String("username", claims.Username),
		zap.Time("expiresAt", claims.ExpiresAt.Time))
	return claims, nil
}
