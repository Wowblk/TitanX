package auth

import (
	"github.com/DoraZa/mini-gateway/config"
	"github.com/gin-gonic/gin"
)

// Authenticator 定义认证器接口
type Authenticator interface {
	Authenticate(c *gin.Context)
}

// NewAuthenticator 创建认证器实例
func NewAuthenticator(cfg *config.Config) Authenticator {
	switch cfg.Security.AuthMode {
	case "jwt":
		return &JWTAuthenticator{cfg: cfg}
	case "rbac":
		return &RBACAuthenticator{cfg: cfg}
	default:
		return &NoopAuthenticator{}
	}
}

// NoopAuthenticator 无认证实现
type NoopAuthenticator struct{}

func (n *NoopAuthenticator) Authenticate(c *gin.Context) {
	c.Next()
}
