package auth

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/security"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var rbacTracer = otel.Tracer("auth:rbac") // 定义认证模块的 Tracer

type RBACAuthenticator struct {
	cfg *config.Config
}

func (r *RBACAuthenticator) Authenticate(c *gin.Context) {
	if !r.cfg.Security.RBAC.Enabled {
		c.Next()
		return
	}

	_, span := rbacTracer.Start(c.Request.Context(), "Auth.RBAC",
		trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
	defer span.End()

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		span.SetStatus(codes.Error, "Authorization header required")
		logger.Warn("No Authorization header provided for RBAC")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		c.Abort()
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		span.SetStatus(codes.Error, "Invalid Authorization header")
		logger.Warn("Invalid Authorization header format for RBAC")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
		c.Abort()
		return
	}

	token := parts[1]
	username, valid := security.ValidateRBACLoginToken(token)
	if !valid {
		span.SetStatus(codes.Error, "Invalid RBAC token")
		logger.Warn("Invalid RBAC token")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid rbac token"})
		c.Abort()
		return
	}

	c.Set("username", username)

	sub := username
	obj := c.Request.URL.Path
	act := c.Request.Method

	if !security.CheckPermission(sub, obj, act) {
		span.SetStatus(codes.Error, "RBAC permission denied")
		logger.Warn("RBAC permission denied",
			zap.String("subject", sub),
			zap.String("object", obj),
			zap.String("action", act),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		c.Abort()
		return
	}

	span.SetAttributes(attribute.String("subject", sub))
	span.SetAttributes(attribute.String("object", obj))
	span.SetAttributes(attribute.String("action", act))
	span.SetStatus(codes.Ok, "Authentication succeeded")
	logger.Debug("RBAC permission granted",
		zap.String("subject", sub),
		zap.String("object", obj),
		zap.String("action", act),
	)
	c.Next()
}
