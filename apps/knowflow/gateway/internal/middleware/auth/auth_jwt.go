package auth

import (
	"net/http"
	"strings"

	"github.com/DoraZa/mini-gateway/internal/core/observability"
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

var jwtTracer = otel.Tracer("auth:jwt") // 定义认证模块的 Tracer

type JWTAuthenticator struct {
	cfg *config.Config
}

func (j *JWTAuthenticator) Authenticate(c *gin.Context) {
	_, span := jwtTracer.Start(c.Request.Context(), "Auth.JWT",
		trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
	defer span.End()

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		span.SetStatus(codes.Error, "Authorization header required")
		logger.Warn("No Authorization header provided")
		observability.JwtAuthFailures.WithLabelValues(c.Request.URL.Path).Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		c.Abort()
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		span.SetStatus(codes.Error, "Invalid Authorization header")
		logger.Warn("Invalid Authorization header format")
		observability.JwtAuthFailures.WithLabelValues(c.Request.URL.Path).Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header"})
		c.Abort()
		return
	}

	token := parts[1]
	claims, err := security.ValidateToken(token)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Invalid JWT token")
		logger.Warn("Invalid JWT token", zap.Error(err))
		observability.JwtAuthFailures.WithLabelValues(c.Request.URL.Path).Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		c.Abort()
		return
	}
	span.SetAttributes(attribute.String("username", claims.Username))
	span.SetStatus(codes.Ok, "Authentication succeeded")
	c.Set("username", claims.Username)
	c.Next()
}
