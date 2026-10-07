package main

import (
	"context"
	"log"
	"time"

	"github.com/DoraZa/mini-gateway/plugins"
	"github.com/hashicorp/go-version"

	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	pluginName        = "Log"
	pluginDescription = "Log plugin"
	pluginVersion     = "1.0.0"
)

func PluginInfo() plugins.Info {
	plugVersion, _ := version.NewVersion(pluginVersion)
	return plugins.Info{
		Name:        pluginName,
		Description: pluginDescription,
		Signature:   plugins.SIGNATURE,
		Version:     plugVersion,
	}
}

type LogPlugin struct{}

func (p *LogPlugin) PluginInfo() plugins.Info {
	return PluginInfo()
}

func (p *LogPlugin) Setup(r gin.IRouter) {
	r.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		logger.Info("Request processed",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", latency),
		)
	})
}

func (p *LogPlugin) Execute(ctx context.Context) error {
	log.Println("Log")
	return nil

}

func NewPlugin() plugins.PluginInterface {
	return &LogPlugin{}
}
