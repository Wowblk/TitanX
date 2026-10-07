package main

import (
	"context"
	"log"

	"github.com/DoraZa/mini-gateway/plugins"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-version"
)

const (
	pluginName        = "Ping"
	pluginDescription = "Ping plugin"
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

type PingPlugin struct {
}

func (i PingPlugin) PluginInfo() plugins.Info {
	return PluginInfo()
}

func (i PingPlugin) Execute(ctx context.Context) error {
	log.Println("PingPlugin")
	return nil
}

func (i PingPlugin) Setup(r gin.IRouter) {
	log.Println("PingPlugin Setup")
}

func NewPlugin() plugins.PluginInterface {
	return &PingPlugin{}
}
