package plugins

import (
	"context"

	"github.com/gin-gonic/gin"
)

type PluginInterface interface {
	PluginInfo() Info

	Setup(r gin.IRouter)               // 插件注册方法
	Execute(ctx context.Context) error // 插件注册方法
}
