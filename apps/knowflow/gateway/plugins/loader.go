package plugins

import (
	"errors"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var loadedPlugins = make(map[string]PluginInterface)

// LoadPlugins 扫描插件目录并动态加载 .so 文件中的插件
func LoadPlugins(r gin.IRouter, cfg *config.Config) {
	pluginDir := cfg.Plugin.Dir
	if pluginDir == "" {
		logger.Warn("Plugin directory not specified in config, skipping plugin loading")
		return
	}

	// 如果指定了插件名称列表，则只加载匹配的插件
	pluginNames := make(map[string]bool)
	for _, name := range cfg.Plugin.Plugins {
		pluginNames[name] = true
	}
	loadAll := len(cfg.Plugin.Plugins) == 0

	// 读取插件目录
	files, err := os.ReadDir(pluginDir)
	if err != nil {
		logger.Error("Failed to read plugin directory",
			zap.String("dir", pluginDir),
			zap.Error(err))
		return
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".so") {
			continue
		}

		pluginPath := filepath.Join(pluginDir, file.Name())
		pluginName := strings.TrimSuffix(file.Name(), ".so")

		// 如果指定了插件名称列表且当前插件不在列表中，跳过
		if !loadAll && !pluginNames[pluginName] {
			logger.Debug("Skipping plugin not in config list",
				zap.String("plugin", pluginName))
			continue
		}

		// 加载插件
		p, err := loadPlugin(pluginPath)
		if err != nil {
			logger.Error("Failed to load plugin",
				zap.String("path", pluginPath),
				zap.Error(err))
			continue
		}

		loadedPlugins[pluginName] = p
		// 注册插件
		p.Setup(r)
		logger.Info("Plugin loaded successfully",
			zap.String("name", p.PluginInfo().Name),
			zap.String("description", p.PluginInfo().Description),
			zap.Any("version", p.PluginInfo().Version),
			zap.String("path", pluginPath))
	}
}

// loadPlugin 从 .so 文件加载插件实例
func loadPlugin(path string) (PluginInterface, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	// 查找插件中导出的 "NewPlugin" 符号
	pluginSymbol, err := p.Lookup("NewPlugin")
	if err != nil {
		return nil, err
	}

	// 确保符号是函数类型并返回 Plugin 接口

	pluginInfoSymbolFunc, ok := pluginSymbol.(func() PluginInterface)
	if !ok {
		return nil, errors.New("invalid Plugin")
	}

	return pluginInfoSymbolFunc(), nil
}

func GetLoadedPlugins() []PluginInterface {
	var pluginsList []PluginInterface
	for _, p := range loadedPlugins {
		pluginsList = append(pluginsList, p)
	}
	return pluginsList
}
