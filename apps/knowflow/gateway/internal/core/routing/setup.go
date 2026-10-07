package routing

import (
	"os"
	"strings"

	"github.com/DoraZa/mini-gateway/internal/core/routing/proxy"
	internalrouter "github.com/DoraZa/mini-gateway/internal/core/routing/router"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// isRegexPattern 检查路径是否包含正则表达式字符
func isRegexPattern(path string) bool {
	return strings.ContainsAny(path, ".*+?()|[]^$\\")
}

// validateRules 验证路由规则与配置的引擎兼容性
func validateRules(cfg *config.Config) {
	engine := cfg.Routing.Engine
	rules := cfg.Routing.Rules

	for path, pathEndpoints := range rules {
		for _, endpoint := range pathEndpoints {
			// 跳过 gRPC 的进一步验证，因其有单独处理
			if endpoint.Protocol == "grpc" {
				continue
			}
			// Gin 引擎原生支持 :param 和 *wildcard 路由，不按正则路由校验。
			if engine == "gin" {
				continue
			}
			// TrieRegexp 引擎不支持正则表达式路径
			if engine == "trie" && isRegexPattern(path) {
				logger.Error("TrieRegexp routing engine does not support regular expression paths",
					zap.String("path", path),
					zap.String("hint", "Use 'trie-regexp' or 'regexp' engine for regex support"))
				os.Exit(1)
			}
			// 除 trie-regexp 和 regexp 外的非正则引擎无法处理正则路径
				if isRegexPattern(path) && engine != "trie-regexp" && engine != "trie_regexp" && engine != "regexp" {
				logger.Error("Routing engine incompatible with regular expression path",
					zap.String("engine", engine),
					zap.String("path", path),
					zap.String("hint", "Use 'trie-regexp' or 'regexp' engine for regex support"))
				os.Exit(1)
			}
		}
	}
}

// Setup 初始化路由引擎并配置路由规则，包括 gRPC 和 WebSocket 代理
func Setup(protected gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	logger.Info("Loading routing rules from configuration",
		zap.Any("rules", cfg.Routing.Rules))
	validateRules(cfg)

	// 根据配置选择并初始化适当的路由引擎
	var router internalrouter.Router
	switch cfg.Routing.Engine {
	case "trie":
		router = internalrouter.NewTrieRouter()
		logger.Info("Initialized TrieRegexp routing engine")
	case "trie-regexp", "trie_regexp": // 支持连字符和下划线两种变体
		router = internalrouter.NewTrieRegexpRouter()
		logger.Info("Initialized TrieRegexp-Regexp routing engine")
	case "regexp":
		router = internalrouter.NewRegexpRouter(cfg)
		logger.Info("Initialized Regexp routing engine")
	case "gin":
		router = internalrouter.NewGinRouter()
		logger.Info("Initialized Gin routing engine")
	default:
		logger.Warn("Unknown routing engine specified, defaulting to Gin",
			zap.String("engine", cfg.Routing.Engine))
		router = internalrouter.NewGinRouter()
	}

	// 为 gRPC 和 WebSocket 路由创建分组，使用配置中的前缀
	grpcGroup := protected.Group(cfg.GRPC.Prefix)
	wsGroup := protected.Group(cfg.WebSocket.Prefix)

	// 配置 HTTP 路由
	router.Setup(protected, httpProxy, cfg)

	// 如果启用且存在规则，配置 gRPC 代理
	if cfg.GRPC.Enabled && len(cfg.Routing.GetGrpcRules()) > 0 {
		proxy.SetupGRPCProxy(cfg, grpcGroup)
	}

	// 如果启用且存在规则，配置 WebSocket 代理
	if cfg.WebSocket.Enabled && len(cfg.Routing.GetWebSocketRules()) > 0 {
		wsProxy := proxy.NewWebSocketProxy(cfg)
		wsProxy.SetupWebSocketProxy(wsGroup, cfg)
		logger.Info("WebSocket proxy configured successfully")
	}

	// 为特定引擎中的动态路由注册空处理器
	switch cfg.Routing.Engine {
	case "trie", "trie-regexp", "trie_regexp", "regexp":
		for p := range cfg.Routing.GetHTTPRules() {
			// 空处理器依赖特定 Router 实现中的中间件
			protected.Any(p, func(c *gin.Context) {})
		}
	}
}
