package router

import (
	"context"
	"net/http"
	"strings"

	"github.com/DoraZa/mini-gateway/internal/core/routing/proxy"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// trieTracer 为 Trie 路由模块初始化追踪器
var trieTracer = otel.Tracer("router:trie")

// TrieRouter 使用 Trie 数据结构管理 HTTP 路由
type TrieRouter struct {
	Trie *Trie // Trie 数据结构实例
}

// Trie 表示用于高效前缀匹配路由的 Trie 数据结构
type Trie struct {
	Root *TrieNode // Trie 的根节点
}

// TrieNode 表示 Trie 中的一个节点，包含子节点和路由规则
type TrieNode struct {
	Children map[rune]*TrieNode  // 子节点映射
	Rules    config.RoutingRules // 路由规则
	IsEnd    bool                // 标记此节点是否为有效路由的终点
}

// NewTrieRouter 创建并初始化 TrieRouter 实例
func NewTrieRouter() *TrieRouter {
	return &TrieRouter{
		Trie: &Trie{
			Root: &TrieNode{Children: make(map[rune]*TrieNode)},
		},
	}
}

// Insert 将路径及其关联的路由规则插入 Trie
func (t *Trie) Insert(path string, rules config.RoutingRules) {
	node := t.Root
	path = strings.TrimPrefix(path, "/") // 规范化路径，去除前导斜杠
	for _, ch := range path {
		if node.Children[ch] == nil {
			node.Children[ch] = &TrieNode{Children: make(map[rune]*TrieNode)}
		}
		node = node.Children[ch]
	}
	node.Rules = rules
	node.IsEnd = true
	logger.Info("Successfully inserted route into TrieRegexp",
		zap.String("path", "/"+path),
		zap.Any("rules", rules))
}

// Search 在 Trie 中查找给定路径的路由规则
func (t *Trie) Search(ctx context.Context, path string) (config.RoutingRules, bool) {
	ctx, span := trieTracer.Start(ctx, "TrieRegexp.Search",
		trace.WithAttributes(attribute.String("path", path)))
	defer span.End()

	node := t.Root
	path = strings.TrimPrefix(path, "/") // 规范化路径，去除前导斜杠
	path = strings.TrimSuffix(path, "/") // 去除尾部斜杠以保持一致性
	for _, ch := range path {
		if node.Children[ch] == nil {
			return nil, false
		}
		node = node.Children[ch]
	}
	if node.IsEnd {
		return node.Rules, true
	}
	return nil, false
}

// Setup 根据配置在 Gin 路由器中设置 TrieRouter 的 HTTP 路由规则
func (tr *TrieRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	// 将所有路由规则插入 TrieRegexp
	for path, targetRules := range rules {
		tr.Trie.Insert(path, targetRules)
	}
	logger.Info("TrieRegexp routing setup completed",
		zap.Int("ruleCount", len(rules)))

	// 中间件：处理路由匹配和代理转发
	r.Use(func(c *gin.Context) {
		// 开始追踪路由匹配过程
		ctx, span := trieTracer.Start(c.Request.Context(), "Routing.Match",
			trace.WithAttributes(attribute.String("type", "TrieRegexp")),
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		logger.Debug("Processing request in TrieRegexp routing middleware",
			zap.String("path", c.Request.URL.Path))
		path := c.Request.URL.Path
		targetRules, found := tr.Trie.Search(ctx, path)
		if !found {
			span.SetStatus(codes.Error, "Route not found")
			logger.Warn("No matching route found",
				zap.String("path", path),
				zap.String("method", c.Request.Method))
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
			c.Abort()
			return
		}

		// 记录和追踪成功匹配的路由
		span.SetAttributes(attribute.String("matched_target", targetRules[0].Target))
		span.SetStatus(codes.Ok, "Route matched successfully")
		logger.Info("Successfully matched route in TrieRegexp",
			zap.String("path", path),
			zap.Any("rules", targetRules))

		// 将追踪上下文传递下游并处理请求
		c.Request = c.Request.WithContext(ctx)
		httpProxy.CreateHTTPHandler(targetRules)(c)
	})
}
