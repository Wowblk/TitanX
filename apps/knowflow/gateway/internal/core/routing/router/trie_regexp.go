package router

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/internal/core/routing/proxy"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var trieRegexpTracer = otel.Tracer("router:trie-regexp")

type TrieRegexpRouter struct {
	TrieRegexp *TrieRegexp
}

type TrieRegexp struct {
	Root *TrieRegexpNode
}

type TrieRegexpNode struct {
	Children   map[rune]*TrieRegexpNode
	Rules      config.RoutingRules
	IsEnd      bool
	RegexRules []RegexRule // 存储多个正则规则
}

type RegexRule struct {
	Regex   *regexp.Regexp
	Pattern string
	Rules   config.RoutingRules
}

func NewTrieRegexpRouter() *TrieRegexpRouter {
	return &TrieRegexpRouter{
		TrieRegexp: &TrieRegexp{
			Root: &TrieRegexpNode{Children: make(map[rune]*TrieRegexpNode)},
		},
	}
}

func (t *TrieRegexp) Insert(path string, rules config.RoutingRules) {
	node := t.Root
	originalPath := path

	if strings.ContainsAny(path, ".*+?()|[]^$\\") {
		re, err := regexp.Compile("^" + path + "$")
		if err != nil {
			logger.Error("Failed to compile regular expression pattern",
				zap.String("path", originalPath),
				zap.Error(err))
			return
		}
		node.RegexRules = append(node.RegexRules, RegexRule{
			Regex:   re,
			Pattern: path,
			Rules:   rules,
		})
		logger.Info("Successfully inserted regex route into TrieRegexp",
			zap.String("pattern", originalPath),
			zap.Any("rules", rules))
		return
	}

	cleanPath := strings.TrimPrefix(path, "/")
	for _, ch := range cleanPath {
		if node.Children[ch] == nil {
			node.Children[ch] = &TrieRegexpNode{Children: make(map[rune]*TrieRegexpNode)}
		}
		node = node.Children[ch]
	}
	node.Rules = rules
	node.IsEnd = true
	logger.Info("Successfully inserted static route into TrieRegexp",
		zap.String("path", originalPath),
		zap.Any("rules", rules))
}

func (t *TrieRegexp) Search(ctx context.Context, path string) (config.RoutingRules, bool) {
	ctx, span := trieRegexpTracer.Start(ctx, "TrieRegexp.Search",
		trace.WithAttributes(attribute.String("path", path)))
	defer span.End()

	node := t.Root
	cleanPath := strings.TrimPrefix(path, "/")

	for _, ch := range cleanPath {
		if node.Children[ch] == nil {
			break
		}
		node = node.Children[ch]
	}
	if node != nil && node.IsEnd {
		return node.Rules, true
	}

	// 检查所有正则规则
	for _, regexRule := range t.Root.RegexRules {
		if regexRule.Regex.MatchString(path) {
			return regexRule.Rules, true
		}
	}

	return nil, false
}

func (tr *TrieRegexpRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	for path, targetRules := range rules {
		tr.TrieRegexp.Insert(path, targetRules)
	}

	r.Use(func(c *gin.Context) {
		ctx, span := trieRegexpTracer.Start(c.Request.Context(), "Routing.Match",
			trace.WithAttributes(attribute.String("type", "TrieRegexp")),
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		path := c.Request.URL.Path
		targetRules, found := tr.TrieRegexp.Search(ctx, path)
		if !found {
			logger.Warn("No matching route found",
				zap.String("path", path),
				zap.String("method", c.Request.Method))
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
			c.Abort()
			span.SetStatus(codes.Error, "Route not found")
			return
		}

		span.SetAttributes(attribute.String("matched_target", targetRules[0].Target))
		span.SetStatus(codes.Ok, "Route matched successfully")
		logger.Info("Successfully matched route in TrieRegexp",
			zap.String("path", path),
			zap.Any("rules", targetRules))

		c.Request = c.Request.WithContext(ctx)
		httpProxy.CreateHTTPHandler(targetRules)(c)
	})
}
