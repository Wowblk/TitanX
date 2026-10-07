package router

import (
	"strings"
	"testing"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// setupLogger 为测试配置日志捕获
func setupLogger() (*zap.Logger, *observer.ObservedLogs) {
	// 创建观察者核心，用于捕获日志
	obsCore, recorded := observer.New(zapcore.DebugLevel)

	// 创建并配置 zap.Logger
	zapLogger := zap.New(obsCore, zap.AddCaller(), zap.AddCallerSkip(1))

	// 替换全局日志实例
	zap.ReplaceGlobals(zapLogger)

	// 初始化 logger 包，确保使用我们提供的 zapLogger
	logger.Init(logger.Config{
		Level:    "debug",
		FilePath: "", // 不写入文件，仅内存捕获
	})

	return zapLogger, recorded
}

func TestNewTrieRegexpRouter(t *testing.T) {
	router := NewTrieRegexpRouter()

	assert.NotNil(t, router, "Expected router to be initialized")
	assert.NotNil(t, router.TrieRegexp, "Expected TrieRegexp to be initialized")
	assert.NotNil(t, router.TrieRegexp.Root, "Expected Root node to be initialized")
	assert.NotNil(t, router.TrieRegexp.Root.Children, "Expected Children map to be initialized")
	assert.Empty(t, router.TrieRegexp.Root.Children, "Expected Children map to be empty")
	assert.Nil(t, router.TrieRegexp.Root.Rules, "Expected Rules to be nil initially")
	assert.False(t, router.TrieRegexp.Root.IsEnd, "Expected IsEnd to be false initially")
	assert.Empty(t, router.TrieRegexp.Root.RegexRules, "Expected RegexRules to be empty initially")
}

func TestTrieRegexpInsert(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		rules       config.RoutingRules
		wantIsEnd   bool
		wantRegex   bool
		wantPattern string
		wantError   bool
	}{
		{
			name:      "Insert static path",
			path:      "/api/v1",
			rules:     config.RoutingRules{{Target: "http://localhost:8080"}},
			wantIsEnd: true,
			wantRegex: false,
		},
		{
			name:        "Insert regex path",
			path:        "/api/v2/.*",
			rules:       config.RoutingRules{{Target: "http://localhost:8081"}},
			wantIsEnd:   false,
			wantRegex:   true,
			wantPattern: "/api/v2/.*",
		},
		{
			name:      "Insert empty path as static",
			path:      "",
			rules:     config.RoutingRules{{Target: "http://localhost:8082"}},
			wantIsEnd: true,
			wantRegex: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置日志捕获
			_, recordedLogs := setupLogger()

			trie := &TrieRegexp{Root: &TrieRegexpNode{Children: make(map[rune]*TrieRegexpNode)}}
			trie.Insert(tt.path, tt.rules)

			// 在检查日志前同步，确保缓冲区被刷新
			logger.Sync()

			if tt.wantRegex {
				assert.Len(t, trie.Root.RegexRules, 1, "Expected one regex rule for path %v", tt.path)
				assert.Equal(t, tt.wantPattern, trie.Root.RegexRules[0].Pattern, "Expected RegexPattern to match for path %v", tt.path)
				assert.Equal(t, tt.rules, trie.Root.RegexRules[0].Rules, "Expected Rules to match for path %v", tt.path)
				assert.False(t, trie.Root.IsEnd, "Expected IsEnd to be false for regex path %v", tt.path)
			} else if !tt.wantError {
				node := trie.Root
				cleanPath := strings.TrimPrefix(tt.path, "/")
				for _, ch := range cleanPath {
					node = node.Children[ch]
					assert.NotNil(t, node, "Expected node for character %v in path %v", ch, tt.path)
				}
				assert.Equal(t, tt.wantIsEnd, node.IsEnd, "Expected IsEnd to be %v for path %v", tt.wantIsEnd, tt.path)
				assert.Equal(t, tt.rules, node.Rules, "Expected Rules to match for path %v", tt.path)
				assert.Empty(t, node.RegexRules, "Expected RegexRules to be empty for static path %v", tt.path)
			} else {
				assert.Empty(t, trie.Root.RegexRules, "Expected RegexRules to remain empty for invalid regex path %v", tt.path)
				assert.Empty(t, trie.Root.Children, "Expected Children to remain empty for invalid regex path %v", tt.path)
				assert.False(t, trie.Root.IsEnd, "Expected IsEnd to remain false for invalid regex path %v", tt.path)
				assert.Nil(t, trie.Root.Rules, "Expected Rules to remain nil for invalid regex path %v", tt.path)

				// 验证错误日志
				logs := recordedLogs.All()
				if !assert.Equal(t, 1, len(logs), "Expected one error log entry for invalid regex path %v", tt.path) {
					t.Logf("Captured logs: %v", logs)
				} else {
					assert.Equal(t, "Failed to compile regular expression pattern", logs[0].Message, "Expected error message")
					assert.Equal(t, tt.path, logs[0].ContextMap()["path"], "Expected path in log")
					assert.Contains(t, logs[0].ContextMap()["error"], "missing closing ]", "Expected error detail in log")
				}
			}
		})
	}
}

func TestTrieRegexpSearch(t *testing.T) {
	trie := &TrieRegexp{Root: &TrieRegexpNode{Children: make(map[rune]*TrieRegexpNode)}}
	rulesStatic := config.RoutingRules{{Target: "http://localhost:8080"}}
	rulesRegex := config.RoutingRules{{Target: "http://localhost:8081"}}
	rulesRoot := config.RoutingRules{{Target: "http://localhost:8082"}}

	trie.Insert("/api/v1", rulesStatic)
	trie.Insert("/api/v2/.*", rulesRegex)
	trie.Insert("/", rulesRoot)

	tests := []struct {
		name      string
		path      string
		wantRules config.RoutingRules
		wantFound bool
	}{
		{
			name:      "Search static path",
			path:      "/api/v1",
			wantRules: rulesStatic,
			wantFound: true,
		},
		{
			name:      "Search regex path match",
			path:      "/api/v2/test",
			wantRules: rulesRegex,
			wantFound: true,
		},
		{
			name:      "Search root path",
			path:      "/",
			wantRules: rulesRoot,
			wantFound: true,
		},
		{
			name:      "Search empty path",
			path:      "",
			wantRules: rulesRoot,
			wantFound: true,
		},
		{
			name:      "Search non-existent static path",
			path:      "/api/v3",
			wantRules: nil,
			wantFound: false,
		},
		{
			name:      "Search partial static path",
			path:      "/api",
			wantRules: nil,
			wantFound: false,
		},
		{
			name:      "Search regex path non-match",
			path:      "/api/v3/test",
			wantRules: nil,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, found := trie.Search(tt.path)
			assert.Equal(t, tt.wantFound, found, "Expected found to be %v for path %v", tt.wantFound, tt.path)
			assert.Equal(t, tt.wantRules, rules, "Expected rules to match for path %v", tt.path)
		})
	}
}
