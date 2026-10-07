package router

import (
	"strings"
	"testing"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/stretchr/testify/assert"
)

// 初始化日志和配置以避免 nil 指针问题
func init() {
	logger.InitTestLogger() // 使用测试日志初始化
}

// TestTrieInsert 测试 Trie 的 Insert 方法
func TestTrieInsert(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		rules    config.RoutingRules
		wantNode bool // 预期路径是否为终点
	}{
		{
			name:     "Insert single path",
			path:     "/api/v1",
			rules:    config.RoutingRules{{Target: "http://localhost:8080"}},
			wantNode: true,
		},
		{
			name:     "Insert nested path",
			path:     "/api/v1/user",
			rules:    config.RoutingRules{{Target: "http://localhost:8081"}},
			wantNode: true,
		},
		{
			name:     "Insert path with leading slash",
			path:     "/api/v2/",
			rules:    config.RoutingRules{{Target: "http://localhost:8082"}},
			wantNode: true,
		},
		{
			name:     "Insert empty path",
			path:     "",
			rules:    config.RoutingRules{{Target: "http://localhost:8083"}},
			wantNode: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trie := &Trie{Root: &TrieNode{Children: make(map[rune]*TrieNode)}}
			trie.Insert(tt.path, tt.rules)

			// 检查插入结果
			node := trie.Root
			path := strings.TrimPrefix(tt.path, "/")
			for _, ch := range path {
				node = node.Children[ch]
				assert.NotNil(t, node, "Expected node for character %v in path %v", ch, tt.path)
			}
			assert.Equal(t, tt.wantNode, node.IsEnd, "Expected IsEnd to be %v for path %v", tt.wantNode, tt.path)
			assert.Equal(t, tt.rules, node.Rules, "Expected rules to match for path %v", tt.path)
		})
	}
}

// TestTrieSearch 测试 Trie 的 Search 方法
func TestTrieSearch(t *testing.T) {
	// 初始化 TrieRegexp 并插入测试数据
	trie := &Trie{Root: &TrieNode{Children: make(map[rune]*TrieNode)}}
	rulesV1 := config.RoutingRules{{Target: "http://localhost:8080"}}
	rulesUser := config.RoutingRules{{Target: "http://localhost:8081"}}
	rulesRoot := config.RoutingRules{{Target: "http://localhost:8082"}}

	trie.Insert("/api/v1", rulesV1)
	trie.Insert("/api/v1/user", rulesUser)
	trie.Insert("/", rulesRoot)

	tests := []struct {
		name      string
		path      string
		wantRules config.RoutingRules
		wantFound bool
	}{
		{
			name:      "Search existing path",
			path:      "/api/v1",
			wantRules: rulesV1,
			wantFound: true,
		},
		{
			name:      "Search nested path",
			path:      "/api/v1/user",
			wantRules: rulesUser,
			wantFound: true,
		},
		{
			name:      "Search root path",
			path:      "/",
			wantRules: rulesRoot,
			wantFound: true,
		},
		{
			name:      "Search with trailing slash",
			path:      "/api/v1/",
			wantRules: rulesV1,
			wantFound: true,
		},
		{
			name:      "Search non-existent path",
			path:      "/api/v2",
			wantRules: nil,
			wantFound: false,
		},
		{
			name:      "Search partial path",
			path:      "/api",
			wantRules: nil,
			wantFound: false,
		},
		{
			name:      "Search empty path",
			path:      "",
			wantRules: rulesRoot,
			wantFound: true,
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
