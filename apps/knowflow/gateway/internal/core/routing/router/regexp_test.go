package router

import (
	"testing"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/stretchr/testify/assert"
)

// TestMatch 测试 Match 方法
func TestMatch(t *testing.T) {
	cfg := &config.Config{
		Routing: config.Routing{
			LoadBalancer: "round_robin",
			Rules: map[string]config.RoutingRules{
				"/api/v1":    {{Target: "http://localhost:8080"}},
				"/api/v2/.*": {{Target: "http://localhost:8081"}},
				"/":          {{Target: "http://localhost:8082"}},
			},
		},
	}
	router := NewRegexpRouter(cfg)

	tests := []struct {
		name      string
		path      string
		wantRules config.RoutingRules
		wantFound bool
	}{
		{
			name:      "Match static path",
			path:      "/api/v1",
			wantRules: config.RoutingRules{{Target: "http://localhost:8080"}},
			wantFound: true,
		},
		{
			name:      "Match regex path",
			path:      "/api/v2/test",
			wantRules: config.RoutingRules{{Target: "http://localhost:8081"}},
			wantFound: true,
		},
		{
			name:      "Match root path",
			path:      "/",
			wantRules: config.RoutingRules{{Target: "http://localhost:8082"}},
			wantFound: true,
		},
		{
			name:      "No match",
			path:      "/api/v3",
			wantRules: nil,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, found := router.Match(tt.path)
			assert.Equal(t, tt.wantFound, found, "Expected found to be %v for path %v", tt.wantFound, tt.path)
			assert.Equal(t, tt.wantRules, rules, "Expected rules to match for path %v", tt.path)
		})
	}
}
