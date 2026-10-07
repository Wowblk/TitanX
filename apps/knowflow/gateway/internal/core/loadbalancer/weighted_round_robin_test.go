package loadbalancer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWeightedRoundRobin_SelectTarget(t *testing.T) {
	rules := map[string][]TargetWeight{
		"/test": {
			{Target: "http://localhost:8081", Weight: 1},
			{Target: "http://localhost:8082", Weight: 2},
		},
	}
	wrr := NewWeightedRoundRobin(rules)

	tests := []struct {
		name    string
		targets []string
		req     *http.Request
		want    string
	}{
		{
			name:    "Empty targets",
			targets: []string{},
			req:     httptest.NewRequest("GET", "/test", nil),
			want:    "",
		},
		{
			name:    "Single target",
			targets: []string{"http://localhost:8081"},
			req:     httptest.NewRequest("GET", "/test", nil),
			want:    "http://localhost:8081",
		},
		{
			name:    "Weighted selection",
			targets: []string{"http://localhost:8081", "http://localhost:8082"},
			req:     httptest.NewRequest("GET", "/test", nil),
			want:    "http://localhost:8081", // First call
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrr.SelectTarget(tt.targets, tt.req)
			if got != tt.want {
				t.Errorf("SelectTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWeightedRoundRobin_Distribution(t *testing.T) {
	rules := map[string][]TargetWeight{
		"/test": {
			{Target: "http://localhost:8081", Weight: 1},
			{Target: "http://localhost:8082", Weight: 2},
		},
	}
	wrr := NewWeightedRoundRobin(rules)
	req := httptest.NewRequest("GET", "/test", nil)
	targets := []string{"http://localhost:8081", "http://localhost:8082"}

	counts := make(map[string]int)
	for i := 0; i < 30; i++ {
		target := wrr.SelectTarget(targets, req)
		counts[target]++
	}

	// 检查分布是否接近 1:2
	if counts["http://localhost:8081"] < 8 || counts["http://localhost:8081"] > 12 {
		t.Errorf("Expected ~10 calls to 8081, got %d", counts["http://localhost:8081"])
	}
	if counts["http://localhost:8082"] < 18 || counts["http://localhost:8082"] > 22 {
		t.Errorf("Expected ~20 calls to 8082, got %d", counts["http://localhost:8082"])
	}
}
