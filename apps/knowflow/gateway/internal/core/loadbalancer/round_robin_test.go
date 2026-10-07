package loadbalancer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoundRobin_SelectTarget(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		req     *http.Request
		want    string
	}{
		{
			name:    "Empty targets",
			targets: []string{},
			req:     httptest.NewRequest("GET", "/", nil),
			want:    "",
		},
		{
			name:    "Single target",
			targets: []string{"http://localhost:8381"},
			req:     httptest.NewRequest("GET", "/", nil),
			want:    "http://localhost:8381",
		},
		{
			name:    "Multiple targets",
			targets: []string{"http://localhost:8381", "http://localhost:8382", "http://localhost:8383"},
			req:     httptest.NewRequest("GET", "/", nil),
			want:    "http://localhost:8381", // 第一次请求
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := NewRoundRobin()
			got := rr.SelectTarget(tt.targets, tt.req)
			if got != tt.want {
				t.Errorf("RoundRobin.SelectTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRoundRobin_RoundRobinBehavior(t *testing.T) {
	targets := []string{"http://localhost:8381", "http://localhost:8382", "http://localhost:8383"}
	rr := NewRoundRobin()
	req := httptest.NewRequest("GET", "/", nil)

	// 测试轮询顺序
	expectedOrder := []string{
		"http://localhost:8381",
		"http://localhost:8382",
		"http://localhost:8383",
		"http://localhost:8381", // 循环回到第一个
	}

	for i, want := range expectedOrder {
		got := rr.SelectTarget(targets, req)
		if got != want {
			t.Errorf("RoundRobin.SelectTarget() iteration %d = %v, want %v", i, got, want)
		}
	}
}

func TestRoundRobin_Concurrency(t *testing.T) {
	targets := []string{"http://localhost:8381", "http://localhost:8382"}
	rr := NewRoundRobin()
	req := httptest.NewRequest("GET", "/", nil)

	// 并发调用
	type result struct {
		target string
		index  int
	}
	results := make(chan result, 100)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			target := rr.SelectTarget(targets, req)
			results <- result{target: target, index: idx}
		}(i)
	}

	// 统计结果
	counts := make(map[string]int)
	for i := 0; i < 100; i++ {
		r := <-results
		counts[r.target]++
	}

	// 检查分布是否接近均匀（允许一定偏差）
	for _, target := range targets {
		count := counts[target]
		if count < 40 || count > 60 { // 期望 50 ± 10
			t.Errorf("RoundRobin concurrency distribution uneven: %s got %d calls, expected ~50", target, count)
		}
	}
}
