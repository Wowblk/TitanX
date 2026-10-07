package loadbalancer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKetama_SelectTarget(t *testing.T) {
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
			targets: []string{"http://localhost:8081"},
			req:     httptest.NewRequest("GET", "/", nil),
			want:    "http://localhost:8081",
		},
		{
			name:    "Multiple targets, consistent hash",
			targets: []string{"http://localhost:8081", "http://localhost:8082", "http://localhost:8083"},
			req:     httptest.NewRequest("GET", "/", nil),
			want:    "", // 具体值依赖客户端 IP，这里仅测试一致性
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := NewKetama(160)
			if len(tt.targets) > 0 {
				tt.req.RemoteAddr = "192.168.1.1:12345" // 固定 IP 测试一致性
				got := k.SelectTarget(tt.targets, tt.req)
				if len(tt.targets) == 1 && got != tt.want {
					t.Errorf("Ketama.SelectTarget() = %v, want %v", got, tt.want)
				}
				if len(tt.targets) > 1 {
					// 测试一致性：同一 IP 应始终返回相同目标
					for i := 0; i < 10; i++ {
						next := k.SelectTarget(tt.targets, tt.req)
						if next != got {
							t.Errorf("Ketama.SelectTarget() inconsistent: got %v, then %v", got, next)
						}
					}
				}
			} else {
				got := k.SelectTarget(tt.targets, tt.req)
				if got != tt.want {
					t.Errorf("Ketama.SelectTarget() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestKetama_BuildRing(t *testing.T) {
	k := NewKetama(4) // 每个节点 4 个虚拟节点
	targets := []string{"node1", "node2", "node3"}

	k.buildRing(targets)

	if len(k.hashRing) != 12 { // 3 nodes * 4 replicas
		t.Errorf("Expected hashRing length 12, got %d", len(k.hashRing))
	}

	if len(k.hashMap) != 12 {
		t.Errorf("Expected hashMap length 12, got %d", len(k.hashMap))
	}

	// 检查排序
	for i := 1; i < len(k.hashRing); i++ {
		if k.hashRing[i-1] >= k.hashRing[i] {
			t.Errorf("hashRing not sorted at index %d: %d >= %d", i, k.hashRing[i-1], k.hashRing[i])
		}
	}
}

func TestKetama_Consistency(t *testing.T) {
	k := NewKetama(160)
	targets := []string{"http://localhost:8081", "http://localhost:8082", "http://localhost:8083"}

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "192.168.1.2:54321"

	target1 := k.SelectTarget(targets, req1)
	target2 := k.SelectTarget(targets, req2)
	target3 := k.SelectTarget(targets, req3)

	if target1 != target2 {
		t.Errorf("Ketama inconsistent for same IP: %v != %v", target1, target2)
	}

	// 不同 IP 可能不同，但不强制检查具体值
	t.Logf("IP1: %v, IP2: %v", target1, target3)
}

func TestKetama_Concurrency(t *testing.T) {
	k := NewKetama(160)
	targets := []string{"http://localhost:8081", "http://localhost:8082"}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	results := make(chan string, 100)
	for i := 0; i < 100; i++ {
		go func() {
			results <- k.SelectTarget(targets, req)
		}()
	}

	// 检查一致性
	expected := k.SelectTarget(targets, req)
	for i := 0; i < 100; i++ {
		got := <-results
		if got != expected {
			t.Errorf("Ketama concurrency inconsistent: got %v, want %v", got, expected)
		}
	}
}

func TestKetama_ZeroReplicas(t *testing.T) {
	k := NewKetama(0) // 零副本
	targets := []string{"http://localhost:8081", "http://localhost:8082"}
	k.buildRing(targets)

	if len(k.hashRing) != 0 {
		t.Errorf("Expected empty hashRing with zero replicas, got %d", len(k.hashRing))
	}

	req := httptest.NewRequest("GET", "/", nil)
	got := k.SelectTarget(targets, req)
	if got != targets[0] {
		t.Errorf("Expected first target %v with zero replicas, got %v", targets[0], got)
	}
}
