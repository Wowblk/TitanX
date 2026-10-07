package util

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DoraZa/mini-gateway/config"
)

// 创建测试配置
func newTestConfig(poolEnabled bool) *config.Config {
	return &config.Config{
		Performance: config.Performance{
			MemoryPool: struct {
				Enabled         bool "mapstructure:\"enabled\""
				TargetsCapacity int  "mapstructure:\"targetsCapacity\""
				RulesCapacity   int  "mapstructure:\"rulesCapacity\""
			}{
				Enabled:         poolEnabled,
				TargetsCapacity: 10,
				RulesCapacity:   10,
			},
		},
	}
}

// BenchmarkGetTargetsPool 基准测试启用对象池时的 GetTargets 性能
func BenchmarkGetTargetsPool(b *testing.B) {
	cfg := newTestConfig(true)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		targets := pm.GetTargets(10)
		pm.PutTargets(targets)
	}
}

// BenchmarkGetTargetsNoPool 基准测试禁用对象池时的 GetTargets 性能
func BenchmarkGetTargetsNoPool(b *testing.B) {
	cfg := newTestConfig(false)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		targets := pm.GetTargets(10)
		_ = targets // 模拟使用，避免编译器优化
	}
}

// BenchmarkGetRulesPool 基准测试启用对象池时的 GetRules 性能
func BenchmarkGetRulesPool(b *testing.B) {
	cfg := newTestConfig(true)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rules := pm.GetRules(10)
		pm.PutRules(rules)
	}
}

// BenchmarkGetRulesNoPool 基准测试禁用对象池时的 GetRules 性能
func BenchmarkGetRulesNoPool(b *testing.B) {
	cfg := newTestConfig(false)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rules := pm.GetRules(10)
		_ = rules // 模拟使用，避免编译器优化
	}
}

// BenchmarkConcurrentGetTargetsPool 基准测试并发场景下启用对象池的 GetTargets 性能
func BenchmarkConcurrentGetTargetsPool(b *testing.B) {
	cfg := newTestConfig(true)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			targets := pm.GetTargets(10)
			pm.PutTargets(targets)
		}
	})
}

// BenchmarkConcurrentGetTargetsNoPool 基准测试并发场景下禁用对象池的 GetTargets 性能
func BenchmarkConcurrentGetTargetsNoPool(b *testing.B) {
	cfg := newTestConfig(false)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			targets := pm.GetTargets(10)
			_ = targets // 模拟使用，避免编译器优化
		}
	})
}

// BenchmarkConcurrentGetRulesPool 基准测试并发场景下启用对象池的 GetRules 性能
func BenchmarkConcurrentGetRulesPool(b *testing.B) {
	cfg := newTestConfig(true)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rules := pm.GetRules(10)
			pm.PutRules(rules)
		}
	})
}

// BenchmarkConcurrentGetRulesNoPool 基准测试并发场景下禁用对象池的 GetRules 性能
func BenchmarkConcurrentGetRulesNoPool(b *testing.B) {
	cfg := newTestConfig(false)
	pm := NewPoolManager(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rules := pm.GetRules(10)
			_ = rules // 模拟使用，避免编译器优化
		}
	})
}

// TestNewPoolManager 测试 NewPoolManager 的初始化
func TestNewPoolManager(t *testing.T) {
	tests := []struct {
		name        string
		poolEnabled bool
		wantNilPool bool
	}{
		{
			name:        "Pool enabled",
			poolEnabled: true,
			wantNilPool: false,
		},
		{
			name:        "Pool disabled",
			poolEnabled: false,
			wantNilPool: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig(tt.poolEnabled)
			pm := NewPoolManager(cfg)

			assert.NotNil(t, pm, "ObjectPoolManager should not be nil")
			assert.Equal(t, cfg, pm.cfg, "Config should match input")

			// 检查对象池是否按预期初始化
			if tt.wantNilPool {
				assert.Empty(t, pm.targetsPool, "Targets pool should be empty when disabled")
				assert.Empty(t, pm.rulesPool, "Rules pool should be empty when disabled")
			} else {
				assert.NotEmpty(t, pm.targetsPool, "Targets pool should be initialized when enabled")
				assert.NotEmpty(t, pm.rulesPool, "Rules pool should be initialized when enabled")
			}
		})
	}
}

// TestGetTargets 测试 GetTargets 方法
func TestGetTargets(t *testing.T) {
	tests := []struct {
		name        string
		poolEnabled bool
		capacity    int
	}{
		{
			name:        "Pool enabled",
			poolEnabled: true,
			capacity:    10,
		},
		{
			name:        "Pool disabled",
			poolEnabled: false,
			capacity:    15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig(tt.poolEnabled)
			pm := NewPoolManager(cfg)

			targets := pm.GetTargets(tt.capacity)

			assert.NotNil(t, targets, "Targets slice should not be nil")
			assert.Equal(t, 0, len(targets), "Targets slice should be empty initially")
			if tt.poolEnabled {
				assert.Equal(t, cfg.Performance.MemoryPool.RulesCapacity, cap(targets), "Capacity should match configured RulesCapacity")
			} else {
				assert.Equal(t, tt.capacity, cap(targets), "Capacity should match input capacity when pool disabled")
			}
		})
	}
}

// TestPutTargets 测试 PutTargets 方法
func TestPutTargets(t *testing.T) {
	cfg := newTestConfig(true) // 仅测试启用池的情况，因为禁用池时 PutTargets 无操作
	pm := NewPoolManager(cfg)

	targets := pm.GetTargets(10)
	targets = append(targets, "http://localhost:8080")

	// PutTargets 不应抛出异常
	assert.NotPanics(t, func() {
		pm.PutTargets(targets)
	}, "PutTargets should not panic")

	// 获取并检查是否复用
	reusedTargets := pm.GetTargets(10)
	assert.Equal(t, 0, len(reusedTargets), "Reused targets should be reset to length 0")
	assert.Equal(t, cfg.Performance.MemoryPool.RulesCapacity, cap(reusedTargets), "Capacity should remain unchanged")
}

// TestGetRules 测试 GetRules 方法
func TestGetRules(t *testing.T) {
	tests := []struct {
		name        string
		poolEnabled bool
		capacity    int
	}{
		{
			name:        "Pool enabled",
			poolEnabled: true,
			capacity:    10,
		},
		{
			name:        "Pool disabled",
			poolEnabled: false,
			capacity:    15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig(tt.poolEnabled)
			pm := NewPoolManager(cfg)

			rules := pm.GetRules(tt.capacity)

			assert.NotNil(t, rules, "Rules slice should not be nil")
			assert.Equal(t, 0, len(rules), "Rules slice should be empty initially")
			if tt.poolEnabled {
				assert.Equal(t, cfg.Performance.MemoryPool.TargetsCapacity, cap(rules), "Capacity should match configured TargetsCapacity")
			} else {
				assert.Equal(t, tt.capacity, cap(rules), "Capacity should match input capacity when pool disabled")
			}
		})
	}
}

// TestPutRules 测试 PutRules 方法
func TestPutRules(t *testing.T) {
	cfg := newTestConfig(true) // 仅测试启用池的情况，因为禁用池时 PutRules 无操作
	pm := NewPoolManager(cfg)

	rules := pm.GetRules(10)
	rules = append(rules, config.RoutingRule{Target: "http://localhost:8080"})

	// PutRules 不应抛出异常
	assert.NotPanics(t, func() {
		pm.PutRules(rules)
	}, "PutRules should not panic")

	// 获取并检查是否复用
	reusedRules := pm.GetRules(10)
	assert.Equal(t, 0, len(reusedRules), "Reused rules should be reset to length 0")
	assert.Equal(t, cfg.Performance.MemoryPool.TargetsCapacity, cap(reusedRules), "Capacity should remain unchanged")
}

// TestPoolReuse 测试对象池的复用功能
func TestPoolReuse(t *testing.T) {
	cfg := newTestConfig(true)
	pm := NewPoolManager(cfg)

	// 测试 Targets 池
	targets1 := pm.GetTargets(10)
	targets1 = append(targets1, "http://localhost:8080")
	pm.PutTargets(targets1)
	targets2 := pm.GetTargets(10)
	assert.Equal(t, 0, len(targets2), "Targets should be reset after reuse")
	assert.Equal(t, cfg.Performance.MemoryPool.RulesCapacity, cap(targets2), "Capacity should match configured value")

	// 测试 Rules 池
	rules1 := pm.GetRules(10)
	rules1 = append(rules1, config.RoutingRule{Target: "http://localhost:8081"})
	pm.PutRules(rules1)
	rules2 := pm.GetRules(10)
	assert.Equal(t, 0, len(rules2), "Rules should be reset after reuse")
	assert.Equal(t, cfg.Performance.MemoryPool.TargetsCapacity, cap(rules2), "Capacity should match configured value")
}
