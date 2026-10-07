package util

import (
	"sync"

	"github.com/DoraZa/mini-gateway/config"
)

// ObjectPoolManager 管理可重用资源的对象池逻辑
type ObjectPoolManager struct {
	cfg *config.Config // 配置信息

	targetsPool sync.Pool // 目标地址切片池
	rulesPool   sync.Pool // 路由规则切片池
}

// NewPoolManager 创建并初始化对象池管理器实例
func NewPoolManager(cfg *config.Config) *ObjectPoolManager {
	pm := &ObjectPoolManager{
		cfg: cfg,
	}

	// 仅当配置中启用内存池时初始化池
	if cfg.Performance.MemoryPool.Enabled {
		pm.targetsPool = sync.Pool{
			New: func() interface{} {
				return make([]string, 0, cfg.Performance.MemoryPool.RulesCapacity)
			},
		}
		pm.rulesPool = sync.Pool{
			New: func() interface{} {
				return make(config.RoutingRules, 0, cfg.Performance.MemoryPool.TargetsCapacity)
			},
		}
	} else {
		// 未启用池时使用空池，避免空引用
		pm.targetsPool = sync.Pool{}
		pm.rulesPool = sync.Pool{}
	}
	return pm
}

// GetTargets 从池中获取可重用的目标切片或创建新切片
func (pm *ObjectPoolManager) GetTargets(capacity int) []string {
	if pm.cfg.Performance.MemoryPool.Enabled {
		targets := pm.targetsPool.Get().([]string)
		return targets[:0] // 重置长度以重用切片
	}
	return make([]string, 0, capacity) // 未启用池时分配新切片
}

// PutTargets 将目标切片归还到池中以供重用
func (pm *ObjectPoolManager) PutTargets(targets []string) {
	if pm.cfg.Performance.MemoryPool.Enabled {
		pm.targetsPool.Put(targets)
	}
	// 未启用池时，切片将通过垃圾回收自动丢弃
}

// GetRules 从池中获取可重用的路由规则切片或创建新切片
func (pm *ObjectPoolManager) GetRules(capacity int) config.RoutingRules {
	if pm.cfg.Performance.MemoryPool.Enabled {
		rules := pm.rulesPool.Get().(config.RoutingRules)
		return rules[:0] // 重置长度以重用切片
	}
	return make(config.RoutingRules, 0, capacity) // 未启用池时分配新切片
}

// PutRules 将路由规则切片归还到池中以供重用
func (pm *ObjectPoolManager) PutRules(rules config.RoutingRules) {
	if pm.cfg.Performance.MemoryPool.Enabled {
		pm.rulesPool.Put(rules)
	}
	// 未启用池时，切片将通过垃圾回收自动丢弃
}
