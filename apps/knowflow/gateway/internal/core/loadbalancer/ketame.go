package loadbalancer

import (
	"crypto/md5"
	"encoding/binary"
	"net/http"
	"sort"
	"strconv"
	"sync"

	"github.com/DoraZa/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// kTracer 为 Ketama 负载均衡模块初始化追踪器
var kTracer = otel.Tracer("loadbalancer:ketama")

// Ketama 使用 Ketama 一致性哈希算法实现的负载均衡器
type Ketama struct {
	nodes    []string          // 目标节点列表
	hashRing []uint32          // 排序后的哈希环
	hashMap  map[uint32]string // 哈希值到节点的映射
	replicas int               // 每个物理节点的虚拟节点数
	mu       sync.RWMutex      // 保护哈希环的并发访问
}

// NewKetama 创建并初始化 Ketama 负载均衡器
func NewKetama(replicas int) *Ketama {
	k := &Ketama{
		replicas: replicas,
		hashMap:  make(map[uint32]string),
		mu:       sync.RWMutex{},
	}
	logger.Info("Ketama load balancer initialized", zap.Int("replicas", replicas))
	return k
}

func (cb *Ketama) Type() string {
	return "ketama"
}

// SelectTarget 根据客户端 IP 使用一致性哈希选择目标节点
func (k *Ketama) SelectTarget(targets []string, req *http.Request) string {
	// 开始追踪负载均衡选择过程
	_, span := kTracer.Start(req.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", k.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	if len(targets) == 0 {
		span.SetAttributes(attribute.String("result", "no targets"))
		logger.Warn("No targets available for selection")
		return ""
	}

	k.mu.RLock()
	// 检查目标列表是否变化，需要重建哈希环
	needRebuild := len(k.nodes) != len(targets) || !equalSlice(k.nodes, targets)
	k.mu.RUnlock()

	if needRebuild {
		k.mu.Lock()
		// 双重检查以避免并发情况下的重复构建
		if len(k.nodes) != len(targets) || !equalSlice(k.nodes, targets) {
			k.buildRing(targets)
		}
		k.mu.Unlock()
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	if len(k.hashRing) == 0 {
		// 如果哈希环为空，回退到第一个目标
		target := targets[0]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected fallback target due to empty hash ring",
			zap.String("target", target))
		return target
	}

	// 使用客户端 IP 作为哈希键进行一致性选择
	key := k.hashKey(req.RemoteAddr)
	index := k.findNearest(key)
	target := k.hashMap[k.hashRing[index]]
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected target using Ketama consistent hashing",
		zap.String("clientIP", req.RemoteAddr),
		zap.String("target", target))
	return target
}

// buildRing 根据目标列表构建 Ketama 哈希环
func (k *Ketama) buildRing(targets []string) {
	k.nodes = targets
	k.hashRing = nil // 重置哈希环
	k.hashMap = make(map[uint32]string)

	totalSlots := len(targets) * k.replicas
	k.hashRing = make([]uint32, 0, totalSlots)

	// 为每个目标添加虚拟节点到哈希环
	for _, node := range targets {
		for j := 0; j < k.replicas; j++ {
			hash := k.hash(node + "-" + strconv.Itoa(j)) // 每个虚拟节点的唯一哈希
			k.hashRing = append(k.hashRing, hash)
			k.hashMap[hash] = node
		}
	}
	// 对哈希环进行排序以支持二分查找
	sort.Slice(k.hashRing, func(i, j int) bool {
		return k.hashRing[i] < k.hashRing[j]
	})
	logger.Info("Ketama hash ring rebuilt",
		zap.Int("nodes", len(targets)),
		zap.Int("totalSlots", totalSlots))
}

// hash 使用 MD5 生成 32 位哈希值
func (k *Ketama) hash(key string) uint32 {
	h := md5.Sum([]byte(key))
	return binary.BigEndian.Uint32(h[0:4]) // 使用前 4 字节作为哈希值
}

// hashKey 从客户端地址计算哈希键
func (k *Ketama) hashKey(clientAddr string) uint32 {
	return k.hash(clientAddr)
}

// findNearest 查找哈希环中大于等于给定哈希值的最近节点索引
func (k *Ketama) findNearest(hash uint32) int {
	index := sort.Search(len(k.hashRing), func(i int) bool {
		return k.hashRing[i] >= hash
	})
	if index == len(k.hashRing) {
		return 0 // 如果哈希值超出所有节点，环绕到第一个节点
	}
	return index
}

// equalSlice 比较两个字符串切片是否相等
func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
