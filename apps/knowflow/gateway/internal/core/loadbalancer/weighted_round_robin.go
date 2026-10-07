package loadbalancer

import (
	"net/http"
	"sync"

	"github.com/DoraZa/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// wrrTracer 为加权轮询负载均衡模块初始化追踪器
var wrrTracer = otel.Tracer("loadbalancer:weighted-round-robin")

// TargetWeight 定义目标及其关联权重
type TargetWeight struct {
	Target string //目标地址
	Weight int    //权重值
}

func (cb *WeightedRoundRobin) Type() string {
	return "weighted-round-robin"
}

// WeightedRoundRobin 实现加权轮询负载均衡算法
type WeightedRoundRobin struct {
	rules  map[string][]TargetWeight // 预定义的路径到加权目标的映射规则
	states map[string]*wrrState      // 每个路径的运行时状态
	mu     sync.Mutex                // 确保状态更新的线程安全
}

// wrrState 保存加权轮询选择的状态
type wrrState struct {
	targets      []string // 目标地址列表
	weights      []int    // 每个目标对应的权重
	totalWeight  int      // 所有权重的总和
	currentCount int      // 请求分发的计数器
}

// NewWeightedRoundRobin 创建并初始化 WeightedRoundRobin 实例
func NewWeightedRoundRobin(rules map[string][]TargetWeight) *WeightedRoundRobin {
	wrr := &WeightedRoundRobin{
		rules:  rules,
		states: make(map[string]*wrrState),
	}

	// 根据预定义规则初始化状态
	for path, targetRules := range rules {
		targets := make([]string, len(targetRules))
		weights := make([]int, len(targetRules))
		totalWeight := 0
		for i, rule := range targetRules {
			targets[i] = rule.Target
			weights[i] = rule.Weight
			totalWeight += rule.Weight
		}
		wrr.states[path] = &wrrState{
			targets:      targets,
			weights:      weights,
			totalWeight:  totalWeight,
			currentCount: -1, // 从 -1 开始，第一次递增后选择索引 0
		}
	}
	logger.Info("WeightedRoundRobin load balancer initialized",
		zap.Int("ruleCount", len(rules)))
	return wrr
}

// SelectTarget 根据加权轮询选择目标，或回退到简单轮询
func (wrr *WeightedRoundRobin) SelectTarget(targets []string, req *http.Request) string {
	wrr.mu.Lock()
	defer wrr.mu.Unlock()

	// 开始追踪负载均衡选择过程
	_, span := wrrTracer.Start(req.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", wrr.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	// 处理边缘情况
	if len(targets) == 0 {
		logger.Warn("No targets available for weighted round-robin selection")
		span.SetAttributes(attribute.String("result", "no targets"))
		return ""
	}
	if len(targets) == 1 {
		target := targets[0]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected single available target",
			zap.String("target", target))
		return target
	}

	// 尝试使用预定义的加权规则
	path := req.URL.Path
	state, ok := wrr.states[path]
	if !ok || len(state.targets) == 0 {
		// 如果没有预定义规则，回退到简单轮询
		count := 0
		if state != nil {
			count = state.currentCount
			state.currentCount = (state.currentCount + 1) % len(targets)
		}
		target := targets[count%len(targets)]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected target using simple round-robin fallback",
			zap.String("path", path),
			zap.String("target", target))
		return target
	}

	// 加权轮询选择
	if state.totalWeight == 0 {
		logger.Warn("Total weight is zero, unable to select target",
			zap.String("path", path))
		return ""
	}

	// 递增计数器并计算在总权重中的位置
	state.currentCount++
	current := state.currentCount % state.totalWeight
	cumulativeWeight := 0

	// 根据累计权重选择目标
	for i, weight := range state.weights {
		cumulativeWeight += weight
		if current < cumulativeWeight {
			target := state.targets[i]
			span.SetAttributes(attribute.String("selected_target", target))
			logger.Debug("Selected target using weighted round-robin",
				zap.String("path", path),
				zap.String("target", target),
				zap.Int("weight", weight))
			return target
		}
	}

	/**
	target1: 1
	target2: 2
	target3: 3
	totalWeight: 6 ( 1 + 2 + 3 )
	currentCount     | -1 0 1 2 3 4 5 6 7 8 9 10 11 12 13 ...
	current          |    0 1 2 3 4 5 0 1 2 3 4 5 0  1  2 ...
	cumulativeWeight |    1 3 3 6 6 6 1 3 3 6 6 6 1  3  3
	选择对象          |    1 2 2 3 3 3 1 2 2 3 3 3 1  2  2 ...
	*/

	// 回退到第一个目标（正常情况下不会发生，除非权重配置错误）
	target := state.targets[0]
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected fallback target due to weight calculation",
		zap.String("path", path),
		zap.String("target", target))
	return target
}
