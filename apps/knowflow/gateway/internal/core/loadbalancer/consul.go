package loadbalancer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/hashicorp/consul/api"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var consulTracer = otel.Tracer("loadbalancer:consul")

// ConsulBalancer 使用 Consul 实现动态规则更新的负载均衡器
type ConsulBalancer struct {
	client *api.Client         // Consul 客户端
	rules  map[string][]string // 路径到目标列表的映射
	mu     sync.RWMutex        // 读写锁
	stopCh chan struct{}       // 停止信号通道
}

// NewConsulBalancer 创建并初始化 ConsulBalancer 实例
func NewConsulBalancer(consulAddr string) (*ConsulBalancer, error) {
	config := api.DefaultConfig()
	config.Address = consulAddr
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %v", err)
	}

	cb := &ConsulBalancer{
		client: client,
		rules:  make(map[string][]string),
		stopCh: make(chan struct{}),
	}
	go cb.watchRules() // 启动 Consul 规则监听协程
	logger.Info("Consul load balancer initialized", zap.String("address", consulAddr))
	return cb, nil
}

func (cb *ConsulBalancer) Type() string {
	return "consul"
}

// SelectTarget 根据 Consul 规则或回退逻辑为请求选择目标
func (cb *ConsulBalancer) SelectTarget(targets []string, req *http.Request) string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// 开始追踪负载均衡选择过程
	_, span := consulTracer.Start(req.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", cb.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	path := req.URL.Path
	if consulTargets, ok := cb.rules[path]; ok && len(consulTargets) > 0 {
		// 如果 Consul 提供了目标列表，则使用
		count := uint32(len(consulTargets))
		index := uint32(time.Now().UnixNano()) % count // 基于时间的简单选择
		target := consulTargets[index]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected target from Consul rules",
			zap.String("path", path),
			zap.String("target", target))
		return target
	}

	// 如果没有匹配的 Consul 规则，回退到提供的目标列表
	if len(targets) == 0 {
		logger.Warn("No targets available for selection", zap.String("path", path))
		return ""
	}
	count := uint32(len(targets))
	index := uint32(time.Now().UnixNano()) % count
	target := targets[index]
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected target from fallback list",
		zap.String("path", path),
		zap.String("target", target))
	return target
}

// watchRules 从 Consul 持续更新负载均衡规则
func (cb *ConsulBalancer) watchRules() {
	var lastIndex uint64
	for {
		select {
		case <-cb.stopCh:
			logger.Info("Stopping Consul rules watcher")
			return
		default:
			// 使用长轮询从 Consul 获取规则
			kv, meta, err := cb.client.KV().Get("gateway/loadbalancer/rules", &api.QueryOptions{
				WaitIndex: lastIndex,
			})
			if err != nil || kv == nil {
				logger.Error("Failed to retrieve load balancer rules from Consul",
					zap.Error(err))
				time.Sleep(5 * time.Second) // 失败后延迟重试
				continue
			}

			lastIndex = meta.LastIndex
			var newRules map[string][]string
			if err := json.Unmarshal(kv.Value, &newRules); err != nil {
				logger.Error("Failed to unmarshal load balancer rules from Consul",
					zap.Error(err))
				time.Sleep(5 * time.Second) // 失败后延迟重试
				continue
			}

			cb.mu.Lock()
			cb.rules = newRules
			cb.mu.Unlock()

			logger.Info("Successfully updated load balancer rules from Consul",
				zap.Any("rules", newRules))
			time.Sleep(1 * time.Second) // 下次轮询前的短暂休眠
		}
	}
}

// Stop 终止 Consul 规则监听协程
func (cb *ConsulBalancer) Stop() {
	close(cb.stopCh)
	logger.Info("Consul load balancer stopped")
}
