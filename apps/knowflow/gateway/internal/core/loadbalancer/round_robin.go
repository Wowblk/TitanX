package loadbalancer

import (
	"net/http"
	"sync"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// rrTracer 为 RoundRobin 负载均衡模块初始化追踪器
var rrTracer = otel.Tracer("loadbalancer:round-robin")

// RoundRobin 实现简单的轮询负载均衡算法
type RoundRobin struct {
	next uint32     // 跟踪下一个目标索引
	mu   sync.Mutex // 确保索引更新的线程安全
}

// NewRoundRobin 创建并初始化 RoundRobin 负载均衡器实例
func NewRoundRobin() LoadBalancer {
	rr := &RoundRobin{}
	logger.Info("RoundRobin load balancer initialized")
	return rr
}

func (rr *RoundRobin) Type() string {
	return "round-robin"
}

// SelectTarget 以轮询方式选择下一个可用目标
// 127.0.0.1:8080 , 127.0.0.1:8081
func (rr *RoundRobin) SelectTarget(targets []string, r *http.Request) string {
	// 开始追踪负载均衡选择过程
	_, span := rrTracer.Start(r.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", rr.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	if len(targets) == 0 {
		logger.Warn("No targets available for round-robin selection")
		span.SetAttributes(attribute.String("result", "no targets"))
		return ""
	}

	rr.mu.Lock()
	defer rr.mu.Unlock()

	// 选择下一个目标并递增计数器
	// 127.0.0.1:8080 , 127.0.0.1:8081

	// len(targets)=2
	// rr.next=0,0 127.0.0.1:8080
	// rr.next=1,1 127.0.0.1:8081
	// rr.next=2,0 127.0.0.1:8080
	// rr.next=3,1 127.0.0.1:8081
	index := rr.next % uint32(len(targets))
	target := targets[index]
	rr.next++

	// 在追踪和日志中记录所选目标
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected target using round-robin",
		zap.String("target", target),
		zap.Uint32("index", index))
	return target
}

// UpdateTargets 对于 RoundRobin 是空操作，因其依赖运行时目标列表
func (rr *RoundRobin) UpdateTargets(cfg *config.Config) {
	// 无需配置更新，目标由每次请求提供
}
