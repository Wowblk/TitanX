package loadbalancer

import (
	"fmt"

	"github.com/DoraZa/mini-gateway/config"
)

func NewLoadBalancer(algorithm string, cfg *config.Config) (LoadBalancer, error) {
	switch algorithm {
	case "round-robin", "round_robin":
		return NewRoundRobin(), nil
	case "ketama":
		return NewKetama(160), nil
	case "consul":
		return NewConsulBalancer(cfg.Consul.Addr)
	case "weighted-round-robin", "weighted_round_robin":
		rules := buildWeightedRoundRobinRules(cfg)
		return NewWeightedRoundRobin(rules), nil
	default:
		return nil, fmt.Errorf("unknown load balancer algorithm: %s", algorithm)
	}
}

func buildWeightedRoundRobinRules(cfg *config.Config) map[string][]TargetWeight {
	rules := make(map[string][]TargetWeight)
	for path, targetRules := range cfg.Routing.GetHTTPRules() {
		rules[path] = make([]TargetWeight, len(targetRules))
		for i, rule := range targetRules {
			rules[path][i] = TargetWeight{
				Target: rule.Target,
				Weight: rule.Weight,
			}
		}
	}
	return rules
}
