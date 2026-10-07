package loadbalancer

import "net/http"

// LoadBalancer 定义负载均衡接口
type LoadBalancer interface {
	SelectTarget(targets []string, r *http.Request) string
	Type() string
}
