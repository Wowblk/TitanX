package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DoraZa/mini-gateway/internal/core/health"
	"github.com/DoraZa/mini-gateway/pkg/util"
	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/gin-gonic/gin"
)

// TestCreateHTTPHandler_NoTarget 模拟没有可用目标的情况，验证返回 503 和错误 JSON 信息。
func TestCreateHTTPHandler_NoTarget(t *testing.T) {
	config.InitTestConfigManager()
	gin.SetMode(gin.TestMode)
	// 构造一个 testHTTPProxy，使 selectTarget 返回空值
	proxy := &HTTPProxy{
		httpPool:        NewHTTPConnectionPool(config.GetConfig()),
		loadBalancer:    initializeLoadBalancer(config.GetConfig()),
		objectPool:      util.NewPoolManager(config.GetConfig()),
		httpPoolEnabled: false,
		selectTargetFunc: func(c *gin.Context, rules config.RoutingRules) (string, string) {
			return "", ""
		}}
	// 此处 rules 可传空（测试中并不使用）
	dummyRules := config.RoutingRules{}
	handler := proxy.CreateHTTPHandler(dummyRules)

	// 构造 gin 路由，注册该 handler
	router := gin.New()
	router.GET("/test", handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("预期状态码 %d，实际得到 %d", http.StatusServiceUnavailable, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应时出错: %v", err)
	}
	if resp["error"] != "No available target" {
		t.Errorf("预期错误信息 'No available target'，实际得到 '%s'", resp["error"])
	}
}

// TestCreateHTTPHandler_ProxyDirect 模拟直接代理模式（httpPoolEnabled = false），使用 httptest.NewServer 模拟目标服务。
func TestCreateHTTPHandler_ProxyDirect(t *testing.T) {
	config.InitTestConfigManager()
	health.InitHealthChecker(config.GetConfig())
	gin.SetMode(gin.TestMode)
	// 启动一个模拟目标服务，返回固定响应
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from target"))
	}))
	defer ts.Close()

	proxy := &HTTPProxy{
		httpPool:        NewHTTPConnectionPool(config.GetConfig()),
		loadBalancer:    initializeLoadBalancer(config.GetConfig()),
		objectPool:      util.NewPoolManager(config.GetConfig()),
		httpPoolEnabled: false,
		// 注入自定义 selectTarget 逻辑，直接返回模拟目标服务的 URL 和默认环境
		selectTargetFunc: func(c *gin.Context, rules config.RoutingRules) (string, string) {
			return ts.URL, "stable"
		},
	}
	dummyRules := config.RoutingRules{}
	handler := proxy.CreateHTTPHandler(dummyRules)

	router := gin.New()
	router.GET("/test", handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("预期状态码 %d，实际得到 %d", http.StatusOK, w.Code)
	}
	body := w.Body.String()
	if body != "Hello from target" {
		t.Errorf("预期响应体 'Hello from target'，实际得到 '%s'", body)
	}
}

// TestCreateHTTPHandler_ProxyWithPool 模拟连接池模式（httpPoolEnabled = true），重写 proxyWithPool 方法，直接返回固定 JSON 响应。
func TestCreateHTTPHandler_ProxyWithPool(t *testing.T) {
	config.InitTestConfigManager()
	gin.SetMode(gin.TestMode)
	proxy := &HTTPProxy{
		httpPool:        NewHTTPConnectionPool(config.GetConfig()),
		loadBalancer:    initializeLoadBalancer(config.GetConfig()),
		objectPool:      util.NewPoolManager(config.GetConfig()),
		httpPoolEnabled: true,
		selectTargetFunc: func(c *gin.Context, rules config.RoutingRules) (string, string) {
			return "dummy-target", "stable"
		},
		proxyWithPoolFunc: func(c *gin.Context, target, env string) {
			c.JSON(http.StatusOK, gin.H{
				"message": "proxied with pool",
				"target":  target,
				"env":     env,
			})
		},
	}
	dummyRules := config.RoutingRules{}
	handler := proxy.CreateHTTPHandler(dummyRules)

	router := gin.New()
	router.GET("/test", handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("预期状态码 %d，实际得到 %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应时出错: %v", err)
	}
	if resp["message"] != "proxied with pool" {
		t.Errorf("预期 message 为 'proxied with pool'，实际得到 '%v'", resp["message"])
	}
	if resp["target"] != "dummy-target" {
		t.Errorf("预期 target 为 'dummy-target'，实际得到 '%v'", resp["target"])
	}
	if resp["env"] != "stable" {
		t.Errorf("预期 env 为 'stable'，实际得到 '%v'", resp["env"])
	}
}

func TestCreateHTTPHandler_CustomInjection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	proxy := &HTTPProxy{
		httpPoolEnabled: true,
		// 注入自定义 selectTarget 逻辑：返回固定的目标和环境
		selectTargetFunc: func(c *gin.Context, rules config.RoutingRules) (string, string) {
			return "dummy-target", "stable"
		},
		// 注入自定义 proxyWithPool 逻辑：直接返回固定响应
		proxyWithPoolFunc: func(c *gin.Context, target, env string) {
			c.JSON(http.StatusOK, gin.H{
				"message": "proxied with injected pool",
				"target":  target,
				"env":     env,
			})
		},
	}
	dummyRules := config.RoutingRules{}
	handler := proxy.CreateHTTPHandler(dummyRules)

	router := gin.New()
	router.GET("/test", handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("预期状态码 %d，实际得到 %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应时出错: %v", err)
	}
	if resp["message"] != "proxied with injected pool" {
		t.Errorf("预期 message 为 'proxied with injected pool'，实际得到 '%v'", resp["message"])
	}
	if resp["target"] != "dummy-target" {
		t.Errorf("预期 target 为 'dummy-target'，实际得到 '%v'", resp["target"])
	}
	if resp["env"] != "stable" {
		t.Errorf("预期 env 为 'stable'，实际得到 '%v'", resp["env"])
	}
}

// dummyLoadBalancer 用于测试 loadbalancer 接口
type dummyLB struct{}

func (d dummyLB) Type() string { return "dummyLB" }
func (d dummyLB) SelectTarget(targets []string, req *http.Request) string {
	if len(targets) > 0 {
		return targets[0]
	}
	return ""
}

// 假设 config.RoutingRule 的定义如下（请根据实际情况调整）：
//
// type RoutingRule struct {
//     Target string
//     Env    string
//     Weight int
// }
// type RoutingRules []RoutingRule

// TestGetLoadBalancerType 测试 GetLoadBalancerType 分支
func TestGetLoadBalancerType(t *testing.T) {
	var hp *HTTPProxy = nil
	if got := hp.GetLoadBalancerType(); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
	hp = &HTTPProxy{}
	if got := hp.GetLoadBalancerType(); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
	hp.loadBalancer = dummyLB{}
	if got := hp.GetLoadBalancerType(); got != "dummyLB" {
		t.Errorf("expected dummyLB, got %q", got)
	}
}

// TestGetLoadBalancerActiveTargets 测试 GetLoadBalancerActiveTargets 分支
func TestGetLoadBalancerActiveTargets(t *testing.T) {
	var hp *HTTPProxy = nil
	if got := hp.GetLoadBalancerActiveTargets(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
	hp = &HTTPProxy{}
	if got := hp.GetLoadBalancerActiveTargets(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
	hp.loadBalancer = dummyLB{}
	targets := hp.GetLoadBalancerActiveTargets()
	if len(targets) != 1 || targets[0] != "dummy" {
		t.Errorf("unexpected targets: %v", targets)
	}
}

// TestGetEnvFromHeader 测试根据请求头获取环境
func TestGetEnvFromHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Env", "canary")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	env := getEnvFromHeader(c)
	if env != "canary" {
		t.Errorf("expected 'canary', got %q", env)
	}
	req2 := httptest.NewRequest("GET", "/", nil)
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	c2.Request = req2
	env = getEnvFromHeader(c2)
	if env != defaultEnv {
		t.Errorf("expected %q, got %q", defaultEnv, env)
	}
}

// TestSingleJoiningSlash 测试路径合并函数
func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"a/", "/b", "a/b"},
		{"a", "b", "a/b"},
		{"a/", "b", "a/b"},
		{"a", "/b", "a/b"},
	}
	for _, tt := range tests {
		got := SingleJoiningSlash(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("SingleJoiningSlash(%q, %q) = %q; want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

// dummySpan 实现 trace.Span 接口，用于测试 createErrorHandler 等函数
type dummySpan struct{}

func (ds dummySpan) End()                                             {}
func (ds dummySpan) RecordError(err error, opts ...trace.EventOption) {}
func (ds dummySpan) SetStatus(code codes.Code, description string)    {}
func (ds dummySpan) AddEvent(name string, opts ...trace.EventOption)  {}
func (ds dummySpan) IsRecording() bool                                { return false }
func (ds dummySpan) SpanContext() trace.SpanContext                   { return trace.SpanContext{} }

// TestCreateDirector 测试 createDirector 返回的 director 函数
func TestCreateDirector(t *testing.T) {
	targetURL, _ := url.Parse("http://example.com")
	director := (&HTTPProxy{}).createDirector(targetURL, "canary")
	req, _ := http.NewRequest("GET", "/path", nil)
	req.URL.Path = "/path"
	director(req)
	if req.URL.Scheme != "http" || req.URL.Host != "example.com" {
		t.Errorf("director did not set scheme/host correctly: %v", req.URL)
	}
	if req.Header.Get("X-Env") != canaryEnv {
		t.Errorf("expected X-Env header to be %q, got %q", canaryEnv, req.Header.Get("X-Env"))
	}
}

// dummyResponseWriter 用于测试 createErrorHandler
type dummyResponseWriter struct {
	header http.Header
	body   *strings.Builder
	status int
}

func newDummyResponseWriter() *dummyResponseWriter {
	return &dummyResponseWriter{
		header: make(http.Header),
		body:   &strings.Builder{},
	}
}
func (d *dummyResponseWriter) Header() http.Header         { return d.header }
func (d *dummyResponseWriter) Write(b []byte) (int, error) { return d.body.Write(b) }
func (d *dummyResponseWriter) WriteHeader(statusCode int)  { d.status = statusCode }

// TestPrepareFastHTTPRequest 测试 prepareFastHTTPRequest 的逻辑
func TestPrepareFastHTTPRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test?query=1", nil)
	req.Header.Set("X-Test", "value")
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	fReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(fReq)
	target := "example.com"
	env := "stable"
	(&HTTPProxy{}).prepareFastHTTPRequest(c, fReq, target, env)
	expectedURI := "http://" + target + "/test?query=1"
	if string(fReq.URI().String()) != expectedURI {
		t.Errorf("expected RequestURI %q, got %q", expectedURI, string(fReq.URI().String()))
	}
	if string(fReq.Header.Method()) != "GET" {
		t.Errorf("expected method GET, got %q", string(fReq.Header.Method()))
	}
	if string(fReq.Header.Peek("X-Test")) != "value" {
		t.Errorf("expected header X-Test to be 'value', got %q", string(fReq.Header.Peek("X-Test")))
	}
}

// TestWriteFastHTTPResponse 测试 writeFastHTTPResponse 将 fasthttp.Response 写入 gin 上下文
func TestWriteFastHTTPResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(fResp)
	fResp.SetStatusCode(201)
	fResp.Header.Set("Content-Type", "application/json")
	fResp.SetBody([]byte(`{"result": "ok"}`))
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	(&HTTPProxy{}).writeFastHTTPResponse(c, fResp)
	if w.Code != 201 {
		t.Errorf("expected status 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"result": "ok"`) {
		t.Errorf("expected body to contain %q, got %q", `{"result": "ok"}`, body)
	}
}

// TestDefaultDirector 测试 defaultDirector 的逻辑
func TestDefaultDirector(t *testing.T) {
	targetURL, _ := url.Parse("http://example.com/api")
	director := defaultDirector(targetURL)
	req, _ := http.NewRequest("GET", "/resource", nil)
	req.URL.Path = "/resource"
	director(req)
	if req.URL.Scheme != "http" || req.URL.Host != "example.com" {
		t.Errorf("defaultDirector did not set scheme/host correctly: %v", req.URL)
	}
	expectedPath := SingleJoiningSlash("/api", "/resource")
	if req.URL.Path != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, req.URL.Path)
	}
}

// TestWeightedRandomSelect 测试 WeightedRandomSelect 函数
func TestWeightedRandomSelect(t *testing.T) {
	var empty config.RoutingRules
	if rule := WeightedRandomSelect(empty); rule != nil {
		t.Errorf("expected nil for empty rules, got %v", rule)
	}
	single := config.RoutingRules{
		{Target: "a", Env: "stable", Weight: 10},
	}
	rule := WeightedRandomSelect(single)
	if rule == nil || rule.Target != "a" {
		t.Errorf("expected rule with target 'a', got %v", rule)
	}
	multi := config.RoutingRules{
		{Target: "a", Env: "stable", Weight: 1},
		{Target: "b", Env: "stable", Weight: 2},
		{Target: "c", Env: "stable", Weight: 3},
	}
	found := make(map[string]bool)
	for i := 0; i < 100; i++ {
		r := WeightedRandomSelect(multi)
		if r != nil {
			found[r.Target] = true
		}
	}
	if len(found) < 2 {
		t.Errorf("expected at least 2 different targets, got %v", found)
	}
}
