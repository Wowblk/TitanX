package proxy

import (
	"testing"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestNewHTTPConnectionPool(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		wantPool bool
	}{
		{
			name: "Pool enabled",
			cfg: &config.Config{
				Performance: config.Performance{
					HttpPoolEnabled: true,
				},
			},
			wantPool: true,
		},
		{
			name: "Pool disabled",
			cfg: &config.Config{
				Performance: config.Performance{
					HttpPoolEnabled: false,
				},
			},
			wantPool: true, // 仍然会创建pool对象，只是不会初始化
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewHTTPConnectionPool(tt.cfg)
			assert.NotNil(t, pool)
			assert.Equal(t, tt.cfg, pool.cfg)
			assert.NotNil(t, pool.cleanupCh)
		})
	}
}

func TestGetClient(t *testing.T) {
	cfg := &config.Config{
		Performance: config.Performance{
			HttpPoolEnabled: true,
			MaxConnsPerHost: 100,
		},
	}
	pool := NewHTTPConnectionPool(cfg)

	tests := []struct {
		name   string
		target string
		want   *fasthttp.HostClient
	}{
		{
			name:   "Valid URL",
			target: "http://example.com:8080",
			want: &fasthttp.HostClient{
				Addr:                "example.com:8080",
				MaxConns:            100,
				MaxIdleConnDuration: defaultMaxIdleConnDuration,
				ReadTimeout:         defaultReadTimeout,
				WriteTimeout:        defaultWriteTimeout,
			},
		},
		{
			name:   "Valid host:port",
			target: "localhost:8080",
			want: &fasthttp.HostClient{
				Addr:                "localhost:8080",
				MaxConns:            100,
				MaxIdleConnDuration: defaultMaxIdleConnDuration,
				ReadTimeout:         defaultReadTimeout,
				WriteTimeout:        defaultWriteTimeout,
			},
		},
		{
			name:   "Invalid URL",
			target: "://invalid",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := pool.GetClient(tt.target)
			if tt.want == nil {
				assert.Nil(t, client)
			} else {
				assert.NotNil(t, client)
				assert.Equal(t, tt.want.Addr, client.Addr)
				assert.Equal(t, tt.want.MaxConns, client.MaxConns)
				assert.Equal(t, tt.want.MaxIdleConnDuration, client.MaxIdleConnDuration)
				assert.Equal(t, tt.want.ReadTimeout, client.ReadTimeout)
				assert.Equal(t, tt.want.WriteTimeout, client.WriteTimeout)
			}
		})
	}
}

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    string
		wantErr bool
	}{
		{
			name:   "Valid URL with port",
			target: "http://example.com:8080",
			want:   "example.com:8080",
		},
		{
			name:   "Valid URL without port",
			target: "https://example.com",
			want:   "example.com",
		},
		{
			name:   "Valid host:port",
			target: "localhost:8080",
			want:   "localhost:8080",
		},
		{
			name:    "Invalid URL",
			target:  "://invalid",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeTarget(tt.target)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestClose(t *testing.T) {
	cfg := &config.Config{
		Performance: config.Performance{
			HttpPoolEnabled: true,
		},
	}
	pool := NewHTTPConnectionPool(cfg)

	// 添加一个测试客户端
	pool.GetClient("http://test.com")

	pool.Close()

	// 验证 cleanupCh 已关闭
	select {
	case _, ok := <-pool.cleanupCh:
		assert.False(t, ok, "cleanupCh should be closed")
	default:
		t.Fatal("cleanupCh should be closed after Close()")
	}

	// 验证 clients map 已清空
	count := 0
	pool.clients.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count)
}
