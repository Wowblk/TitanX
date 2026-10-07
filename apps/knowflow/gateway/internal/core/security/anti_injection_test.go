package security

import (
	"testing"

	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/stretchr/testify/assert"
)

// TestDetectInjection 测试 DetectInjection 函数
func TestDetectInjection(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      string
		wantBool   bool
		wantKeyVal string
	}{
		{
			name:       "Safe input",
			key:        "name",
			value:      "Alice",
			wantBool:   false,
			wantKeyVal: "",
		},
		{
			name:       "SQL injection in key",
			key:        "select * from users",
			value:      "data",
			wantBool:   true,
			wantKeyVal: "select * from users",
		},
		{
			name:       "SQL injection in value",
			key:        "query",
			value:      "drop table users",
			wantBool:   true,
			wantKeyVal: "drop table users",
		},
		{
			name:       "XSS injection in value",
			key:        "content",
			value:      "<script>alert('xss')</script>",
			wantBool:   true,
			wantKeyVal: "<script>alert('xss')</script>",
		},
		{
			name:       "Command injection in key",
			key:        "exec ls",
			value:      "param",
			wantBool:   true,
			wantKeyVal: "exec ls",
		},
		{
			name:       "Path injection in value",
			key:        "file",
			value:      "../../etc/passwd",
			wantBool:   true,
			wantKeyVal: "../../etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = logger.InitTestLogger() // 初始化日志，尽管这里不直接验证日志
			defer logger.Sync()

			detected, keyVal := DetectInjection(tt.key, tt.value)
			assert.Equal(t, tt.wantBool, detected, "Expected detection result to be %v for key '%v' and value '%v'", tt.wantBool, tt.key, tt.value)
			assert.Equal(t, tt.wantKeyVal, keyVal, "Expected key/value to be '%v' for key '%v' and value '%v'", tt.wantKeyVal, tt.key, tt.value)
		})
	}
}

// TestIsInjectionDetected 测试 isInjectionDetected 函数
func TestIsInjectionDetected(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantBool bool
	}{
		{
			name:     "Safe input",
			input:    "hello world",
			wantBool: false,
		},
		{
			name:     "SQL injection",
			input:    "SELECT * FROM users",
			wantBool: true,
		},
		{
			name:     "XSS injection",
			input:    "<iframe src='malicious.com'>",
			wantBool: true,
		},
		{
			name:     "Command injection",
			input:    "system('rm -rf /')",
			wantBool: true,
		},
		{
			name:     "Path injection",
			input:    "../config",
			wantBool: true,
		},
		{
			name:     "Case insensitive SQL",
			input:    "union SELECT",
			wantBool: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isInjectionDetected(tt.input)
			assert.Equal(t, tt.wantBool, result, "Expected detection result to be %v for input '%v'", tt.wantBool, tt.input)
		})
	}
}
