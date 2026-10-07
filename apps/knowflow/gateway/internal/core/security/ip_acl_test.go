package security

import (
	"context"
	"testing"

	"github.com/DoraZa/mini-gateway/pkg/logger"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/cache"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

// TestCheckIPAccess 测试 CheckIPAccess 函数，使用 mock Cache
func TestCheckIPAccess(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		cfg         *config.Config
		mockSetup   func(redismock.ClientMock)
		wantAllowed bool
		wantErr     bool
		wantErrLogs int
	}{
		{
			name: "Allowed with no lists",
			ip:   "192.168.1.1",
			cfg: &config.Config{
				Security: config.Security{
					IPWhitelist: []string{},
					IPBlacklist: []string{},
				},
			},
			mockSetup:   func(mock redismock.ClientMock) {},
			wantAllowed: true,
			wantErr:     false,
			wantErrLogs: 0,
		},
		{
			name: "Whitelisted IP",
			ip:   "10.0.0.1",
			cfg: &config.Config{
				Security: config.Security{
					IPWhitelist: []string{"10.0.0.1"},
					IPBlacklist: []string{},
				},
			},
			mockSetup: func(mock redismock.ClientMock) {
				mock.ExpectHGet(whitelistKey, "10.0.0.1").SetVal("true")
			},
			wantAllowed: true,
			wantErr:     false,
			wantErrLogs: 0,
		},
		{
			name: "Not in whitelist",
			ip:   "192.168.1.1",
			cfg: &config.Config{
				Security: config.Security{
					IPWhitelist: []string{"10.0.0.1"},
					IPBlacklist: []string{},
				},
			},
			mockSetup: func(mock redismock.ClientMock) {
				mock.ExpectHGet(whitelistKey, "192.168.1.1").RedisNil()
			},
			wantAllowed: false,
			wantErr:     false,
			wantErrLogs: 0,
		},
		{
			name: "Blacklisted IP",
			ip:   "172.16.0.1",
			cfg: &config.Config{
				Security: config.Security{
					IPWhitelist: []string{},
					IPBlacklist: []string{"172.16.0.1"},
				},
			},
			mockSetup: func(mock redismock.ClientMock) {
				mock.ExpectHGet(blacklistKey, "172.16.0.1").SetVal("true")
			},
			wantAllowed: false,
			wantErr:     false,
			wantErrLogs: 0,
		},
		{
			name: "Not in blacklist",
			ip:   "192.168.1.1",
			cfg: &config.Config{
				Security: config.Security{
					IPWhitelist: []string{},
					IPBlacklist: []string{"172.16.0.1"},
				},
			},
			mockSetup: func(mock redismock.ClientMock) {
				mock.ExpectHGet(blacklistKey, "192.168.1.1").RedisNil()
			},
			wantAllowed: true,
			wantErr:     false,
			wantErrLogs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建 mock Cache 客户端
			db, mock := redismock.NewClientMock()
			cache.Client = db
			ctx := context.Background()

			// 设置日志捕获
			zapLogger, recordedLogs := logger.InitTestLogger()
			defer zapLogger.Sync() // 使用 zapLogger.Sync 替代 logger.Sync

			// 设置 mock 行为
			tt.mockSetup(mock)

			allowed, err := CheckIPAccess(ctx, tt.ip, tt.cfg)
			if tt.wantErr {
				assert.Error(t, err, "Expected an error")
			} else {
				assert.NoError(t, err, "Expected no error")
			}
			assert.Equal(t, tt.wantAllowed, allowed, "Expected allowed to be %v for IP %v", tt.wantAllowed, tt.ip)

			// 检查错误日志
			logs := recordedLogs.All()
			errLogs := 0
			for _, log := range logs {
				if log.Level == zapcore.ErrorLevel {
					errLogs++
					assert.Equal(t, "Failed to check IP access", log.Message, "Expected error message")
					assert.Equal(t, tt.ip, log.ContextMap()["ip"], "Expected IP in log")
				}
			}
			assert.Equal(t, tt.wantErrLogs, errLogs, "Expected %v error logs", tt.wantErrLogs)

			// 验证 mock 期望
			assert.NoError(t, mock.ExpectationsWereMet(), "Cache mock expectations were not met")
		})
	}
}

// TestInitIPRules 测试 InitIPRules 函数，使用 mock Cache
func TestInitIPRules(t *testing.T) {
	tests := []struct {
		name          string
		cfg           *config.Config
		mockSetup     func(redismock.ClientMock)
		wantBlacklist map[string]string
		wantWhitelist map[string]string
		wantErrCount  int
	}{
		{
			name: "Override mode with lists",
			cfg: &config.Config{
				Security: config.Security{
					IPUpdateMode: "override",
					IPWhitelist:  []string{"10.0.0.1", "10.0.0.2"},
					IPBlacklist:  []string{"172.16.0.1"},
				},
			},
			mockSetup: func(mock redismock.ClientMock) {
				mock.ExpectDel(blacklistKey, whitelistKey).SetVal(2)
				mock.ExpectHSet(whitelistKey, "10.0.0.1", "true").SetVal(1)
				mock.ExpectHSet(whitelistKey, "10.0.0.2", "true").SetVal(1)
				mock.ExpectHSet(blacklistKey, "172.16.0.1", "true").SetVal(1)
				mock.ExpectHGetAll(blacklistKey).SetVal(map[string]string{"172.16.0.1": "true"})
				mock.ExpectHGetAll(whitelistKey).SetVal(map[string]string{"10.0.0.1": "true", "10.0.0.2": "true"})
			},
			wantBlacklist: map[string]string{"172.16.0.1": "true"},
			wantWhitelist: map[string]string{"10.0.0.1": "true", "10.0.0.2": "true"},
			wantErrCount:  0,
		},
		{
			name: "Append mode with empty lists",
			cfg: &config.Config{
				Security: config.Security{
					IPUpdateMode: "append",
					IPWhitelist:  []string{},
					IPBlacklist:  []string{},
				},
			},
			mockSetup: func(mock redismock.ClientMock) {
				mock.ExpectHGetAll(blacklistKey).SetVal(map[string]string{})
				mock.ExpectHGetAll(whitelistKey).SetVal(map[string]string{})
			},
			wantBlacklist: map[string]string{},
			wantWhitelist: map[string]string{},
			wantErrCount:  0,
		},
		{
			name: "Override mode with Cache error",
			cfg: &config.Config{
				Security: config.Security{
					IPUpdateMode: "override",
					IPWhitelist:  []string{"10.0.0.1"},
					IPBlacklist:  []string{},
				},
			},
			mockSetup: func(mock redismock.ClientMock) {
				mock.ExpectDel(blacklistKey, whitelistKey).SetErr(redis.ErrClosed)
				mock.ExpectHSet(whitelistKey, "10.0.0.1", "true").SetVal(1)
				mock.ExpectHGetAll(blacklistKey).SetVal(map[string]string{})
				mock.ExpectHGetAll(whitelistKey).SetVal(map[string]string{"10.0.0.1": "true"})
			},
			wantBlacklist: map[string]string{},
			wantWhitelist: map[string]string{"10.0.0.1": "true"},
			wantErrCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建 mock Cache 客户端
			db, mock := redismock.NewClientMock()
			cache.Client = db
			ctx := context.Background()

			// 设置日志捕获
			zapLogger, recordedLogs := logger.InitTestLogger()
			defer zapLogger.Sync()

			// 设置 mock 行为
			tt.mockSetup(mock)

			InitIPRules(tt.cfg)

			// 检查 Cache 中的黑白名单
			blacklist, err := cache.Client.HGetAll(ctx, blacklistKey).Result()
			assert.NoError(t, err)
			assert.Equal(t, tt.wantBlacklist, blacklist, "Expected blacklist to match")

			whitelist, err := cache.Client.HGetAll(ctx, whitelistKey).Result()
			assert.NoError(t, err)
			assert.Equal(t, tt.wantWhitelist, whitelist, "Expected whitelist to match")

			// 检查错误日志数量
			logs := recordedLogs.All()
			errCount := 0
			for _, log := range logs {
				if log.Level == zapcore.ErrorLevel {
					errCount++
				}
			}
			assert.Equal(t, tt.wantErrCount, errCount, "Expected %v error logs", tt.wantErrCount)

			// 验证 mock 期望
			assert.NoError(t, mock.ExpectationsWereMet(), "Cache mock expectations were not met")
		})
	}
}
