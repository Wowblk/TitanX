package security

import (
	"testing"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// mockConfig 创建 mock 配置
func mockConfig(secret string, expiresIn int) *config.Config {
	config.InitTestConfigManager()
	return &config.Config{
		Security: config.Security{
			JWT: config.JWT{
				Secret:    secret,
				ExpiresIn: expiresIn,
			},
		},
	}
}

// TestInitJWT 测试 InitJWT 函数
func TestInitJWT(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		wantSecret string
	}{
		{
			name:       "With custom secret",
			cfg:        mockConfig("my-secret-key", 3600),
			wantSecret: "my-secret-key",
		},
		{
			name:       "With empty secret",
			cfg:        mockConfig("", 3600),
			wantSecret: "default-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 重置 jwtSecret
			jwtSecret = ""

			InitJWT(tt.cfg)

			assert.Equal(t, tt.wantSecret, jwtSecret, "Expected jwtSecret to be %v", tt.wantSecret)
		})
	}
}

// TestGenerateToken 测试 GenerateToken 函数
func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name     string
		username string
		cfg      *config.Config
		wantErr  bool
	}{
		{
			name:     "Valid token generation",
			username: "alice",
			cfg:      mockConfig("test-secret", 3600),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置 mock 配置
			config.SetConfig(tt.cfg)
			InitJWT(tt.cfg)

			token, err := GenerateToken(tt.username)
			if tt.wantErr {
				assert.Error(t, err, "Expected an error")
			} else {
				assert.NoError(t, err, "Expected no error")
				assert.NotEmpty(t, token, "Expected token to be generated")

				// 验证生成的 token
				claims, err := ValidateToken(token)
				assert.NoError(t, err)
				assert.Equal(t, tt.username, claims.Username)
				assert.WithinDuration(t, time.Now().Add(time.Duration(tt.cfg.Security.JWT.ExpiresIn)*time.Second), claims.ExpiresAt.Time, 2*time.Second)
			}
		})
	}
}

// TestValidateToken 测试 ValidateToken 函数
func TestValidateToken(t *testing.T) {
	// 设置一个测试密钥
	config.SetConfig(mockConfig("test-secret", 3600))
	InitJWT(config.GetConfig())

	// 生成一个有效的 token
	validToken, _ := GenerateToken("bob")

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "Valid token",
			token:   validToken,
			wantErr: false,
		},
		{
			name:    "Invalid token format",
			token:   "invalid.token.string",
			wantErr: true,
		},
		{
			name: "Expired token",
			token: func() string {
				claims := &Claims{
					Username: "alice",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
						Subject:   "alice",
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signedToken, _ := token.SignedString([]byte(jwtSecret))
				return signedToken
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateToken(tt.token)
			if tt.wantErr {
				assert.Error(t, err, "Expected an error")
				assert.Nil(t, claims, "Expected claims to be nil on error")
			} else {
				assert.NoError(t, err, "Expected no error")
				assert.NotNil(t, claims, "Expected claims to be returned")
				assert.Equal(t, "bob", claims.Username)
			}
		})
	}
}
