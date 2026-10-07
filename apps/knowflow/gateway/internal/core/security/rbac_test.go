package security

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/stretchr/testify/assert"
)

func resetForTest() {
	enforcer = nil
	tokenStore = make(map[string]string)
}

func TestInitRBAC(t *testing.T) {
	resetForTest()

	// 创建临时模型和策略文件
	modelContent := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	policyContent := "p, alice, data1, read\np, bob, data2, write"

	modelFile, err := os.CreateTemp("", "rbac_model_*.conf")
	assert.NoError(t, err)
	defer os.Remove(modelFile.Name())
	_, err = modelFile.WriteString(modelContent)
	assert.NoError(t, err)
	modelFile.Close()

	policyFile, err := os.CreateTemp("", "rbac_policy_*.csv")
	assert.NoError(t, err)
	defer os.Remove(policyFile.Name())
	_, err = policyFile.WriteString(policyContent)
	assert.NoError(t, err)
	policyFile.Close()

	cfg := &config.Config{
		Security: config.Security{
			RBAC: config.RBAC{
				ModelPath:  modelFile.Name(),
				PolicyPath: policyFile.Name(),
				Enabled:    true,
			},
		},
	}

	// 测试成功初始化
	err = InitRBAC(cfg)
	assert.NoError(t, err, "InitRBAC should succeed with valid paths")
	assert.NotNil(t, enforcer, "enforcer should be initialized")

	// 测试失败初始化
	resetForTest()
	cfg.Security.RBAC.ModelPath = "/invalid/path"
	err = InitRBAC(cfg)
	assert.Error(t, err, "InitRBAC should return error for invalid model path")
}

func TestGenerateRBACLoginToken(t *testing.T) {
	resetForTest()

	username := "testuser"
	token, err := GenerateRBACLoginToken(username)
	assert.NoError(t, err, "GenerateRBACLoginToken should succeed")
	assert.NotEmpty(t, token, "token should not be empty")
	assert.Equal(t, username, tokenStore[token], "token should map to username")
}

func TestValidateRBACLoginToken(t *testing.T) {
	resetForTest()

	// 预设一个有效令牌
	username := "testuser"
	machineID := "test-machine-id"
	rawToken := fmt.Sprintf("%s-%s-%d", machineID, username, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(rawToken))
	token := base64.URLEncoding.EncodeToString(hash[:])
	tokenStore[token] = username

	// 测试有效令牌
	returnedUsername, valid := ValidateRBACLoginToken(token)
	assert.True(t, valid, "token should be valid")
	assert.Equal(t, username, returnedUsername, "username should match")

	// 测试无效令牌
	invalidUsername, valid := ValidateRBACLoginToken("invalid-token")
	assert.False(t, valid, "invalid token should fail")
	assert.Empty(t, invalidUsername, "username should be empty for invalid token")
}
