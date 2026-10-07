package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Client 是全局的 Redis 客户端实例
var Client *redis.Client

// Init 初始化 Redis 客户端
func Init(cfg *config.Config) {
	Client = redis.NewClient(&redis.Options{
		Addr:     cfg.Cache.Addr,     // Redis 地址
		Password: cfg.Cache.Password, // Redis 密码
		DB:       cfg.Cache.DB,       // Redis 数据库编号
	})

	// 测试连接
	ctx := context.Background()
	_, err := Client.Ping(ctx).Result()
	if err != nil {
		logger.Error("Failed to connect to Redis", zap.Error(err), zap.String("addr", cfg.Cache.Addr))
		panic(err)
	}
	logger.Info("Redis connected successfully", zap.String("addr", cfg.Cache.Addr))
}

// GetCacheKey 生成缓存键，基于 HTTP 方法和路径
func GetCacheKey(method, path string) string {
	return fmt.Sprintf("mg:cache:%s:%s", method, path)
}

// CheckCache 检查缓存是否存在并返回内容
func CheckCache(ctx context.Context, method, path string) (string, bool) {
	if Client == nil {
		logger.Warn("Redis client not initialized, skipping cache check")
		return "", false
	}

	key := GetCacheKey(method, path)
	content, err := Client.Get(ctx, key).Result()
	if err == redis.Nil {
		logger.Debug("Cache miss", zap.String("key", key))
		return "", false
	} else if err != nil {
		logger.Error("Failed to check cache", zap.Error(err), zap.String("key", key))
		return "", false
	}

	logger.Debug("Cache hit", zap.String("key", key))
	return content, true
}

// SetCache 设置缓存内容并指定过期时间
func SetCache(ctx context.Context, method, path, content string, ttl time.Duration) error {
	if Client == nil {
		logger.Warn("Redis client not initialized, skipping cache set")
		return fmt.Errorf("redis client not initialized")
	}

	key := GetCacheKey(method, path)
	err := Client.Set(ctx, key, content, ttl).Err()
	if err != nil {
		logger.Error("Failed to set cache", zap.Error(err), zap.String("key", key), zap.Duration("ttl", ttl))
		return err
	}

	logger.Debug("Cache set successfully", zap.String("key", key), zap.Duration("ttl", ttl))
	return nil
}

// IncrementRequestCount 增加指定路径的请求计数，返回当前计数。
// 当计数器为新建时，设置过期时间为当前TTL窗口长度。
func IncrementRequestCount(ctx context.Context, path string, ttl time.Duration) int64 {
	if Client == nil {
		logger.Warn("Redis client not initialized, skipping request count increment")
		return 0
	}

	key := GetPathReqCountKey(path)
	count, err := Client.Incr(ctx, key).Result()
	if err != nil {
		logger.Error("Failed to increment request count", zap.Error(err), zap.String("key", key))
		return 0
	}

	// 如果是新的计数，设置过期时间
	if count == 1 {
		err := Client.Expire(ctx, key, ttl).Err()
		if err != nil {
			logger.Error("Failed to set TTL for request count", zap.Error(err), zap.String("key", key), zap.Duration("ttl", ttl))
		}
	}

	logger.Debug("Request count incremented", zap.String("key", key), zap.Int64("count", count))
	return count
}

func GetPathReqCountKey(path string) string {
	return fmt.Sprintf("mg:cache:req_count:%s", path)
}

// ClearRequestCount 清除指定路径的请求计数（可选，用于测试或重置）
func ClearRequestCount(ctx context.Context, path string) error {
	if Client == nil {
		logger.Warn("Redis client not initialized, skipping request count clear")
		return fmt.Errorf("redis client not initialized")
	}

	key := GetPathReqCountKey(path)
	err := Client.Del(ctx, key).Err()
	if err != nil {
		logger.Error("Failed to clear request count", zap.Error(err), zap.String("key", key))
		return err
	}

	logger.Debug("Request count cleared", zap.String("key", key))
	return nil
}

type PathCount struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// BatchGetPathReqCount 批量获取多个路径的请求计数
func BatchGetPathReqCount(ctx context.Context, paths []string) ([]PathCount, error) {
	if Client == nil {
		logger.Warn("Redis client not initialized, skipping batch request count retrieval")
		return nil, fmt.Errorf("redis client not initialized")
	}

	keys := make([]string, len(paths))
	for i, path := range paths {
		keys[i] = GetPathReqCountKey(path)
	}

	counts, err := Client.MGet(ctx, keys...).Result()
	if err != nil {
		logger.Error("Failed to batch get request counts", zap.Error(err))
		return nil, err
	}

	results := make([]PathCount, len(paths))
	for i, count := range counts {
		// 初始化 PathCount 结构体
		results[i] = PathCount{
			Path: paths[i], // 假设 PathCount 结构体有 Path 字段
		}

		// 处理 Redis 返回的计数结果
		if count == nil { // key 不存在时返回 0
			results[i].Count = 0
		} else {
			// 将 interface{} 类型转换为字符串，然后转换为整数
			if countStr, ok := count.(string); ok {
				if val, err := strconv.ParseInt(countStr, 10, 64); err == nil {
					results[i].Count = val // 假设 PathCount 结构体有 Count 字段
				} else {
					logger.Warn("Failed to parse count value",
						zap.String("path", paths[i]),
						zap.String("value", countStr),
						zap.Error(err))
					results[i].Count = 0
				}
			} else {
				logger.Warn("Unexpected count type",
					zap.String("path", paths[i]),
					zap.Any("value", count))
				results[i].Count = 0
			}
		}
	}
	return results, nil
}

// ClearMethodCount 清除指定方法和路径的请求计数（可选，用于测试或重置）
func ClearMethodCount(ctx context.Context, method, path string) error {
	if Client == nil {
		logger.Warn("Redis client not initialized, skipping request count clear")
		return fmt.Errorf("redis client not initialized")
	}

	key := fmt.Sprintf("mg:cache:%s:%s", method, path)
	err := Client.Del(ctx, key).Err()
	if err != nil {
		logger.Error("Failed to clear method count", zap.Error(err), zap.String("key", key))
		return err
	}

	logger.Debug("Request method cleared", zap.String("key", key))
	return nil
}
