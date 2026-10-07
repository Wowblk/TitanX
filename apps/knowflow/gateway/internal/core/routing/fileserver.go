package routing

import (
	"github.com/DoraZa/mini-gateway/config"
	"github.com/DoraZa/mini-gateway/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// FileServerRouter 处理静态文件服务，可使用 fasthttp 或 Gin 默认实现
type FileServerRouter struct {
	filePath string // 静态文件根目录
	enabled  bool   // 是否启用 fasthttp 实现零拷贝文件服务
}

// NewFileServerRouter 根据配置创建 FileServerRouter 实例
func NewFileServerRouter(cfg *config.Config) *FileServerRouter {
	return &FileServerRouter{
		filePath: cfg.FileServer.StaticFilePath,
		enabled:  cfg.FileServer.EnabledFastHttp,
	}
}

// Setup 在 Gin 路由器中配置静态文件服务路由
func (fr *FileServerRouter) Setup(r gin.IRouter, cfg *config.Config) {
	if fr.filePath == "" {
		logger.Warn("Static file serving disabled due to empty file path")
		return
	}

	// 注册静态文件服务路由
	r.GET("/static/*filepath", fr.serveStaticFile)
	if fr.enabled {
		logger.Info("FastHTTP static file serving enabled",
			zap.String("rootPath", fr.filePath))
	} else {
		logger.Info("Gin default static file serving enabled",
			zap.String("rootPath", fr.filePath))
	}
}

// serveStaticFile 处理静态文件请求，根据配置选择 fasthttp 或 Gin 实现
func (fr *FileServerRouter) serveStaticFile(c *gin.Context) {
	filepath := c.Param("filepath")
	if filepath == "" {
		logger.Warn("Invalid static file request: empty file path")
		c.JSON(400, gin.H{"error": "File path cannot be empty"})
		return
	}

	// 构建完整文件路径
	fullPath := fr.filePath + filepath
	logger.Debug("Handling static file request",
		zap.String("requestPath", c.Request.URL.Path),
		zap.String("fullPath", fullPath))

	if fr.enabled {
		// 使用 fasthttp 实现零拷贝文件服务
		fctx := &fasthttp.RequestCtx{
			Request:  fasthttp.Request{},
			Response: fasthttp.Response{},
		}
		fasthttp.ServeFile(fctx, fullPath)

		if fctx.Response.StatusCode() >= 400 {
			logger.Warn("FastHTTP failed to serve static file",
				zap.String("filePath", fullPath),
				zap.Int("statusCode", fctx.Response.StatusCode()))
			c.Data(fctx.Response.StatusCode(), string(fctx.Response.Header.ContentType()), fctx.Response.Body())
			return
		}

		// 直接写入 Gin 的响应流，避免数据拷贝
		c.Writer.WriteHeader(fctx.Response.StatusCode())
		fctx.Response.Header.VisitAll(func(key, value []byte) {
			c.Writer.Header().Set(string(key), string(value))
		})
		fctx.Response.BodyWriteTo(c.Writer)
		logger.Info("FastHTTP successfully served static file",
			zap.String("filePath", fullPath),
			zap.Int("statusCode", fctx.Response.StatusCode()))
	} else {
		// 使用 Gin 默认文件服务（非零拷贝）
		c.File(fullPath)
		if c.Writer.Status() >= 400 {
			logger.Warn("Gin failed to serve static file",
				zap.String("filePath", fullPath),
				zap.Int("statusCode", c.Writer.Status()))
			return
		}
		logger.Info("Gin successfully served static file",
			zap.String("filePath", fullPath),
			zap.Int("statusCode", c.Writer.Status()))
	}
}
