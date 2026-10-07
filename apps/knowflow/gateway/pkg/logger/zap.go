package logger

import (
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger 定义全局日志实例
type Logger struct {
	*zap.Logger
}

// loggerInstance 用于存储全局日志实例
var (
	loggerInstance *Logger
	observedLogs   *observer.ObservedLogs
	loggerMutex    sync.Once
)

// Config 日志配置结构体
type Config struct {
	Level      string `mapstructure:"level"`      // 日志级别 (debug, info, warn, error)
	FilePath   string `mapstructure:"filePath"`   // 日志文件路径
	MaxSize    int    `mapstructure:"maxSize"`    // 单个日志文件最大大小 (MB)
	MaxBackups int    `mapstructure:"maxBackups"` // 保留的旧日志文件数
	MaxAge     int    `mapstructure:"maxAge"`     // 日志文件保留天数
	Compress   bool   `mapstructure:"compress"`   // 是否压缩旧日志文件
}

func InitTestLogger() (*Logger, *observer.ObservedLogs) {
	// 配置 Zap 的核心组件
	obsCore, recorded := observer.New(zapcore.DebugLevel)
	zapLogger := zap.New(obsCore, zap.AddCaller(), zap.AddCallerSkip(1))
	loggerInstance = &Logger{zapLogger}
	observedLogs = recorded

	// 替换全局 Zap logger，便于直接使用 zap.L()
	zap.ReplaceGlobals(zapLogger)

	return loggerInstance, observedLogs
}

// Init 初始化全局日志实例
func Init(cfg Config) *Logger {
	loggerMutex.Do(func() {
		// 配置 Zap 的核心组件
		core := zapcore.NewCore(
			getEncoder(),           // 日志编码器（JSON 格式）
			getWriteSyncer(cfg),    // 日志输出目标（文件 + 控制台）
			getLogLevel(cfg.Level), // 日志级别
		)

		// 创建 Zap Logger
		zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1), zap.AddStacktrace(zap.ErrorLevel))
		loggerInstance = &Logger{zapLogger}

		// 替换全局 Zap logger，便于直接使用 zap.L()
		zap.ReplaceGlobals(zapLogger)
	})

	return loggerInstance
}

// GetLogger 获取全局日志实例
func GetLogger() *Logger {
	if loggerInstance == nil {
		// 如果未初始化，使用默认配置
		return Init(Config{
			Level:      "info",
			FilePath:   "logs/gateway.log",
			MaxSize:    100, // 100 MB
			MaxBackups: 10,
			MaxAge:     30, // 30 天
			Compress:   true,
		})
	}
	return loggerInstance
}

// Sync 同步日志缓冲区，将未写入的日志刷新到输出目标
func Sync() error {
	logger := GetLogger()
	if logger == nil {
		return nil // 如果日志未初始化，无需同步
	}
	return logger.Logger.Sync()
}

// getEncoder 配置日志编码器（JSON 格式）
func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	// 修改时间格式为带时区的 RFC3339 格式
	encoderConfig.EncodeTime = zapcore.TimeEncoder(func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02T15:04:05-07:00"))
	})
	// 调整字段名称
	encoderConfig.TimeKey = "time"                            // 时间字段改为 "time"
	encoderConfig.LevelKey = "level"                          // 级别字段改为 "level"
	encoderConfig.MessageKey = "msg"                          // 消息字段改为 "msg"
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder // 级别使用小写 (info, error 等)
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder   // 可选：简化调用者信息
	return zapcore.NewConsoleEncoder(encoderConfig)
}

// getWriteSyncer 配置日志输出（文件 + 控制台）
func getWriteSyncer(cfg Config) zapcore.WriteSyncer {
	// 配置日志文件滚动
	fileWriter := &lumberjack.Logger{
		Filename:   cfg.FilePath,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	// 同时输出到文件和控制台
	return zapcore.NewMultiWriteSyncer(
		zapcore.AddSync(fileWriter),
		zapcore.AddSync(os.Stdout),
	)
}

// getLogLevel 将字符串级别转换为 Zap 的日志级别
func getLogLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel // 默认级别
	}
}

// 快捷方法，方便直接调用

// Debug 记录调试日志
func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

// Info 记录信息日志
func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

// Warn 记录警告日志
func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

// Error 记录错误日志
func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

// WithTrace 添加分布式追踪字段（例如 Trace ID）
func WithTrace(traceID string) *Logger {
	return &Logger{GetLogger().With(zap.String("trace_id", traceID))}
}
