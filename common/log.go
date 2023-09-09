package common

import (
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"sync"
	"time"
)

// 日志级别，int类型，内部接口使用常量
type LOG_LEVEL int

const (
	LEVEL_DEBUG LOG_LEVEL = iota
	LEVEL_INFO
	LEVEL_WARN
	LEVEL_ERROR
)

var (
	LOG_LEVEL_Name = map[LOG_LEVEL]string{
		0: "DEBUG",
		1: "INFO",
		2: "WARN",
		3: "ERROR",
	}
	LOG_LEVEL_Value = map[string]LOG_LEVEL{
		"DEBUG": 0,
		"INFO":  1,
		"WARN":  2,
		"ERROR": 3,
	}
)

// 日志切割默认配置
const (
	LOG_MODE_DEV  = "DEV"
	LOG_MODE_PROD = "PROD"
)

type LogConfig struct {
	BriefMode          string
	ModuleSpecialLevel map[string]LOG_LEVEL // 模块特别指定的日志级别

	ChainID        string // 通道ID
	LogPath        string
	LogLevel       LOG_LEVEL
	RotationMaxAge int // 日志的保存期限
	RotationTime   int // 日志rotation的间隔
	RotationSize   int // 日志rotation的大小
	ShowLine       bool
	LogInConsole   bool
}

// 若未设置配置，则按照DEV模式设置
func DefaultLogConfig(isDEV bool) *LogConfig {
	if isDEV {
		return defaultBriefLogConfigForDEV()
	}

	return defaultBriefLogConfigForPROD()
}

func defaultBriefLogConfigForDEV() *LogConfig {
	return &LogConfig{
		LogPath:        "./npcc.dev.log",
		LogLevel:       LEVEL_DEBUG,
		RotationMaxAge: 1,
		RotationTime:   1,
		RotationSize:   10,
		ShowLine:       true,
		LogInConsole:   true,
	}
}

func defaultBriefLogConfigForPROD() *LogConfig {
	return &LogConfig{
		LogPath:        "./npcc.prod.log",
		LogLevel:       LEVEL_INFO,
		RotationMaxAge: 1,
		RotationTime:   24,
		RotationSize:   30,
		ShowLine:       true,
		LogInConsole:   false,
	}
}

func adjustLogConfig(name string, lc *LogConfig) *LogConfig {
	ok := true
	if lc.BriefMode != "" {
		if lc.BriefMode == LOG_MODE_PROD {
			ok = false
		}
		return DefaultLogConfig(ok)
	}

	newC := &LogConfig{}
	newC.LogLevel, ok = lc.ModuleSpecialLevel[name]
	if !ok {
		newC.LogLevel = lc.LogLevel
	}
	newC.LogPath = lc.LogPath
	newC.LogInConsole = lc.LogInConsole
	newC.ShowLine = lc.ShowLine
	newC.RotationSize = lc.RotationSize
	newC.RotationTime = lc.RotationTime
	newC.RotationMaxAge = lc.RotationMaxAge

	return newC
}

func NewSugaredLogger(name string, lc *LogConfig) *zap.SugaredLogger {
	lcc := adjustLogConfig(name, lc)
	//1.创建level
	var zapLevel zapcore.Level
	switch lcc.LogLevel {
	case LEVEL_DEBUG:
		zapLevel = zap.DebugLevel
	case LEVEL_INFO:
		zapLevel = zap.InfoLevel
	case LEVEL_WARN:
		zapLevel = zap.WarnLevel
	case LEVEL_ERROR:
		zapLevel = zap.ErrorLevel
	default:
		zapLevel = zap.InfoLevel
	}

	//level := zap.NewAtomicLevel()
	//level.SetLevel(zapLevel)
	priorityLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapLevel
	})

	//2.创建syncer
	fileName := lcc.LogPath + ".%Y%m%d%H"
	ratationWriter, err := rotatelogs.New(
		fileName,
		rotatelogs.WithRotationTime(time.Duration(lcc.RotationTime)*time.Hour),
		rotatelogs.WithRotationSize(int64(lcc.RotationSize*1*1024*1024)),
		rotatelogs.WithMaxAge(time.Hour*24*time.Duration(lcc.RotationMaxAge)),
	)
	if err != nil {
		log.Fatalf("new ratation log failed, %s", err)
	}

	var syncer zapcore.WriteSyncer
	if lcc.LogInConsole {
		syncer = zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), zapcore.AddSync(ratationWriter))
	} else {
		syncer = zapcore.AddSync(ratationWriter)
	}
	//3.创建encoder
	customLevelEncoder := func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString("[" + level.CapitalString() + "]")
	}
	customTimeEncoder := func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
	}
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "line",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    customLevelEncoder,
		EncodeTime:     customTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeName:     zapcore.FullNameEncoder,
	}
	encoder := zapcore.NewConsoleEncoder(encoderConfig)
	//4.根据1-3，创建core
	core := zapcore.NewCore(encoder, syncer, priorityLevel)
	//5.创建SugaredLogger
	logger := zap.New(core).Named(name)
	defer logger.Sync()

	var opts []zap.Option
	if lcc.ShowLine {
		opts = append(opts, zap.AddCaller())

	}
	//logger最终是装载到NPCCLogger中使用的，因此这里跳过1层调用
	opts = append(opts, zap.AddCallerSkip(1))
	logger = logger.WithOptions(opts...)

	return logger.Sugar()
}

const (
	MODULE_BLOCKCHAIN = "[Blockchain]"
	MODULE_P2PNET     = "[P2PNet]"
	MODULE_STORAGE    = "[Storage]"
	MODULE_ELECT      = "[Elect]"
)

type Logger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

type NPCCLogger struct {
	zlog    *zap.SugaredLogger
	name    string
	chainID string
	mutex   sync.RWMutex
}

func (l *NPCCLogger) Logger() *zap.SugaredLogger {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.zlog
}

func (l *NPCCLogger) Debug(args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Debug(args...)
}

func (l *NPCCLogger) Debugf(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Debugf(format, args...)
}

func (l *NPCCLogger) Error(args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Error(args...)
}

func (l *NPCCLogger) Errorf(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Errorf(format, args...)
}

func (l *NPCCLogger) Fatal(args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Fatal(args...)
}

func (l *NPCCLogger) Fatalf(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Fatalf(format, args...)
}

func (l *NPCCLogger) Info(args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Info(args...)
}

func (l *NPCCLogger) Infof(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Infof(format, args...)
}

func (l *NPCCLogger) Panic(args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Panic(args...)
}

func (l *NPCCLogger) Panicf(format string, args ...interface{}) {
	l.zlog.Panicf(format, args...)
}

func (l *NPCCLogger) Warn(args ...interface{}) {
	l.zlog.Warn(args...)
}

func (l *NPCCLogger) Warnf(format string, args ...interface{}) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	l.zlog.Warnf(format, args...)
}

func (l *NPCCLogger) SetLogger(logger *zap.SugaredLogger) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.zlog = logger
}

var (
	npccLoggersMap = make(map[string]*NPCCLogger)
	loggerMutex    sync.RWMutex
	npccLogConfig  *LogConfig
)

func GetLogger(name string) *NPCCLogger {
	return GetLoggerWithChainID(name, "")
}

func GetLoggerWithChainID(name, chainID string) *NPCCLogger {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()

	loggerKey := name + chainID
	if logger, ok := npccLoggersMap[loggerKey]; ok {
		return logger
	}

	if npccLogConfig == nil {
		npccLogConfig = DefaultLogConfig(true)
	}

	zapLogger := NewSugaredLogger(name, npccLogConfig)
	logger := &NPCCLogger{
		name:    name,
		chainID: chainID,
		zlog:    zapLogger,
	}
	npccLoggersMap[loggerKey] = logger

	return logger
}

// 在获取日志对象之前进行配置设置，若未设置，则使用
func SetLogConfig(config *LogConfig) {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()

	npccLogConfig = config
	for _, logger := range npccLoggersMap {
		newLogger := NewSugaredLogger(logger.name, npccLogConfig)
		logger.SetLogger(newLogger)
	}
}
