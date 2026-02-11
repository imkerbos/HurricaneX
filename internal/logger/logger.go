package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New creates a production JSON logger for the given component and level.
// Level is one of: "debug", "info", "warn", "error". Invalid levels default to "info".
func New(component string, level string) (*zap.Logger, error) {
	lvl, err := zapcore.ParseLevel(level)
	if err != nil {
		lvl = zapcore.InfoLevel
	}

	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(lvl),
		Encoding:         "json",
		EncoderConfig:    productionEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		InitialFields: map[string]any{
			"component": component,
		},
	}

	return cfg.Build()
}

// NewDev creates a development logger with human-readable console output.
func NewDev(component string) (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()
	cfg.InitialFields = map[string]any{
		"component": component,
	}
	return cfg.Build()
}

// NewNop creates a no-op logger for testing.
func NewNop() *zap.Logger {
	return zap.NewNop()
}

func productionEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "component",
		MessageKey:     "msg",
		CallerKey:      "",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
		EncodeName:     zapcore.FullNameEncoder,
	}
}
