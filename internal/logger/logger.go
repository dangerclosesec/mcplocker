package logger

import (
	"os"

	"github.com/bresrch/sawmill"
)

// Preset configurations for common scenarios
func NewDevelopmentLoggerOptions(debug bool) []sawmill.HandlerOption {
	opts := []sawmill.HandlerOption{
		sawmill.WithColorsEnabled(true),
		sawmill.WithColorMappings(map[string]string{
			"version":   sawmill.ColorBrightGreen,
			"timestamp": sawmill.ColorYellow,
			"debug":     sawmill.ColorGreen,
			"message":   sawmill.ColorGreen,
		}),
	}

	if debug {
		opts = append(opts,
			sawmill.WithLevel(sawmill.LevelDebug),
			sawmill.WithSourceInfo(true))
	} else {
		opts = append(opts, sawmill.WithLevel(sawmill.LevelInfo))
	}

	return opts
}

func NewProductionLoggerOptions(debug bool) []sawmill.HandlerOption {
	level := sawmill.LevelInfo
	opts := []sawmill.HandlerOption{sawmill.WithLevel(level)}

	if debug {
		opts[0] = sawmill.WithLevel(sawmill.LevelDebug)
		opts = append(opts, sawmill.WithSourceInfo(true))
	}

	return opts
}

func WithOptionsForEnvironment(env string, debug bool) []sawmill.HandlerOption {
	switch env {
	case "local", "development":
		return NewDevelopmentLoggerOptions(debug)
	case "staging", "production":
		return NewProductionLoggerOptions(debug)
	default:
		return NewProductionLoggerOptions(debug)
	}
}

// Helper function for environment variable with default
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
