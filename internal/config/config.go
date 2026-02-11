package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for HurricaneX.
type Config struct {
	Target    TargetConfig    `yaml:"target"`
	Engine    EngineConfig    `yaml:"engine"`
	Scheduler SchedulerConfig `yaml:"scheduler"`
	GRPC      GRPCConfig      `yaml:"grpc"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Log       LogConfig       `yaml:"log"`
}

// TargetConfig defines the traffic target.
type TargetConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	TLS  bool   `yaml:"tls"`
	Path string `yaml:"path"`
}

// EngineConfig defines engine tuning parameters.
type EngineConfig struct {
	Workers     int `yaml:"workers"`
	Connections int `yaml:"connections"`
	CPS         int `yaml:"cps"`
	DurationSec int `yaml:"duration_sec"`
	MempoolSize int `yaml:"mempool_size"`
}

// SchedulerConfig defines distributed scheduling parameters.
type SchedulerConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	MaxNodes     int    `yaml:"max_nodes"`
	HeartbeatSec int    `yaml:"heartbeat_sec"`
}

// GRPCConfig defines gRPC connection settings.
type GRPCConfig struct {
	ListenAddr string    `yaml:"listen_addr"`
	TLS        TLSConfig `yaml:"tls"`
}

// TLSConfig defines mTLS certificate paths.
type TLSConfig struct {
	CACert     string `yaml:"ca_cert"`
	ServerCert string `yaml:"server_cert"`
	ServerKey  string `yaml:"server_key"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
}

// MetricsConfig defines Prometheus metrics settings.
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
}

// LogConfig defines logging settings.
type LogConfig struct {
	Level string `yaml:"level"`
	Dev   bool   `yaml:"dev"`
}

// Load reads and parses a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for invalid values.
func (c *Config) Validate() error {
	if c.Target.Port < 0 || c.Target.Port > 65535 {
		return fmt.Errorf("invalid target port: %d", c.Target.Port)
	}
	if c.Engine.Workers < 1 {
		return fmt.Errorf("workers must be >= 1, got %d", c.Engine.Workers)
	}
	if c.Engine.CPS < 1 {
		return fmt.Errorf("cps must be >= 1, got %d", c.Engine.CPS)
	}
	if c.Engine.Connections < 1 {
		return fmt.Errorf("connections must be >= 1, got %d", c.Engine.Connections)
	}
	if c.Engine.DurationSec < 1 {
		return fmt.Errorf("duration_sec must be >= 1, got %d", c.Engine.DurationSec)
	}
	if c.GRPC.TLS.CACert != "" {
		if c.GRPC.TLS.ServerCert == "" || c.GRPC.TLS.ServerKey == "" {
			return fmt.Errorf("grpc.tls: ca_cert is set but server_cert or server_key is missing")
		}
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.Target.Port == 0 {
		cfg.Target.Port = 80
	}
	if cfg.Target.Path == "" {
		cfg.Target.Path = "/"
	}
	if cfg.Engine.Workers == 0 {
		cfg.Engine.Workers = 1
	}
	if cfg.Engine.Connections == 0 {
		cfg.Engine.Connections = 1000
	}
	if cfg.Engine.CPS == 0 {
		cfg.Engine.CPS = 100
	}
	if cfg.Engine.DurationSec == 0 {
		cfg.Engine.DurationSec = 10
	}
	if cfg.Engine.MempoolSize == 0 {
		cfg.Engine.MempoolSize = 65536
	}
	if cfg.Scheduler.ListenAddr == "" {
		cfg.Scheduler.ListenAddr = "0.0.0.0:9527"
	}
	if cfg.Scheduler.MaxNodes == 0 {
		cfg.Scheduler.MaxNodes = 16
	}
	if cfg.Scheduler.HeartbeatSec == 0 {
		cfg.Scheduler.HeartbeatSec = 5
	}
	if cfg.GRPC.ListenAddr == "" {
		cfg.GRPC.ListenAddr = "0.0.0.0:9527"
	}
	if cfg.Metrics.ListenAddr == "" {
		cfg.Metrics.ListenAddr = ":9090"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
}
