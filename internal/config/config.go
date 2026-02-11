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
	return cfg, nil
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
}
