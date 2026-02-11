package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	yaml := `
target:
  host: "example.com"
  port: 443
  tls: true
  path: "/api"
engine:
  workers: 4
  connections: 10000
  cps: 5000
  duration_sec: 60
  mempool_size: 131072
scheduler:
  listen_addr: "0.0.0.0:9527"
  max_nodes: 8
  heartbeat_sec: 3
grpc:
  listen_addr: "0.0.0.0:9527"
metrics:
  enabled: true
  listen_addr: ":9090"
log:
  level: "debug"
  dev: true
`
	path := writeTempConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Target.Host != "example.com" {
		t.Errorf("Target.Host = %q, want %q", cfg.Target.Host, "example.com")
	}
	if cfg.Target.Port != 443 {
		t.Errorf("Target.Port = %d, want 443", cfg.Target.Port)
	}
	if !cfg.Target.TLS {
		t.Error("Target.TLS = false, want true")
	}
	if cfg.Engine.Workers != 4 {
		t.Errorf("Engine.Workers = %d, want 4", cfg.Engine.Workers)
	}
	if cfg.Engine.CPS != 5000 {
		t.Errorf("Engine.CPS = %d, want 5000", cfg.Engine.CPS)
	}
	if cfg.Scheduler.MaxNodes != 8 {
		t.Errorf("Scheduler.MaxNodes = %d, want 8", cfg.Scheduler.MaxNodes)
	}
}

func TestLoadDefaults(t *testing.T) {
	yaml := `
target:
  host: "example.com"
`
	path := writeTempConfig(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"Target.Port", cfg.Target.Port, 80},
		{"Target.Path", cfg.Target.Path, "/"},
		{"Engine.Workers", cfg.Engine.Workers, 1},
		{"Engine.Connections", cfg.Engine.Connections, 1000},
		{"Engine.CPS", cfg.Engine.CPS, 100},
		{"Engine.DurationSec", cfg.Engine.DurationSec, 10},
		{"Engine.MempoolSize", cfg.Engine.MempoolSize, 65536},
		{"Scheduler.ListenAddr", cfg.Scheduler.ListenAddr, "0.0.0.0:9527"},
		{"Scheduler.MaxNodes", cfg.Scheduler.MaxNodes, 16},
		{"Scheduler.HeartbeatSec", cfg.Scheduler.HeartbeatSec, 5},
		{"GRPC.ListenAddr", cfg.GRPC.ListenAddr, "0.0.0.0:9527"},
		{"Metrics.ListenAddr", cfg.Metrics.ListenAddr, ":9090"},
		{"Log.Level", cfg.Log.Level, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestValidateInvalidPort(t *testing.T) {
	cfg := &Config{
		Target: TargetConfig{Port: 99999},
		Engine: EngineConfig{Workers: 1, Connections: 1, CPS: 1, DurationSec: 1},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for port 99999")
	}
}

func TestValidateZeroWorkers(t *testing.T) {
	cfg := &Config{
		Target: TargetConfig{Port: 80},
		Engine: EngineConfig{Workers: 0, Connections: 1, CPS: 1, DurationSec: 1},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for 0 workers")
	}
}

func TestValidateZeroCPS(t *testing.T) {
	cfg := &Config{
		Target: TargetConfig{Port: 80},
		Engine: EngineConfig{Workers: 1, Connections: 1, CPS: 0, DurationSec: 1},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for 0 CPS")
	}
}

func TestValidateZeroConnections(t *testing.T) {
	cfg := &Config{
		Target: TargetConfig{Port: 80},
		Engine: EngineConfig{Workers: 1, Connections: 0, CPS: 1, DurationSec: 1},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for 0 connections")
	}
}

func TestValidateZeroDuration(t *testing.T) {
	cfg := &Config{
		Target: TargetConfig{Port: 80},
		Engine: EngineConfig{Workers: 1, Connections: 1, CPS: 1, DurationSec: 0},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for 0 duration")
	}
}

func TestValidateTLSIncomplete(t *testing.T) {
	cfg := &Config{
		Target: TargetConfig{Port: 80},
		Engine: EngineConfig{Workers: 1, Connections: 1, CPS: 1, DurationSec: 1},
		GRPC: GRPCConfig{
			TLS: TLSConfig{
				CACert: "/path/to/ca.pem",
				// Missing ServerCert and ServerKey
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail when ca_cert is set but server cert/key missing")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Load() should fail for nonexistent file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "{{invalid yaml")
	_, err := Load(path)
	if err == nil {
		t.Error("Load() should fail for invalid YAML")
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
