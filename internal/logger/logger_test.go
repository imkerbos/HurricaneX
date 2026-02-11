package logger

import (
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		component string
		level     string
	}{
		{name: "info level", component: "scheduler", level: "info"},
		{name: "debug level", component: "grpc", level: "debug"},
		{name: "invalid level defaults to info", component: "test", level: "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := New(tt.component, tt.level)
			if err != nil {
				t.Fatalf("New(%q, %q) error = %v", tt.component, tt.level, err)
			}
			if l == nil {
				t.Fatal("New() returned nil logger")
			}
			_ = l.Sync() // best-effort flush
		})
	}
}

func TestNewDev(t *testing.T) {
	l, err := NewDev("test")
	if err != nil {
		t.Fatalf("NewDev() error = %v", err)
	}
	if l == nil {
		t.Fatal("NewDev() returned nil logger")
	}
	_ = l.Sync()
}

func TestNewNop(t *testing.T) {
	l := NewNop()
	if l == nil {
		t.Fatal("NewNop() returned nil logger")
	}
	// Should not panic
	l.Info("this should be silently discarded")
}

func TestWithNodeID(t *testing.T) {
	l := NewNop()
	child := WithNodeID(l, "node-1")
	if child == nil {
		t.Fatal("WithNodeID() returned nil")
	}
}

func TestWithTaskID(t *testing.T) {
	l := NewNop()
	child := WithTaskID(l, "task-42")
	if child == nil {
		t.Fatal("WithTaskID() returned nil")
	}
}

func TestWithNodeAndTask(t *testing.T) {
	l := NewNop()
	child := WithNodeAndTask(l, "node-1", "task-42")
	if child == nil {
		t.Fatal("WithNodeAndTask() returned nil")
	}
}
