package scheduler

import (
	"testing"

	"go.uber.org/zap"
)

func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return New(logger)
}

func TestRegisterNode(t *testing.T) {
	s := newTestScheduler(t)

	if err := s.RegisterNode("node-1", "10.0.0.1:9527"); err != nil {
		t.Fatalf("RegisterNode() error: %v", err)
	}

	// Duplicate registration should fail
	if err := s.RegisterNode("node-1", "10.0.0.1:9527"); err == nil {
		t.Error("RegisterNode() should fail for duplicate node")
	}
}

func TestConfirmNode(t *testing.T) {
	s := newTestScheduler(t)
	s.RegisterNode("node-1", "10.0.0.1:9527")

	if err := s.ConfirmNode("node-1"); err != nil {
		t.Fatalf("ConfirmNode() error: %v", err)
	}

	// Confirming again should fail (already Ready, not Online)
	if err := s.ConfirmNode("node-1"); err == nil {
		t.Error("ConfirmNode() should fail for non-Online node")
	}
}

func TestConfirmNonexistentNode(t *testing.T) {
	s := newTestScheduler(t)

	if err := s.ConfirmNode("ghost"); err == nil {
		t.Error("ConfirmNode() should fail for nonexistent node")
	}
}

func TestReadyNodes(t *testing.T) {
	s := newTestScheduler(t)

	// No nodes yet
	if got := s.ReadyNodes(); len(got) != 0 {
		t.Errorf("ReadyNodes() = %d nodes, want 0", len(got))
	}

	// Register 3 nodes, confirm 2
	s.RegisterNode("node-1", "10.0.0.1:9527")
	s.RegisterNode("node-2", "10.0.0.2:9527")
	s.RegisterNode("node-3", "10.0.0.3:9527")
	s.ConfirmNode("node-1")
	s.ConfirmNode("node-3")

	ready := s.ReadyNodes()
	if len(ready) != 2 {
		t.Fatalf("ReadyNodes() = %d nodes, want 2", len(ready))
	}

	ids := map[string]bool{}
	for _, n := range ready {
		ids[n.ID] = true
	}
	if !ids["node-1"] || !ids["node-3"] {
		t.Errorf("ReadyNodes() missing expected nodes, got %v", ids)
	}
	if ids["node-2"] {
		t.Error("ReadyNodes() should not include unconfirmed node-2")
	}
}

func TestRemoveNode(t *testing.T) {
	s := newTestScheduler(t)
	s.RegisterNode("node-1", "10.0.0.1:9527")
	s.ConfirmNode("node-1")

	s.RemoveNode("node-1")

	if got := s.ReadyNodes(); len(got) != 0 {
		t.Errorf("ReadyNodes() after remove = %d, want 0", len(got))
	}

	// Removing nonexistent node should not panic
	s.RemoveNode("ghost")
}

func TestNodeStateTransitions(t *testing.T) {
	s := newTestScheduler(t)
	s.RegisterNode("node-1", "10.0.0.1:9527")

	s.mu.RLock()
	node := s.nodes["node-1"]
	s.mu.RUnlock()

	if node.State != NodeOnline {
		t.Errorf("initial state = %d, want NodeOnline(%d)", node.State, NodeOnline)
	}

	s.ConfirmNode("node-1")
	if node.State != NodeReady {
		t.Errorf("after confirm state = %d, want NodeReady(%d)", node.State, NodeReady)
	}
}
