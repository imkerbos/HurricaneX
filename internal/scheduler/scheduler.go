package scheduler

import (
	"fmt"
	"sync"
)

// NodeState represents the current state of an engine node.
type NodeState int

const (
	NodeOffline  NodeState = iota
	NodeOnline             // registered but not confirmed
	NodeReady              // confirmed and ready for tasks
	NodeRunning            // executing a traffic task
)

// Node represents a single engine node in the cluster.
type Node struct {
	ID      string
	Addr    string
	State   NodeState
	Workers int
}

// Scheduler manages distributed engine nodes.
type Scheduler struct {
	mu    sync.RWMutex
	nodes map[string]*Node
}

// New creates a new Scheduler.
func New() *Scheduler {
	return &Scheduler{
		nodes: make(map[string]*Node),
	}
}

// RegisterNode registers a new engine node. The node starts in Online state
// and must be confirmed before it can receive tasks.
func (s *Scheduler) RegisterNode(id, addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.nodes[id]; exists {
		return fmt.Errorf("node %s already registered", id)
	}

	s.nodes[id] = &Node{
		ID:    id,
		Addr:  addr,
		State: NodeOnline,
	}
	return nil
}

// ConfirmNode marks a node as ready for task scheduling.
func (s *Scheduler) ConfirmNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, exists := s.nodes[id]
	if !exists {
		return fmt.Errorf("node %s not found", id)
	}
	if node.State != NodeOnline {
		return fmt.Errorf("node %s is not in Online state", id)
	}

	node.State = NodeReady
	return nil
}

// ReadyNodes returns all nodes in Ready state.
func (s *Scheduler) ReadyNodes() []*Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ready []*Node
	for _, n := range s.nodes {
		if n.State == NodeReady {
			ready = append(ready, n)
		}
	}
	return ready
}

// RemoveNode removes a node from the scheduler.
func (s *Scheduler) RemoveNode(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nodes, id)
}
