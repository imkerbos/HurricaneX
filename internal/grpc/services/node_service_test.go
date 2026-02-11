package services

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kerbos/hurricanex/api/proto"
	"github.com/kerbos/hurricanex/internal/scheduler"
)

func newTestNodeService(t *testing.T) (*NodeServiceServer, *scheduler.Scheduler) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	sched := scheduler.New(logger)
	return NewNodeServiceServer(sched, logger), sched
}

func TestNodeRegister(t *testing.T) {
	svc, _ := newTestNodeService(t)
	ctx := context.Background()

	resp, err := svc.Register(ctx, &pb.RegisterRequest{
		NodeId:   "node-1",
		Addr:     "10.0.0.1:9527",
		Workers:  4,
		MemoryMb: 32768,
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if !resp.Accepted {
		t.Error("Register() accepted = false, want true")
	}
}

func TestNodeRegisterDuplicate(t *testing.T) {
	svc, _ := newTestNodeService(t)
	ctx := context.Background()

	svc.Register(ctx, &pb.RegisterRequest{NodeId: "node-1", Addr: "10.0.0.1:9527"})

	_, err := svc.Register(ctx, &pb.RegisterRequest{NodeId: "node-1", Addr: "10.0.0.1:9527"})
	if err == nil {
		t.Fatal("Register() should fail for duplicate node")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.AlreadyExists {
		t.Errorf("Register() error code = %v, want AlreadyExists", s.Code())
	}
}

func TestNodeRegisterMissingFields(t *testing.T) {
	svc, _ := newTestNodeService(t)
	ctx := context.Background()

	tests := []struct {
		name string
		req  *pb.RegisterRequest
	}{
		{"empty_node_id", &pb.RegisterRequest{Addr: "10.0.0.1:9527"}},
		{"empty_addr", &pb.RegisterRequest{NodeId: "node-1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Register(ctx, tt.req)
			if err == nil {
				t.Error("Register() should fail for missing fields")
			}
			if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
				t.Errorf("error code = %v, want InvalidArgument", s.Code())
			}
		})
	}
}

func TestNodeHeartbeat(t *testing.T) {
	svc, sched := newTestNodeService(t)
	ctx := context.Background()

	sched.RegisterNode("node-1", "10.0.0.1:9527")

	resp, err := svc.Heartbeat(ctx, &pb.HeartbeatRequest{
		NodeId:    "node-1",
		Timestamp: 1000,
		Status:    pb.NodeStatus_NODE_ONLINE,
	})
	if err != nil {
		t.Fatalf("Heartbeat() error: %v", err)
	}
	if !resp.Ok {
		t.Error("Heartbeat() ok = false, want true")
	}
}

func TestNodeHeartbeatAutoConfirm(t *testing.T) {
	svc, sched := newTestNodeService(t)
	ctx := context.Background()

	sched.RegisterNode("node-1", "10.0.0.1:9527")

	// Heartbeat with READY status should auto-confirm
	svc.Heartbeat(ctx, &pb.HeartbeatRequest{
		NodeId: "node-1",
		Status: pb.NodeStatus_NODE_READY,
	})

	ready := sched.ReadyNodes()
	if len(ready) != 1 {
		t.Errorf("ReadyNodes() = %d, want 1 (auto-confirm failed)", len(ready))
	}
}

func TestNodeHeartbeatMissingNodeID(t *testing.T) {
	svc, _ := newTestNodeService(t)
	ctx := context.Background()

	_, err := svc.Heartbeat(ctx, &pb.HeartbeatRequest{})
	if err == nil {
		t.Error("Heartbeat() should fail for empty node_id")
	}
}
