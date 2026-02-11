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

func newTestTaskService(t *testing.T) (*TaskServiceServer, *scheduler.Scheduler) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	sched := scheduler.New(logger)
	return NewTaskServiceServer(sched, logger), sched
}

func TestTaskDeploy(t *testing.T) {
	svc, sched := newTestTaskService(t)
	ctx := context.Background()

	// Register and confirm a node
	sched.RegisterNode("node-1", "10.0.0.1:9527")
	sched.ConfirmNode("node-1")

	resp, err := svc.Deploy(ctx, &pb.DeployRequest{
		TaskId: "task-1",
		Target: &pb.TargetConfig{Host: "example.com", Port: 443, Tls: true},
		Engine: &pb.EngineConfig{Workers: 4, Connections: 10000, Cps: 5000, DurationSec: 60},
	})
	if err != nil {
		t.Fatalf("Deploy() error: %v", err)
	}
	if !resp.Accepted {
		t.Error("Deploy() accepted = false, want true")
	}
	if resp.TaskId != "task-1" {
		t.Errorf("Deploy() task_id = %q, want %q", resp.TaskId, "task-1")
	}
}

func TestTaskDeployDuplicate(t *testing.T) {
	svc, sched := newTestTaskService(t)
	ctx := context.Background()

	sched.RegisterNode("node-1", "10.0.0.1:9527")
	sched.ConfirmNode("node-1")

	req := &pb.DeployRequest{
		TaskId: "task-1",
		Target: &pb.TargetConfig{Host: "example.com"},
	}
	svc.Deploy(ctx, req)

	_, err := svc.Deploy(ctx, req)
	if err == nil {
		t.Fatal("Deploy() should fail for duplicate task")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.AlreadyExists {
		t.Errorf("error code = %v, want AlreadyExists", s.Code())
	}
}

func TestTaskDeployNoReadyNodes(t *testing.T) {
	svc, _ := newTestTaskService(t)
	ctx := context.Background()

	_, err := svc.Deploy(ctx, &pb.DeployRequest{
		TaskId: "task-1",
		Target: &pb.TargetConfig{Host: "example.com"},
	})
	if err == nil {
		t.Fatal("Deploy() should fail when no ready nodes")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.FailedPrecondition {
		t.Errorf("error code = %v, want FailedPrecondition", s.Code())
	}
}

func TestTaskDeployMissingFields(t *testing.T) {
	svc, _ := newTestTaskService(t)
	ctx := context.Background()

	tests := []struct {
		name string
		req  *pb.DeployRequest
	}{
		{"empty_task_id", &pb.DeployRequest{Target: &pb.TargetConfig{Host: "x"}}},
		{"nil_target", &pb.DeployRequest{TaskId: "t1"}},
		{"empty_host", &pb.DeployRequest{TaskId: "t1", Target: &pb.TargetConfig{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Deploy(ctx, tt.req)
			if err == nil {
				t.Error("Deploy() should fail")
			}
			if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
				t.Errorf("error code = %v, want InvalidArgument", s.Code())
			}
		})
	}
}

func TestTaskDeploySpecificNodes(t *testing.T) {
	svc, sched := newTestTaskService(t)
	ctx := context.Background()

	sched.RegisterNode("node-1", "10.0.0.1:9527")
	sched.ConfirmNode("node-1")
	sched.RegisterNode("node-2", "10.0.0.2:9527")
	sched.ConfirmNode("node-2")

	resp, err := svc.Deploy(ctx, &pb.DeployRequest{
		TaskId:  "task-1",
		Target:  &pb.TargetConfig{Host: "example.com"},
		NodeIds: []string{"node-2"},
	})
	if err != nil {
		t.Fatalf("Deploy() error: %v", err)
	}
	if !resp.Accepted {
		t.Error("Deploy() accepted = false")
	}
}

func TestTaskStop(t *testing.T) {
	svc, sched := newTestTaskService(t)
	ctx := context.Background()

	sched.RegisterNode("node-1", "10.0.0.1:9527")
	sched.ConfirmNode("node-1")
	svc.Deploy(ctx, &pb.DeployRequest{
		TaskId: "task-1",
		Target: &pb.TargetConfig{Host: "example.com"},
	})

	resp, err := svc.Stop(ctx, &pb.StopRequest{TaskId: "task-1"})
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if !resp.Ok {
		t.Error("Stop() ok = false")
	}
}

func TestTaskStopNotFound(t *testing.T) {
	svc, _ := newTestTaskService(t)
	ctx := context.Background()

	_, err := svc.Stop(ctx, &pb.StopRequest{TaskId: "ghost"})
	if err == nil {
		t.Fatal("Stop() should fail for nonexistent task")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
		t.Errorf("error code = %v, want NotFound", s.Code())
	}
}

func TestTaskStatus(t *testing.T) {
	svc, sched := newTestTaskService(t)
	ctx := context.Background()

	sched.RegisterNode("node-1", "10.0.0.1:9527")
	sched.ConfirmNode("node-1")
	svc.Deploy(ctx, &pb.DeployRequest{
		TaskId: "task-1",
		Target: &pb.TargetConfig{Host: "example.com"},
	})

	resp, err := svc.Status(ctx, &pb.StatusRequest{TaskId: "task-1"})
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if resp.TaskId != "task-1" {
		t.Errorf("Status() task_id = %q, want %q", resp.TaskId, "task-1")
	}
	if resp.State != "pending" {
		t.Errorf("Status() state = %q, want %q", resp.State, "pending")
	}
	if len(resp.Nodes) != 1 {
		t.Errorf("Status() nodes = %d, want 1", len(resp.Nodes))
	}
}

func TestTaskStatusNotFound(t *testing.T) {
	svc, _ := newTestTaskService(t)
	ctx := context.Background()

	_, err := svc.Status(ctx, &pb.StatusRequest{TaskId: "ghost"})
	if err == nil {
		t.Fatal("Status() should fail for nonexistent task")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
		t.Errorf("error code = %v, want NotFound", s.Code())
	}
}
