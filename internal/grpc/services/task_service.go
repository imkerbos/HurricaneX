package services

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kerbos/hurricanex/api/proto"
	"github.com/kerbos/hurricanex/internal/scheduler"
)

// TaskState represents the lifecycle state of a traffic task.
type TaskState string

const (
	TaskPending   TaskState = "pending"
	TaskRunning   TaskState = "running"
	TaskCompleted TaskState = "completed"
	TaskFailed    TaskState = "failed"
)

// Task holds the state of a deployed traffic task.
type Task struct {
	ID      string
	State   TaskState
	Config  *pb.DeployRequest
	NodeIDs []string
}

// TaskServiceServer implements the TaskService gRPC service.
type TaskServiceServer struct {
	pb.UnimplementedTaskServiceServer
	mu     sync.RWMutex
	tasks  map[string]*Task
	sched  *scheduler.Scheduler
	logger *zap.Logger
}

// NewTaskServiceServer creates a new TaskServiceServer.
func NewTaskServiceServer(sched *scheduler.Scheduler, logger *zap.Logger) *TaskServiceServer {
	return &TaskServiceServer{
		tasks:  make(map[string]*Task),
		sched:  sched,
		logger: logger.Named("task_service"),
	}
}

// Deploy handles task deployment requests.
func (s *TaskServiceServer) Deploy(ctx context.Context, req *pb.DeployRequest) (*pb.DeployResponse, error) {
	if req.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}
	if req.Target == nil {
		return nil, status.Error(codes.InvalidArgument, "target config is required")
	}
	if req.Target.Host == "" {
		return nil, status.Error(codes.InvalidArgument, "target.host is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tasks[req.TaskId]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "task %s already exists", req.TaskId)
	}

	// Determine target nodes
	nodeIDs := req.NodeIds
	if len(nodeIDs) == 0 {
		// Use all ready nodes
		ready := s.sched.ReadyNodes()
		if len(ready) == 0 {
			return nil, status.Error(codes.FailedPrecondition, "no ready nodes available")
		}
		for _, n := range ready {
			nodeIDs = append(nodeIDs, n.ID)
		}
	}

	task := &Task{
		ID:      req.TaskId,
		State:   TaskPending,
		Config:  req,
		NodeIDs: nodeIDs,
	}
	s.tasks[req.TaskId] = task

	s.logger.Info("task deployed",
		zap.String("task_id", req.TaskId),
		zap.String("target", req.Target.Host),
		zap.Int("node_count", len(nodeIDs)),
	)

	return &pb.DeployResponse{
		Accepted: true,
		TaskId:   req.TaskId,
		Message:  fmt.Sprintf("task deployed to %d node(s)", len(nodeIDs)),
	}, nil
}

// Stop handles task stop requests.
func (s *TaskServiceServer) Stop(ctx context.Context, req *pb.StopRequest) (*pb.StopResponse, error) {
	if req.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	task, exists := s.tasks[req.TaskId]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "task %s not found", req.TaskId)
	}

	if task.State != TaskRunning && task.State != TaskPending {
		return nil, status.Errorf(codes.FailedPrecondition,
			"task %s is in state %s, cannot stop", req.TaskId, task.State)
	}

	task.State = TaskCompleted

	s.logger.Info("task stopped",
		zap.String("task_id", req.TaskId),
	)

	return &pb.StopResponse{Ok: true}, nil
}

// Status handles task status queries.
func (s *TaskServiceServer) Status(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	if req.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	task, exists := s.tasks[req.TaskId]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "task %s not found", req.TaskId)
	}

	var nodeStatuses []*pb.NodeTaskStatus
	for _, nid := range task.NodeIDs {
		nodeStatuses = append(nodeStatuses, &pb.NodeTaskStatus{
			NodeId: nid,
			State:  string(task.State),
		})
	}

	return &pb.StatusResponse{
		TaskId: task.ID,
		State:  string(task.State),
		Nodes:  nodeStatuses,
	}, nil
}
