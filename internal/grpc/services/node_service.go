package services

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kerbos/hurricanex/api/proto"
	"github.com/kerbos/hurricanex/internal/scheduler"
)

// NodeServiceServer implements the NodeService gRPC service.
type NodeServiceServer struct {
	pb.UnimplementedNodeServiceServer
	sched  *scheduler.Scheduler
	logger *zap.Logger
}

// NewNodeServiceServer creates a new NodeServiceServer.
func NewNodeServiceServer(sched *scheduler.Scheduler, logger *zap.Logger) *NodeServiceServer {
	return &NodeServiceServer{
		sched:  sched,
		logger: logger.Named("node_service"),
	}
}

// Register handles node registration requests.
func (s *NodeServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}
	if req.Addr == "" {
		return nil, status.Error(codes.InvalidArgument, "addr is required")
	}

	if err := s.sched.RegisterNode(req.NodeId, req.Addr); err != nil {
		return nil, status.Errorf(codes.AlreadyExists, "register node: %v", err)
	}

	s.logger.Info("node registered via gRPC",
		zap.String("node_id", req.NodeId),
		zap.String("addr", req.Addr),
		zap.Int32("workers", req.Workers),
	)

	return &pb.RegisterResponse{
		Accepted: true,
		Message:  fmt.Sprintf("node %s registered, awaiting confirmation", req.NodeId),
	}, nil
}

// Heartbeat handles periodic heartbeat from engine nodes.
func (s *NodeServiceServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}

	s.logger.Debug("heartbeat received",
		zap.String("node_id", req.NodeId),
		zap.Int64("timestamp", req.Timestamp),
		zap.String("status", req.Status.String()),
	)

	// If node reports READY and is still Online, auto-confirm
	if req.Status == pb.NodeStatus_NODE_READY {
		if err := s.sched.ConfirmNode(req.NodeId); err != nil {
			// Not fatal — node might already be confirmed
			s.logger.Debug("confirm on heartbeat skipped",
				zap.String("node_id", req.NodeId),
				zap.Error(err),
			)
		}
	}

	_ = time.Now() // placeholder for future heartbeat tracking

	return &pb.HeartbeatResponse{Ok: true}, nil
}
