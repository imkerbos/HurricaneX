package services

import (
	"io"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	pb "github.com/kerbos/hurricanex/api/proto"
)

// MetricsServiceServer implements the MetricsService gRPC service.
type MetricsServiceServer struct {
	pb.UnimplementedMetricsServiceServer
	logger        *zap.Logger
	reportsRecv   atomic.Int64
	latestMetrics sync.Map // node_id -> *pb.MetricsReport
}

// NewMetricsServiceServer creates a new MetricsServiceServer.
func NewMetricsServiceServer(logger *zap.Logger) *MetricsServiceServer {
	return &MetricsServiceServer{
		logger: logger.Named("metrics_service"),
	}
}

// ReportMetrics handles streaming metrics from engine nodes.
func (s *MetricsServiceServer) ReportMetrics(stream pb.MetricsService_ReportMetricsServer) error {
	for {
		report, err := stream.Recv()
		if err == io.EOF {
			s.logger.Debug("metrics stream closed")
			return stream.SendAndClose(&pb.MetricsAck{Ok: true})
		}
		if err != nil {
			return err
		}

		s.reportsRecv.Add(1)
		s.latestMetrics.Store(report.NodeId, report)

		s.logger.Debug("metrics received",
			zap.String("node_id", report.NodeId),
			zap.Int64("active_conns", report.ActiveConnections),
			zap.Int64("cps", report.Cps),
			zap.Int64("bytes_sent", report.BytesSent),
			zap.Float64("latency_avg_us", report.LatencyAvgUs),
		)
	}
}

// GetLatestMetrics returns the most recent metrics report for a node.
func (s *MetricsServiceServer) GetLatestMetrics(nodeID string) *pb.MetricsReport {
	val, ok := s.latestMetrics.Load(nodeID)
	if !ok {
		return nil
	}
	return val.(*pb.MetricsReport)
}

// TotalReportsReceived returns the total number of metrics reports received.
func (s *MetricsServiceServer) TotalReportsReceived() int64 {
	return s.reportsRecv.Load()
}
