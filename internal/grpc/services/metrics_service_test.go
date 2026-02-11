package services

import (
	"testing"

	"go.uber.org/zap"

	pb "github.com/kerbos/hurricanex/api/proto"
)

func TestMetricsServiceCreate(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	svc := NewMetricsServiceServer(logger)
	if svc == nil {
		t.Fatal("NewMetricsServiceServer() returned nil")
	}
	if svc.TotalReportsReceived() != 0 {
		t.Errorf("TotalReportsReceived() = %d, want 0", svc.TotalReportsReceived())
	}
}

func TestMetricsGetLatestNone(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	svc := NewMetricsServiceServer(logger)

	if m := svc.GetLatestMetrics("node-1"); m != nil {
		t.Error("GetLatestMetrics() should return nil for unknown node")
	}
}

func TestMetricsStoreAndRetrieve(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	svc := NewMetricsServiceServer(logger)

	// Simulate storing metrics directly (bypassing stream for unit test)
	report := &pb.MetricsReport{
		NodeId:            "node-1",
		Timestamp:         1000,
		ActiveConnections: 500,
		Cps:               2000,
		BytesSent:         1048576,
		LatencyAvgUs:      150.5,
	}
	svc.latestMetrics.Store("node-1", report)
	svc.reportsRecv.Add(1)

	if svc.TotalReportsReceived() != 1 {
		t.Errorf("TotalReportsReceived() = %d, want 1", svc.TotalReportsReceived())
	}

	got := svc.GetLatestMetrics("node-1")
	if got == nil {
		t.Fatal("GetLatestMetrics() returned nil")
	}
	if got.Cps != 2000 {
		t.Errorf("Cps = %d, want 2000", got.Cps)
	}
	if got.ActiveConnections != 500 {
		t.Errorf("ActiveConnections = %d, want 500", got.ActiveConnections)
	}
	if got.LatencyAvgUs != 150.5 {
		t.Errorf("LatencyAvgUs = %f, want 150.5", got.LatencyAvgUs)
	}
}
