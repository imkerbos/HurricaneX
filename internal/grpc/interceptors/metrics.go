package interceptors

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// GRPCMetrics holds Prometheus metrics for gRPC calls.
type GRPCMetrics struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

// NewGRPCMetrics creates and registers gRPC metrics with the given registerer.
func NewGRPCMetrics(reg prometheus.Registerer) *GRPCMetrics {
	m := &GRPCMetrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hurricanex",
			Subsystem: "grpc",
			Name:      "requests_total",
			Help:      "Total number of gRPC requests by method and status.",
		}, []string{"method", "status"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "hurricanex",
			Subsystem: "grpc",
			Name:      "request_duration_seconds",
			Help:      "gRPC request duration in seconds.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0},
		}, []string{"method"}),
	}

	reg.MustRegister(m.requestsTotal, m.requestDuration)
	return m
}

// UnaryServerInterceptor returns a gRPC unary server interceptor for metrics collection.
func (m *GRPCMetrics) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {

		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		st, _ := status.FromError(err)
		m.requestsTotal.WithLabelValues(info.FullMethod, st.Code().String()).Inc()
		m.requestDuration.WithLabelValues(info.FullMethod).Observe(duration.Seconds())

		return resp, err
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor for metrics collection.
func (m *GRPCMetrics) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {

		start := time.Now()
		err := handler(srv, ss)
		duration := time.Since(start)

		st, _ := status.FromError(err)
		m.requestsTotal.WithLabelValues(info.FullMethod, st.Code().String()).Inc()
		m.requestDuration.WithLabelValues(info.FullMethod).Observe(duration.Seconds())

		return err
	}
}
