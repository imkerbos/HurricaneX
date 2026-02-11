package interceptors

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// UnaryServerLogging returns a gRPC unary server interceptor that logs each call.
func UnaryServerLogging(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {

		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		st, _ := status.FromError(err)
		logger.Info("grpc unary call",
			zap.String("method", info.FullMethod),
			zap.String("status", st.Code().String()),
			zap.Duration("duration", duration),
			zap.Error(err),
		)

		return resp, err
	}
}

// StreamServerLogging returns a gRPC stream server interceptor that logs stream lifecycle.
func StreamServerLogging(logger *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {

		start := time.Now()
		err := handler(srv, ss)
		duration := time.Since(start)

		st, _ := status.FromError(err)
		logger.Info("grpc stream closed",
			zap.String("method", info.FullMethod),
			zap.String("status", st.Code().String()),
			zap.Duration("duration", duration),
			zap.Error(err),
		)

		return err
	}
}
