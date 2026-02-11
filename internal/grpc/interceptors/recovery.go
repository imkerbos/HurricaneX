package interceptors

import (
	"context"
	"runtime/debug"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryServerRecovery returns a gRPC unary server interceptor that recovers from panics.
func UnaryServerRecovery(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {

		defer func() {
			if r := recover(); r != nil {
				logger.Error("grpc panic recovered",
					zap.String("method", info.FullMethod),
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// StreamServerRecovery returns a gRPC stream server interceptor that recovers from panics.
func StreamServerRecovery(logger *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) (err error) {

		defer func() {
			if r := recover(); r != nil {
				logger.Error("grpc stream panic recovered",
					zap.String("method", info.FullMethod),
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(srv, ss)
	}
}
