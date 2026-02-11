package server

import (
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/kerbos/hurricanex/internal/config"
	"github.com/kerbos/hurricanex/internal/grpc/auth"
	"github.com/kerbos/hurricanex/internal/grpc/interceptors"
)

// Server wraps a gRPC server with HurricaneX interceptors and mTLS.
type Server struct {
	gs     *grpc.Server
	logger *zap.Logger
	cfg    config.GRPCConfig
}

// New creates a new gRPC server with interceptors and optional mTLS.
func New(cfg config.GRPCConfig, logger *zap.Logger, grpcMetrics *interceptors.GRPCMetrics) (*Server, error) {
	var opts []grpc.ServerOption

	// mTLS credentials (only if CA cert is configured)
	if cfg.TLS.CACert != "" {
		creds, err := auth.ServerCredentials(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("setup server mTLS: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// Interceptor chain: recovery -> logging -> metrics
	opts = append(opts,
		grpc.ChainUnaryInterceptor(
			interceptors.UnaryServerRecovery(logger),
			interceptors.UnaryServerLogging(logger),
			grpcMetrics.UnaryServerInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			interceptors.StreamServerRecovery(logger),
			interceptors.StreamServerLogging(logger),
			grpcMetrics.StreamServerInterceptor(),
		),
	)

	return &Server{
		gs:     grpc.NewServer(opts...),
		logger: logger,
		cfg:    cfg,
	}, nil
}

// GRPCServer returns the underlying grpc.Server for service registration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.gs
}

// Serve starts listening and serving gRPC requests.
func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}

	s.logger.Info("grpc server listening", zap.String("addr", s.cfg.ListenAddr))
	return s.gs.Serve(lis)
}

// GracefulStop gracefully stops the gRPC server.
func (s *Server) GracefulStop() {
	s.logger.Info("grpc server shutting down")
	s.gs.GracefulStop()
}
