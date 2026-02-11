package errors

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Sentinel errors for HurricaneX internal error conditions.
// These map to specific gRPC status codes via ToGRPC().
var (
	ErrNodeNotFound      = errors.New("node not found")
	ErrNodeAlreadyExists = errors.New("node already registered")
	ErrInvalidState      = errors.New("invalid state transition")
	ErrTaskNotFound      = errors.New("task not found")
	ErrTaskAlreadyRunning = errors.New("task already running")
)

// ToGRPC converts an internal error to a gRPC status error.
// Returns nil if err is nil.
func ToGRPC(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, ErrNodeNotFound), errors.Is(err, ErrTaskNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrNodeAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ErrInvalidState), errors.Is(err, ErrTaskAlreadyRunning):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
