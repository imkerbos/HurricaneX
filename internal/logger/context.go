package logger

import (
	"go.uber.org/zap"
)

// WithNodeID returns a child logger with node_id field attached.
func WithNodeID(l *zap.Logger, nodeID string) *zap.Logger {
	return l.With(zap.String("node_id", nodeID))
}

// WithTaskID returns a child logger with task_id field attached.
func WithTaskID(l *zap.Logger, taskID string) *zap.Logger {
	return l.With(zap.String("task_id", taskID))
}

// WithNodeAndTask returns a child logger with both node_id and task_id.
func WithNodeAndTask(l *zap.Logger, nodeID, taskID string) *zap.Logger {
	return l.With(
		zap.String("node_id", nodeID),
		zap.String("task_id", taskID),
	)
}
