package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Collector holds all HurricaneX Prometheus metrics.
type Collector struct {
	Registry *prometheus.Registry

	ConnectionsActive *prometheus.GaugeVec
	ConnectionsTotal  *prometheus.CounterVec
	CPS               *prometheus.GaugeVec
	BytesSentTotal    *prometheus.CounterVec
	BytesRecvTotal    *prometheus.CounterVec
	ErrorsTotal       *prometheus.CounterVec
	LatencyUS         *prometheus.HistogramVec
	NodesActive       prometheus.Gauge
	TasksActive       prometheus.Gauge
}

// NewCollector creates and registers all HurricaneX metrics.
func NewCollector() *Collector {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	c := &Collector{
		Registry: reg,
		ConnectionsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "hurricanex", Name: "connections_active",
			Help: "Current active connections.",
		}, []string{"node_id"}),
		ConnectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hurricanex", Name: "connections_total",
			Help: "Total connections established.",
		}, []string{"node_id"}),
		CPS: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "hurricanex", Name: "cps",
			Help: "Current connections per second.",
		}, []string{"node_id"}),
		BytesSentTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hurricanex", Name: "bytes_sent_total",
			Help: "Total bytes sent.",
		}, []string{"node_id"}),
		BytesRecvTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hurricanex", Name: "bytes_recv_total",
			Help: "Total bytes received.",
		}, []string{"node_id"}),
		ErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "hurricanex", Name: "errors_total",
			Help: "Total errors by type.",
		}, []string{"node_id", "error_type"}),
		LatencyUS: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "hurricanex", Name: "latency_us",
			Help:    "Connection latency in microseconds.",
			Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 50000, 100000},
		}, []string{"node_id"}),
		NodesActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "hurricanex", Name: "nodes_active",
			Help: "Number of active engine nodes.",
		}),
		TasksActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "hurricanex", Name: "tasks_active",
			Help: "Number of active traffic tasks.",
		}),
	}

	reg.MustRegister(
		c.ConnectionsActive, c.ConnectionsTotal, c.CPS,
		c.BytesSentTotal, c.BytesRecvTotal,
		c.ErrorsTotal, c.LatencyUS,
		c.NodesActive, c.TasksActive,
	)

	return c
}

// Handler returns an HTTP handler for the /metrics endpoint.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.Registry, promhttp.HandlerOpts{})
}

// RecordNodeMetrics updates Prometheus metrics from a node's metrics report.
func (c *Collector) RecordNodeMetrics(nodeID string, activeConns, totalConns, cps, bytesSent, bytesRecv, errors int64, latencyAvgUS float64) {
	c.ConnectionsActive.WithLabelValues(nodeID).Set(float64(activeConns))
	c.ConnectionsTotal.WithLabelValues(nodeID).Add(float64(totalConns))
	c.CPS.WithLabelValues(nodeID).Set(float64(cps))
	c.BytesSentTotal.WithLabelValues(nodeID).Add(float64(bytesSent))
	c.BytesRecvTotal.WithLabelValues(nodeID).Add(float64(bytesRecv))
	if errors > 0 {
		c.ErrorsTotal.WithLabelValues(nodeID, "general").Add(float64(errors))
	}
	if latencyAvgUS > 0 {
		c.LatencyUS.WithLabelValues(nodeID).Observe(latencyAvgUS)
	}
}

// ServeHTTP starts the metrics HTTP server with /metrics and /healthz endpoints.
func ServeHTTP(addr string, collector *Collector, logger *zap.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", collector.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok")) // best-effort write
	})

	logger.Info("metrics server listening", zap.String("addr", addr))
	return http.ListenAndServe(addr, mux)
}
