package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector() returned nil")
	}
	if c.Registry == nil {
		t.Error("Registry is nil")
	}
}

func TestMetricsHandler(t *testing.T) {
	c := NewCollector()

	// Record some values so metrics appear in output
	c.RecordNodeMetrics("test", 1, 1, 1, 1, 1, 1, 1.0)
	c.NodesActive.Set(1)
	c.TasksActive.Set(1)

	handler := c.Handler()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Should contain our custom metrics
	expectedMetrics := []string{
		"hurricanex_connections_active",
		"hurricanex_connections_total",
		"hurricanex_cps",
		"hurricanex_bytes_sent_total",
		"hurricanex_bytes_recv_total",
		"hurricanex_errors_total",
		"hurricanex_latency_us",
		"hurricanex_nodes_active",
		"hurricanex_tasks_active",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(bodyStr, m) {
			t.Errorf("metrics output missing %q", m)
		}
	}
}

func TestRecordNodeMetrics(t *testing.T) {
	c := NewCollector()

	c.RecordNodeMetrics("node-1", 500, 100, 2000, 1048576, 524288, 5, 150.0)

	// Verify via handler output
	handler := c.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	bodyStr := string(body)

	checks := []string{
		`hurricanex_connections_active{node_id="node-1"} 500`,
		`hurricanex_cps{node_id="node-1"} 2000`,
		`hurricanex_nodes_active 0`,
	}

	for _, check := range checks {
		if !strings.Contains(bodyStr, check) {
			t.Errorf("metrics output missing %q", check)
		}
	}
}

func TestRecordNodeMetricsMultipleNodes(t *testing.T) {
	c := NewCollector()

	c.RecordNodeMetrics("node-1", 100, 50, 1000, 0, 0, 0, 0)
	c.RecordNodeMetrics("node-2", 200, 80, 2000, 0, 0, 0, 0)
	c.NodesActive.Set(2)

	handler := c.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, `hurricanex_connections_active{node_id="node-1"} 100`) {
		t.Error("missing node-1 connections_active")
	}
	if !strings.Contains(bodyStr, `hurricanex_connections_active{node_id="node-2"} 200`) {
		t.Error("missing node-2 connections_active")
	}
	if !strings.Contains(bodyStr, `hurricanex_nodes_active 2`) {
		t.Error("missing nodes_active = 2")
	}
}

func TestHealthzEndpoint(t *testing.T) {
	c := NewCollector()

	mux := http.NewServeMux()
	mux.Handle("/metrics", c.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("healthz body = %q, want %q", string(body), "ok")
	}
}

func TestRecordZeroLatency(t *testing.T) {
	c := NewCollector()

	// Zero latency should not be observed
	c.RecordNodeMetrics("node-1", 0, 0, 0, 0, 0, 0, 0)

	handler := c.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	bodyStr := string(body)

	// latency_us_count should be 0 (no observations)
	if strings.Contains(bodyStr, `hurricanex_latency_us_count{node_id="node-1"} 1`) {
		t.Error("latency should not be observed for 0 value")
	}
}
