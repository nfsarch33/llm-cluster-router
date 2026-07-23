// Package observability / v18729_2_metrics_smoke_test.go
//
// v18729-2 smoke test: spin up a production-isolated registry,
// observe a sample, serve it via promhttp.Handler, and assert the
// scraped text contains the new histogram line. This is what an
// operator running `curl :8787/metrics` will see.
package observability

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TestMetricsEndpoint_ExposesRequestDurationByModel verifies the
// new histogram appears on the production /metrics scrape path.
func TestMetricsEndpoint_ExposesRequestDurationByModel(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	ObserveRequestDurationByModel("aes-mtls", "MiniMax-M3", 0.123)
	ObserveRequestDurationByModel("socks5", "qwen3.7-plus", 0.456)
	ObserveRequestDurationByModel("tls-edge", "MiniMax-M3", 0.789)

	srv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)
	want := []string{
		`llm_cluster_router_request_duration_by_model_seconds_bucket{listener="aes-mtls",model="MiniMax-M3"`,
		`llm_cluster_router_request_duration_by_model_seconds_bucket{listener="socks5",model="qwen3.7-plus"`,
		`llm_cluster_router_request_duration_by_model_seconds_bucket{listener="tls-edge",model="MiniMax-M3"`,
	}
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("/metrics missing %s", w)
		}
	}
}
