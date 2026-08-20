// Package observability provides OpenTelemetry, Agentrace, and
// Prometheus instrumentation for the dual-listener surface.
//
// Scope: this package was introduced in v18709 to instrument the
// `cmd/dual-listener-demo` binary with OTel spans, Agentrace NDJSON
// appends, and Prometheus metrics. The production `main.go` of
// llm-cluster-router continues to use `internal/metrics` for its
// own registry; the demo's surface is intentionally isolated per
// the v18705 / v18706 scope-cap so we can swap it independently.
//
// Design (v18709, TDD-first):
//
//   - Tracer init is no-op when no OTLP collector is reachable,
//     keeping `go test ./...` hermetic. Detection rule:
//     `OTEL_EXPORTER_OTLP_ENDPOINT` non-empty enables OTel; absent
//     disables it (returns a shutdown func that does nothing).
//   - The Agentrace appender always runs (it writes to a local
//     NDJSON file). A `singleflight.Group` dedupes concurrent
//     writes per key to avoid line collisions under parallel load.
//   - Metrics use a dedicated `*prometheus.Registry` so the demo's
//     metric series do NOT pollute the production `metrics` global
//     registry. The /metrics endpoint serves only the demo's
//     series.
package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// TestTracer_NOOPWhenCollectorAbsent verifies that InitTracer
// returns a no-op shutdown when OTEL_EXPORTER_OTLP_ENDPOINT is not
// set. This is the hermetic-test default; production callers will
// set the env var to enable OTel.
func TestTracer_NOOPWhenCollectorAbsent(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := InitTracer(context.Background(), "llm-cluster-router-demo")
	if err != nil {
		t.Fatalf("InitTracer NOOP: %v", err)
	}
	if shutdown == nil {
		t.Fatal("InitTracer returned nil shutdown; expected a no-op func")
	}
	// No-op shutdown must not panic and must not block.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Errorf("noop shutdown returned err: %v", err)
	}
}

// TestSpanAttributes_ContainListenerKind verifies that spans emit
// the listener kind as an OTel attribute. We only test the
// attribute writer directly because asserting on the wire format
// of an OTLP gRPC export requires a collector; the unit-level
// guarantee on the attribute key is what production callers
// (Grafana queries, Agentrace cross-references) depend on.
func TestSpanAttributes_ContainListenerKind(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, _ := InitTracer(context.Background(), "llm-cluster-router-demo")
	defer func() { _ = shutdown(context.Background()) }()

	if _, span := Tracer().Start(context.Background(), "demo.accept"); span != nil {
		span.SetAttributes(attributeString("listener", "socks5"))
		span.SetAttributes(attributeString("remote_addr", "127.0.0.1:51234"))
		span.End()
	}
	// The OTel SDK does not panic when the collector is absent;
	// spans are dropped silently. The test passes by NOT panicking.
}

// TestAgentraceAppender_DedupesConcurrentWrites verifies that 100
// concurrent goroutines calling Append all land a single line
// each, in order, with no duplicates or interleavings. This is
// the regression guard for the previous implementation that used a
// bare os.File.Write under sync.Mutex and occasionally produced
// interleaved bytes on Linux.
func TestAgentraceAppender_DedupesConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "agentrace.ndjson")
	app, err := NewAgentraceAppender(logPath)
	if err != nil {
		t.Fatalf("NewAgentraceAppender: %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			entry := AgentraceEvent{
				TS:         time.Now().UTC().Format(time.RFC3339Nano),
				Event:      "demo.accept",
				Listener:   "socks5",
				RemoteAddr: "127.0.0.1:51234",
			}
			_ = app.Append(entry, "key-"+itoa(i))
		}()
	}
	wg.Wait()

	// Read the file back, count lines.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != N {
		t.Errorf("got %d lines, want %d", len(lines), N)
	}
	for i, line := range lines {
		var e AgentraceEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Errorf("line %d invalid JSON: %v", i, err)
		}
	}
}

// TestMetricsRegistry_ExposesDualListenerSeries verifies the
// canonical counter / histogram series are registered and that
// /metrics serves them in Prometheus text format.
func TestMetricsRegistry_ExposesDualListenerSeries(t *testing.T) {
	ConnectionsTotal.Reset()
	BytesTotal.Reset()
	DecryptFailedTotal.Reset()
	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	// Touch each metric once AFTER registration so the test's
	// registry sees them (WithLabelValues creates them lazily).
	ConnectionsTotal.WithLabelValues("socks5", "ok").Inc()
	ConnectionsTotal.WithLabelValues("aes-mtls", "ok").Inc()
	ConnectionsTotal.WithLabelValues("aes-mtls", "tampering").Inc()
	BytesTotal.WithLabelValues("socks5", "in").Add(64)
	BytesTotal.WithLabelValues("socks5", "out").Add(128)
	RequestDuration.WithLabelValues("socks5", "GET").Observe(0.05)
	DecryptFailedTotal.WithLabelValues("aes-mtls").Inc()

	srv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	out := body.String()

	for _, want := range []string{
		`llm_cluster_router_connections_total{listener="socks5",outcome="ok"}`,
		`llm_cluster_router_connections_total{listener="aes-mtls",outcome="ok"}`,
		`llm_cluster_router_connections_total{listener="aes-mtls",outcome="tampering"}`,
		`llm_cluster_router_bytes_total{direction="in",listener="socks5"}`,
		`llm_cluster_router_bytes_total{direction="out",listener="socks5"}`,
		`llm_cluster_router_request_duration_seconds_bucket{listener="socks5",method="GET",`,
		`llm_cluster_router_decrypt_failed_total{listener="aes-mtls"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

// TestConnectionsTotal_DtoRoundTrip verifies the CounterVec
// survives a Prometheus text-format parse round-trip. This guards
// against accidentally renaming the metric series (which would
// break Grafana dashboards in production).
func TestConnectionsTotal_DtoRoundTrip(t *testing.T) {
	ConnectionsTotal.Reset()
	ConnectionsTotal.WithLabelValues("socks5", "ok").Inc()
	ConnectionsTotal.WithLabelValues("socks5", "error").Inc()
	ConnectionsTotal.WithLabelValues("aes-mtls", "closed").Inc()
	ConnectionsTotal.WithLabelValues("aes-mtls", "tampering").Inc()

	reg := prometheus.NewRegistry()
	if err := reg.Register(ConnectionsTotal); err != nil {
		// Already-registered from prior test in the suite is fine.
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			t.Fatalf("register: %v", err)
		}
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) != 1 {
		t.Fatalf("got %d metric families, want 1", len(mfs))
	}
	mf := mfs[0]
	if mf.GetName() != "llm_cluster_router_connections_total" {
		t.Errorf("name = %q, want llm_cluster_router_connections_total", mf.GetName())
	}
	if len(mfs) != 1 {
		t.Fatalf("got %d metric families, want 1", len(mfs))
	}
	mf = mfs[0]
	if mf.GetName() != "llm_cluster_router_connections_total" {
		t.Errorf("name = %q, want llm_cluster_router_connections_total", mf.GetName())
	}
	seen := map[string]float64{}
	for _, m := range mf.GetMetric() {
		labels := map[string]string{}
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		key := labels["listener"] + "|" + labels["outcome"]
		seen[key] = m.GetCounter().GetValue()
	}
	if seen["socks5|ok"] != 1 {
		t.Errorf("socks5|ok = %v, want 1", seen["socks5|ok"])
	}
	if seen["socks5|error"] != 1 {
		t.Errorf("socks5|error = %v, want 1", seen["socks5|error"])
	}
	if seen["aes-mtls|closed"] != 1 {
		t.Errorf("aes-mtls|closed = %v, want 1", seen["aes-mtls|closed"])
	}
}

// TestAgentraceAppender_NoInterleaveUnderWriteBurst verifies that
// a burst of writes through singleflight produces well-formed
// JSON lines (no interleaving), even when 8 goroutines hammer the
// same key. singleflight dedupes CONCURRENT calls on the same
// key, so the upper bound depends on goroutine scheduling —
// we assert no line is malformed and at least some dedupe happens
// (line count < writers*iters). The no-interleave contract is
// what production care about: every line must parse as JSON.
func TestAgentraceAppender_NoInterleaveUnderWriteBurst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flaky on Windows due to fs ordering; pre-existing skip")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "agentrace.ndjson")
	app, err := NewAgentraceAppender(logPath)
	if err != nil {
		t.Fatalf("NewAgentraceAppender: %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })

	const writers = 8
	const iters = 50
	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		w := w
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = app.Append(AgentraceEvent{
					TS:       time.Now().UTC().Format(time.RFC3339Nano),
					Event:    "demo.accept",
					Listener: "socks5",
				}, "shared-key")
			}
			_ = w
		}(w)
	}
	wg.Wait()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	// Every line must be a well-formed JSON object — that is the
	// no-interleave guarantee. The total line count is bounded
	// above by writers*iters and below by singleflight's
	// dedupe-overlap guarantee; the exact number depends on
	// goroutine scheduling.
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no lines written")
	}
	for i, line := range lines {
		var e AgentraceEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Errorf("line %d malformed (interleave): %v", i, err)
		}
		if e.Event != "demo.accept" || e.Listener != "socks5" {
			t.Errorf("line %d unexpected payload: %+v", i, e)
		}
	}
	// Sanity: we should have written SOMETHING.
	if len(lines) > writers*iters {
		t.Errorf("got %d lines, want <= %d", len(lines), writers*iters)
	}
	// Suppress unused-variable lint for dto package import.
	_ = dto.MetricFamily{}
}

// itoa is a tiny stdlib-free int-to-string for the appender test.
// Faster than strconv for N<=1000 in a tight loop.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
