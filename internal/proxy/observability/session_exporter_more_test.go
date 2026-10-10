// Copyright (c) 2026 nfsarch33. Test-only; do not export.
//
// session_exporter_more_test.go (v18760) covers the session-outcome
// chokepoint, the registry install/reset lifecycle, and the OTLP
// exporter construction path that only runs when a collector endpoint
// is configured.
package observability

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestObserveHelixChannelSession_IncrementsMetricWithoutSpan(t *testing.T) {
	Reset()
	before := testutil.ToFloat64(HelixChannelSessionTotal.WithLabelValues("success"))
	ObserveHelixChannelSession(context.Background(), "success")
	after := testutil.ToFloat64(HelixChannelSessionTotal.WithLabelValues("success"))
	if after-before != 1 {
		t.Fatalf("session counter delta = %v, want 1", after-before)
	}
}

func TestObserveHelixChannelSession_RecordsSpanOutcome(t *testing.T) {
	Reset()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("v18760-test")
	ctx, span := tracer.Start(context.Background(), "session")
	ObserveHelixChannelSession(ctx, "tampering")
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("exported %d spans, want 1", len(spans))
	}
	foundAttr := false
	for _, a := range spans[0].Attributes {
		if string(a.Key) == "helixchannel.session.outcome" && a.Value.AsString() == "tampering" {
			foundAttr = true
		}
	}
	if !foundAttr {
		t.Fatalf("span attributes %v missing helixchannel.session.outcome=tampering", spans[0].Attributes)
	}
	foundEvent := false
	for _, e := range spans[0].Events {
		if e.Name == "helixchannel.session.outcome" {
			foundEvent = true
		}
	}
	if !foundEvent {
		t.Fatalf("span events %v missing helixchannel.session.outcome", spans[0].Events)
	}
	if got := testutil.ToFloat64(HelixChannelSessionTotal.WithLabelValues("tampering")); got != 1 {
		t.Fatalf("tampering counter = %v, want 1 (metric and trace must agree)", got)
	}
}

func TestReset_ClearsAllFamilies(t *testing.T) {
	ConnectionsTotal.WithLabelValues("socks5", "ok").Inc()
	BytesTotal.WithLabelValues("socks5", "in").Add(9)
	RequestDuration.WithLabelValues("socks5", "GET").Observe(0.1)
	DecryptFailedTotal.WithLabelValues("aes-mtls").Inc()
	HelixChannelConnectionsTotal.WithLabelValues("in").Inc()
	HelixChannelBytesTotal.WithLabelValues("out").Add(3)
	HelixChannelSessionTotal.WithLabelValues("closed").Inc()

	Reset()

	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if len(mf.GetMetric()) != 0 {
			t.Fatalf("family %s still has %d series after Reset()", mf.GetName(), len(mf.GetMetric()))
		}
	}
}

func TestRegisterMetrics_SecondCallIsIdempotent(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("first RegisterMetrics: %v", err)
	}
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("second RegisterMetrics: %v (AlreadyRegistered must be tolerated)", err)
	}
}

func TestRegisterMetrics_ConflictingCollectorSurfacesError(t *testing.T) {
	reg := prometheus.NewRegistry()
	// Same fully-qualified name, different label schema → inconsistent
	// duplicate, which must NOT be swallowed.
	clash := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "llm_cluster_router_connections_total",
		Help: "clashing single counter",
	})
	if err := reg.Register(clash); err != nil {
		t.Fatalf("pre-register clash: %v", err)
	}
	err := RegisterMetrics(reg)
	if err == nil || !strings.Contains(err.Error(), "register metric") {
		t.Fatalf("RegisterMetrics with clashing collector = %v, want register-metric error", err)
	}
}

func TestInitTracer_HermeticWhenNoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := InitTracer(context.Background(), "v18760-hermetic")
	if err != nil {
		t.Fatalf("InitTracer = %v, want nil", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("noop shutdown = %v, want nil", err)
	}
}

func TestInitTracer_WithEndpointBuildsExporter(t *testing.T) {
	// otlptracegrpc dials lazily, so construction must succeed even though
	// nothing listens at the endpoint; shutdown then flushes into the void
	// under a short deadline. This is exactly the production construction
	// path (newOTLPExporter → otlpGRPCExporter).
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "127.0.0.1:1")
	shutdown, err := InitTracer(context.Background(), "v18760-exporter")
	if err != nil {
		t.Fatalf("InitTracer with endpoint = %v, want nil (lazy gRPC dial)", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = shutdown(ctx) // error acceptable: no collector; must return promptly
	if Tracer() == nil {
		t.Fatal("Tracer() nil after InitTracer")
	}
}

func TestOTLPGRPCExporter_EmptyEndpointRejected(t *testing.T) {
	if _, err := otlpGRPCExporter(context.Background(), ""); err == nil {
		t.Fatal("otlpGRPCExporter(\"\") = nil error, want rejection")
	}
}

func TestAttributeStringHelper(t *testing.T) {
	kv := attributeString("k", "v")
	if string(kv.Key) != "k" || kv.Value.AsString() != "v" {
		t.Fatalf("attributeString = %v", kv)
	}
}
