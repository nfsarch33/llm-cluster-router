// Package observability is the v18709 instrumentation surface for
// the dual-listener-demo binary.
//
// See observability_test.go for the contract. The implementation
// here is intentionally minimal:
//
//   - Tracer init is no-op when OTEL_EXPORTER_OTLP_ENDPOINT is
//     empty, so `go test ./...` stays hermetic. Production callers
//     set the env var to enable OTel.
//   - The Agentrace appender uses golang.org/x/sync/singleflight to
//     dedupe writes per key under concurrent load. This is the
//     same pattern the v18706 fuzz harness used to dodge
//     EADDRINUSE under parallel port allocation; here it dodges
//     line-interleaving in NDJSON.
//   - Metrics are exported on a dedicated *prometheus.Registry
//     (not the default global one) so the demo's series do not
//     collide with the production router metrics.
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	xlsync "golang.org/x/sync/singleflight"
)

// AgentraceEvent is the NDJSON shape emitted by the Agentrace
// appender. Field names are short on purpose: OTel/Agentrace
// consumers typically stream this into DRL feature pipelines.
type AgentraceEvent struct {
	TS         string `json:"ts"`
	Event      string `json:"event"`
	Listener   string `json:"listener"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	BytesIn    int64  `json:"bytes_in,omitempty"`
	BytesOut   int64  `json:"bytes_out,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

// AgentraceAppender serialises AgentraceEvent to NDJSON, one
// event per line. Writes dedupe per key via singleflight, so
// concurrent Append(key, ...) calls collapse to a single physical
// file write per "inflight" key — preventing line interleaving
// on Linux without forcing callers to serialise.
type AgentraceAppender struct {
	f         *os.File
	enc       *json.Encoder
	mu        sync.Mutex // guards enc.Encode + f.Write ordering
	sf        xlsync.Group
	closeOnce sync.Once
}

// NewAgentraceAppender opens the NDJSON log for append. Callers
// must Close() in defer.
func NewAgentraceAppender(path string) (*AgentraceAppender, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open agentrace log: %w", err)
	}
	return &AgentraceAppender{
		f:   f,
		enc: json.NewEncoder(f),
	}, nil
}

// Append emits `event` with optional dedupe `key`. Concurrent
// callers passing the same key will share a single underlying
// file write per "inflight" round (last-write-wins for that key).
// Passing empty `key` disables dedupe and writes every event.
func (a *AgentraceAppender) Append(event AgentraceEvent, key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return fmt.Errorf("agentrace: appender closed")
	}
	v, err, _ := a.sf.Do(key, func() (any, error) {
		if err := a.enc.Encode(&event); err != nil {
			return nil, err
		}
		return nil, nil
	})
	_ = v
	return err
}

// Close flushes and closes the underlying file. Idempotent.
func (a *AgentraceAppender) Close() error {
	a.closeOnce.Do(func() {
		if a.f != nil {
			_ = a.f.Close()
			a.f = nil
		}
	})
	return nil
}

// --- Tracer / OTel surface ---

var (
	tracerOnce sync.Once
	tracerInst trace.Tracer
)

func Tracer() trace.Tracer {
	tracerOnce.Do(func() { tracerInst = otel.Tracer("llm-cluster-router-demo") })
	return tracerInst
}

// InitTracer configures the global OTel TracerProvider. If
// OTEL_EXPORTER_OTLP_ENDPOINT is empty (default in tests), this
// returns a no-op shutdown that does nothing — keeping unit tests
// hermetic and CI default behavior cheap.
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is set, this opens an OTLP gRPC
// exporter against that endpoint and returns a shutdown that
// flushes pending spans within the supplied context's deadline.
func InitTracer(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// Hermetic default. Touch Tracer() so the package-level
		// init registers; return a no-op shutdown.
		_ = Tracer()
		return func(context.Context) error { return nil }, nil
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}
	// Lazy import of otlptracegrpc to keep test build hermetic
	// when no endpoint is set.
	exp, err := newOTLPExporter(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(otelPropagator)
	tracerOnce = sync.Once{}
	tracerInst = otel.Tracer(serviceName)
	return tp.Shutdown, nil
}

// newOTLPExporter is a thin wrapper so we can keep the otlptracegrpc
// import in one place and not pull it in unless the endpoint is
// configured. Production wiring sets
// OTEL_EXPORTER_OTLP_ENDPOINT=127.0.0.1:4317.
func newOTLPExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	return otlpGRPCExporter(ctx, endpoint)
}

// attributeString returns the canonical attribute.KeyValue with
// the supplied key + string value. We export it as a helper so
// tests and the binary use identical attribute constructors.
func attributeString(key, value string) attribute.KeyValue {
	return attribute.String(key, value)
}

// --- Prometheus metrics ---

// ConnectionsTotal is the dual-listener connection counter,
// labelled by listener (socks5|aes-mtls) and outcome
// (ok|error|closed|tampering).
//
// The "tampering" outcome was added in v18710-4 to surface AES-GCM
// authentication failures from the AES/mTLS channel. Production
// monitoring should alert on `rate(...{outcome="tampering"}[5m]) > 0`
// because every increment represents an attacker (or a buggy client)
// probing or mutating the wire.
//
// The other outcomes (ok|error|closed) are unchanged from the v18706
// dual-listener demo and remain backward-compatible with existing
// dashboards.
var ConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "llm_cluster_router_connections_total",
	Help: "Total connections accepted by the dual-listener, partitioned by listener and outcome.",
}, []string{"listener", "outcome"})

// BytesTotal counts byte volume per direction (in|out) per
// listener. Useful for capacity planning.
var BytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "llm_cluster_router_bytes_total",
	Help: "Total bytes proxied by the dual-listener, partitioned by listener and direction.",
}, []string{"listener", "direction"})

// RequestDuration measures per-request latency. Buckets
// cover 5ms..5s which spans both loopback and tunnel hops.
var RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "llm_cluster_router_request_duration_seconds",
	Help:    "End-to-end request duration by listener and HTTP method.",
	Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
}, []string{"listener", "method"})

// DecryptFailedTotal counts AES-GCM authentication failures per
// listener. v18710-4 introduces this metric to support the
// Lightsail release readiness gate (ADR-083 C2/C7): any non-zero
// rate over a 1-minute window is an incident.
//
// The metric is partitioned by listener (socks5|aes-mtls) so the
// same Prometheus scrape target can show tampering on both
// channels. Today only the AES/mTLS channel increments this
// counter; the SOCKS5 listener is documented as "future" because
// SOCKS5 itself does not authenticate frames.
var DecryptFailedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "llm_cluster_router_decrypt_failed_total",
	Help: "AES-GCM authentication failures by listener. Non-zero rate indicates tampering or corrupted transport.",
}, []string{"listener"})

// HelixChannelConnectionsTotal is the additive v18712-1 alias for
// the AES/mTLS channel under the operator-facing name "HelixChannel".
// It points at the SAME counter family as ConnectionsTotal but with
// the listener label fixed to "helixchannel" so dashboards can show
// the brand name alongside the legacy "aes-mtls" line. The two
// counters are incremented in lock-step from the dual-listener
// ServeLoop; the alias is read-only.
//
// Why an alias and not a new metric? Operators asked for the
// HelixChannel name to appear in dashboards and runbook scripts
// without changing existing Grafana panels that key off
// listener="aes-mtls". Both labels are populated; queries that
// filter by listener="helixchannel" return the same wire traffic
// as listener="aes-mtls".
var HelixChannelConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "llm_cluster_router_helixchannel_connections_total",
	Help: "HelixChannel (AES-256-GCM application-layer encrypted) connections by direction. Additive v18712-1 alias for llm_cluster_router_connections_total{listener=\"helixchannel\"}.",
}, []string{"direction"})

// HelixChannelBytesTotal mirrors BytesTotal under the HelixChannel
// brand. Read-only alias; both labels increment from the same
// ServeLoop path.
var HelixChannelBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "llm_cluster_router_helixchannel_bytes_total",
	Help: "HelixChannel bytes proxied, partitioned by direction. Additive v18712-1 alias for llm_cluster_router_bytes_total{listener=\"helixchannel\"}.",
}, []string{"direction"})

// HelixChannelSessionTotal counts HelixChannel sessions by terminal
// outcome. Added in v18714-3 to give operators a per-session view of
// the channel's health, distinct from the per-connection view in
// HelixChannelConnectionsTotal.
//
// Why a new counter when HelixChannelConnectionsTotal already exists?
// The connection-level metric tallies TCP accepts; the session-level
// metric tallies logical HelixChannel sessions, where one session
// may span many connections (HTTP keep-alive) and where the same
// connection may carry multiple logically independent sessions after
// reconnect. Splitting the two lets SREs alert on
//
//   - rate(helixchannel_session_total{outcome="success"}[5m])    — healthy traffic
//   - rate(helixchannel_session_total{outcome="failure"}[5m])     — application errors
//   - rate(helixchannel_session_total{outcome="tampering"}[5m])   — wire-modification attack
//   - rate(helixchannel_session_total{outcome="decrypt_error"}[5m]) — key/IV mismatch
//   - rate(helixchannel_session_total{outcome="closed"}[5m])      — graceful teardown
//
// The canonical outcomes are not enforced as an enum; callers may
// introduce additional values (e.g. "rate_limited", "auth_failed")
// without re-cutting this metric, but the five above are wired into
// the v18714-3 dashboards and runbooks and MUST NOT be renamed
// without a coordinated dashboard PR.
//
// Co-emitted with the OTel span attribute
// "helixchannel.session.outcome" (see ObserveHelixChannelSession).
var HelixChannelSessionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "llm_cluster_router_helixchannel_session_total",
	Help: "HelixChannel sessions by terminal outcome (success|failure|tampering|decrypt_error|closed|...). Use this for SLO dashboards; use helixchannel_connections_total for connection-level traffic.",
}, []string{"outcome"})

// ObserveHelixChannelSession increments the session counter and, if
// a span is active in ctx, records the outcome as an OTel span event
// plus an attribute so traces and metrics agree. The function is the
// single chokepoint for session-level outcome emission; callers MUST
// use this rather than touching HelixChannelSessionTotal directly
// when a context is available so the OTel side stays in sync.
//
// ctx may be context.Background() in which case only the metric is
// updated.
func ObserveHelixChannelSession(ctx context.Context, outcome string) {
	HelixChannelSessionTotal.WithLabelValues(outcome).Inc()
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(attribute.String("helixchannel.session.outcome", outcome))
		span.AddEvent("helixchannel.session.outcome", trace.WithAttributes(
			attribute.String("outcome", outcome),
		))
	}
}

// RegisterMetrics installs the dual-listener metrics on the
// provided (production-isolated) registry. Call once at startup.
func RegisterMetrics(reg *prometheus.Registry) error {
	for _, c := range []prometheus.Collector{ConnectionsTotal, BytesTotal, RequestDuration, DecryptFailedTotal, HelixChannelConnectionsTotal, HelixChannelBytesTotal, HelixChannelSessionTotal} {
		if err := reg.Register(c); err != nil {
			// Already-registered (e.g. by a previous test) is fine; only fail on unexpected errors.
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return fmt.Errorf("register metric: %w", err)
			}
		}
	}
	return nil
}

// Reset clears all demo-scoped metrics. Test-only helper; never
// call from production.
func Reset() {
	ConnectionsTotal.Reset()
	BytesTotal.Reset()
	RequestDuration.Reset()
	DecryptFailedTotal.Reset()
	HelixChannelConnectionsTotal.Reset()
	HelixChannelBytesTotal.Reset()
	HelixChannelSessionTotal.Reset()
}

// silentIOReset discards any error from io.Closer; kept here so
// future code that needs to silence a Close() can import one
// function rather than copying the pattern.
var _ io.Closer = (*AgentraceAppender)(nil)

// propagationTraceContext is provided in propagation.go so the
// propagator wiring stays in one place. See propagation.go for
// the package-level otelPropagator instance and init().
