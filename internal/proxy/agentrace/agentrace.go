// Package agentrace is the v18729-1 dual-publish surface for the
// llm-cluster-router observability stack.
//
// It composes the existing AgentraceAppender (NDJSON file log from
// internal/proxy/observability/observability.go) with an OpenTelemetry
// span exporter (gRPC or HTTP, selected at construction) so every
// dual-publish call lands in both:
//
//  1. The NDJSON agentrace log (the durable, append-only audit log
//     used by DRL feature pipelines).
//  2. An OTel span emitted to the configured collector (the
//     metrics + traces source for Grafana dashboards).
//
// The Publisher.Publish method is the single chokepoint; callers
// MUST use it rather than touching the underlying appender or
// OTel tracer directly so the two sides stay in sync.
//
// The package is hermetic when no endpoint is configured; the
// constructor returns a no-op publisher that records nothing and
// never blocks. This matches the v18709 contract on
// observability.InitTracer (no-op when OTEL_EXPORTER_OTLP_ENDPOINT
// is empty).
package agentrace

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/nfsarch33/llm-cluster-router/internal/proxy/observability"
)

// Transport selects the OTel wire protocol. gRPC is the production
// default (port 4317); HTTP is the operator-preferred path when the
// collector is fronted by nginx + TLS termination on port 4318.
type Transport int

const (
	// TransportGRPC routes spans through OTLP/gRPC (port 4317).
	TransportGRPC Transport = iota
	// TransportHTTP routes spans through OTLP/HTTP+protobuf (port 4318).
	TransportHTTP
)

// Config is the constructor input for NewPublisher. Empty Endpoint
// is allowed; the resulting publisher is hermetic (no-op) so unit
// tests and CI do not require a running collector.
type Config struct {
	// ServiceName populates the OTel resource's service.name
	// attribute and the Agentrace log "service" field.
	ServiceName string
	// Endpoint is the OTLP collector endpoint (host:port). Empty
	// disables the OTel path entirely.
	Endpoint string
	// Transport selects gRPC (default) or HTTP.
	Transport Transport
	// NDJSONPath is the AgentraceAppender log path. Empty disables
	// the NDJSON path; useful for tests that only exercise the OTel
	// side.
	NDJSONPath string
}

// Publisher is the dual-publish surface. Concurrent calls are
// safe; the underlying observability.AgentraceAppender handles
// line-interleaving via singleflight, and the OTel SDK is
// goroutine-safe by contract.
type Publisher struct {
	cfg Config

	mu       sync.Mutex // guards appender + tracer access during Shutdown
	appender *observability.AgentraceAppender
	tracer   trace.Tracer
	tp       *sdktrace.TracerProvider
	shutdown func(context.Context) error
	started  bool
	closed   bool
}

// NewPublisher constructs a Publisher. The OTel TracerProvider is
// only initialised when cfg.Endpoint is non-empty; the
// AgentraceAppender is only opened when cfg.NDJSONPath is non-empty.
// The combination (endpoint empty, ndjson empty) is valid and
// produces a fully hermetic publisher (useful for unit tests).
func NewPublisher(ctx context.Context, cfg Config) (*Publisher, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "llm-cluster-router"
	}
	p := &Publisher{cfg: cfg}

	if cfg.NDJSONPath != "" {
		app, err := observability.NewAgentraceAppender(cfg.NDJSONPath)
		if err != nil {
			return nil, fmt.Errorf("agentrace: open NDJSON log: %w", err)
		}
		p.appender = app
	}

	if cfg.Endpoint != "" {
		tp, shutdown, err := newTracerProvider(ctx, cfg)
		if err != nil {
			// Best-effort: close the appender before propagating.
			if p.appender != nil {
				_ = p.appender.Close()
			}
			return nil, fmt.Errorf("agentrace: init tracer: %w", err)
		}
		p.tp = tp
		p.shutdown = shutdown
		p.tracer = tp.Tracer(cfg.ServiceName)
		p.started = true
	} else {
		// Hermetic: use the no-op global tracer. The Agentrace log
		// (if configured) still records events.
		p.tracer = observability.Tracer()
	}

	return p, nil
}

// newTracerProvider builds the OTel TracerProvider per the
// selected transport. The shutdown callback is returned alongside
// so the caller can flush pending spans on close.
func newTracerProvider(ctx context.Context, cfg Config) (*sdktrace.TracerProvider, func(context.Context) error, error) {
	var (
		exp sdktrace.SpanExporter
		err error
	)
	switch cfg.Transport {
	case TransportHTTP:
		exp, err = otlpHTTPExporter(ctx, cfg.Endpoint)
	default:
		// Delegate gRPC wiring to the observability package so we
		// don't double-import the gRPC client here.
		exp, err = observability.NewOTLPGRPCExporter(ctx, cfg.Endpoint)
	}
	if err != nil {
		return nil, nil, err
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(cfg.ServiceName)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("otel resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	return tp, tp.Shutdown, nil
}

// Publish records ev into both the NDJSON log and the OTel span
// stream. The OTel side creates a span keyed by the supplied
// spanName with the AgentraceEvent fields as attributes; the NDJSON
// side appends one event per call. Either side may be a no-op
// depending on cfg.
//
// The returned error is the first non-nil error from either side;
// callers MAY log but MUST NOT retry, because the NDJSON path is
// append-only and a re-publish would corrupt the stream.
func (p *Publisher) Publish(ctx context.Context, spanName string, ev observability.AgentraceEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return fmt.Errorf("agentrace: publisher closed")
	}
	var firstErr error
	if p.appender != nil {
		if err := p.appender.Append(ev, ev.Listener); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("ndjson: %w", err)
		}
	}
	if p.started && p.tracer != nil {
		_, span := p.tracer.Start(ctx, spanName)
		span.SetAttributes(
			attribute.String("agentrace.listener", ev.Listener),
			attribute.String("agentrace.event", ev.Event),
			attribute.String("agentrace.remote_addr", ev.RemoteAddr),
			attribute.Int64("agentrace.bytes_in", ev.BytesIn),
			attribute.Int64("agentrace.bytes_out", ev.BytesOut),
			attribute.Int64("agentrace.duration_ms", ev.DurationMS),
		)
		span.End()
	}
	return firstErr
}

// Close flushes pending spans and closes the NDJSON log. Idempotent.
func (p *Publisher) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var firstErr error
	if p.shutdown != nil {
		if err := p.shutdown(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("otel shutdown: %w", err)
		}
	}
	if p.appender != nil {
		if err := p.appender.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("ndjson close: %w", err)
		}
	}
	return firstErr
}

// Tracer exposes the underlying OTel tracer for callers that need
// to wrap spans around their own work and emit Publish within them.
// Returns the no-op global tracer when the OTel side is disabled.
func (p *Publisher) Tracer() trace.Tracer {
	return p.tracer
}
