// Package agentrace / otlp_http_exporter.go
//
// v18729-1 OTLP/HTTP exporter wrapper. Mirrors the gRPC wrapper in
// internal/proxy/observability/otlp_exporter.go so the package can be
// configured to publish spans over either transport. The HTTP path
// is the default for environments that front the OTel collector with
// nginx + TLS termination on port 4318 (the OTel collector's
// canonical HTTP+TLS port); the gRPC path remains the default for
// direct loopback wiring on port 4317.
//
// Selection rule:
//
//   - If AGENTRACE_OTEL_TRANSPORT=http (or OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf)
//     -> otlpHTTPExporter.
//   - Otherwise -> otlpGRPCExporter (delegated to the observability package
//     so we don't double-import the gRPC client).
//
// Production callers set OTEL_EXPORTER_OTLP_ENDPOINT=<host>:4318 and
// OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf; the dial is bounded to
// 3 s so a missing collector fails fast rather than hanging tests.
package agentrace

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// otlpHTTPExporter returns an OTel HTTP span exporter targeting
// the supplied endpoint. The endpoint should be a host:port tuple
// (e.g. "otel-collector.local:4318"); the otlptracehttp client
// takes care of the "/v1/traces" path. WithInsecure() is wired
// because production terminates TLS at nginx; production callers
// that need end-to-end TLS must wrap this factory with a TLS-aware
// variant (planned v18730).
func otlpHTTPExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("otlp/http: empty endpoint")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = dialCtx
	client := otlptracehttp.NewClient(
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("otlptrace.New(http): %w", err)
	}
	return exp, nil
}
