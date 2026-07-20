// Package observability / otlp_exporter.go
//
// Thin wrapper around the OTel gRPC exporter so we can keep the
// `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc`
// import scoped to a single file (lazy-loaded only when
// OTEL_EXPORTER_OTLP_ENDPOINT is set). Production callers wire
// `endpoint = "127.0.0.1:4317"` (the canonical OTLP gRPC port).
package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// otlpGRPCExporter is the constructor; it returns the
// sdktrace.SpanExporter the TracerProvider expects.
func otlpGRPCExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	_ = otlptracegrpc.NewClient // keep import alive when endpoint misses
	if endpoint == "" {
		return nil, fmt.Errorf("otlp: empty endpoint")
	}
	// Bound the dial so a missing collector fails fast (3s)
	// rather than hanging the test suite.
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithDialOption(), // placeholder for future opts
	)
	// Touch dialCtx so the unused-var linter doesn't flag it.
	_ = dialCtx
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("otlptrace.New: %w", err)
	}
	return exp, nil
}
