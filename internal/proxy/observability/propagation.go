// Package observability / propagation.go
//
// W3C trace-context propagator wrapper so the import is contained
// to a single file. Production should set this once at startup;
// tests get the global default (noop).
package observability

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// propagationType is a tiny type-alias for the OTel Propagators
// type so other files in the package don't need to import the OTel
// propagation package directly.
type propagationType = propagation.TextMapPropagator

// otelPropagator is the package-level propagator instance. We
// initialise it once at package init so a fresh ConfigMap in
// production does not need to know about OTel internals.
var otelPropagator = otel.GetTextMapPropagator()

// init installs the W3C trace-context + baggage propagator on
// first import. Tests that disable OTel via OTEL_EXPORTER_OTLP_ENDPOINT=""
// still call SetTextMapPropagator here, but this is harmless
// because no tracer is ever set.
func init() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
}
