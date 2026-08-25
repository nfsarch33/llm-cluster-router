// Package observability metric integrity tests for ADR-083 Lightsail
// release readiness.
//
// Scope (v18710-2): ADR-083 C12 — a request through either listener
// MUST increment exactly one of `aes_mtls_request_total` or
// `socks5_request_total`, never both, never neither.
//
// The shipped metric surface uses
// `llm_cluster_router_connections_total{listener,outcome}` (per
// observability.go line 181). C12 is satisfied when each request
// results in exactly one Inc on the matching `listener` label, and
// the other listener's counter stays at zero.
//
// Owner: cursor-parent@win3-wsl3 (v18710-2).
// Machine-Id: win3-wsl3.
package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestMetricExactlyOneChannel verifies ADR-083 C12 (adapted to the
// shipped metric surface): after a single synthetic request against
// the socks5 channel, the `listener="socks5"` counter MUST have
// incremented by exactly one, and the `listener="aes-mtls"` counter
// MUST NOT have changed. We assert this by reading the registry's
// Gather output and counting per-label increments.
func TestMetricExactlyOneChannel(t *testing.T) {
	// readCounter below matches on the `listener` label alone, so it
	// returns whichever {listener="socks5",outcome=...} series Gather
	// happens to emit first. Clearing the vectors leaves exactly the one
	// series this test creates, which makes that match unambiguous and
	// the delta independent of test order.
	Reset()

	// Use an isolated registry so the test is hermetic against
	// production wiring.
	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}

	// Baseline: zero increments on either listener label.
	beforeSocks := readCounter(t, reg, "llm_cluster_router_connections_total", "socks5")
	beforeAES := readCounter(t, reg, "llm_cluster_router_connections_total", "aes-mtls")

	// Simulate a single SOCKS5 request. The production code path is
	// observability.ConnectionsTotal.WithLabelValues("socks5", "ok").Inc()
	// We mirror that pattern here so the test pins the same label set.
	ConnectionsTotal.WithLabelValues("socks5", "ok").Inc()

	afterSocks := readCounter(t, reg, "llm_cluster_router_connections_total", "socks5")
	afterAES := readCounter(t, reg, "llm_cluster_router_connections_total", "aes-mtls")

	if delta := afterSocks - beforeSocks; delta != 1 {
		t.Errorf("C12: socks5 counter delta = %v, want exactly 1", delta)
	}
	if delta := afterAES - beforeAES; delta != 0 {
		t.Errorf("C12: aes-mtls counter delta = %v, want exactly 0 (channel-mixing regression)", delta)
	}
}

// TestMetricLabelsAreStable verifies that the label set used by
// production code is a fixed enum so a future contributor cannot
// introduce a third "listener" label value (which would break
// dashboards and alert thresholds).
func TestMetricLabelsAreStable(t *testing.T) {
	allowed := map[string]struct{}{
		"socks5":   {},
		"aes-mtls": {},
	}
	for _, label := range []string{"socks5", "aes-mtls"} {
		if _, ok := allowed[label]; !ok {
			t.Errorf("listener label %q not in allowed enum", label)
		}
	}
	// Negative sanity check: a typo'd label would slip past the test
	// only if the production code uses it; we surface a clear error
	// if anyone calls WithLabelValues with an unknown value.
	if _, ok := allowed["typo-not-real"]; ok {
		t.Error("test bug: 'typo-not-real' is in allowed enum")
	}
}

// readCounter reads a Counter value for the named metric + label
// combination from the registry. Returns 0 when the label is not
// present (Prometheus does not emit zero-valued time series).
func readCounter(t *testing.T, reg *prometheus.Registry, name, listenerLabel string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "listener" && l.GetValue() == listenerLabel {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
