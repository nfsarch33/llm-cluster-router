package observability

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestHelixChannelSessionTotal_RegisterAndIncrement asserts the
// v18714-3 HelixChannel session counter is registered on the
// production-isolated Prometheus registry and increments per outcome
// label (success|failure|tampering|decrypt_error|closed).
//
// This is the RED-phase test the v18714-3 plan calls out as the
// acceptance gate for "helixchannel_session_total{outcome} metric
// + dashboards".
func TestHelixChannelSessionTotal_RegisterAndIncrement(t *testing.T) {
	// The counter vectors are package-level singletons, so a fresh
	// prometheus.NewRegistry() still gathers whatever an earlier test in
	// this package already incremented. This test asserts absolute values,
	// so it must start from a known zero or its answer depends on the
	// order -shuffle=on happens to pick.
	Reset()

	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}

	// Each outcome should be a valid label value. We do NOT validate
	// the closed set of outcomes (callers can extend it) but we DO
	// assert the metric family name and that all five canonical
	// outcomes increment without error.
	HelixChannelSessionTotal.WithLabelValues("success").Inc()
	HelixChannelSessionTotal.WithLabelValues("success").Inc()
	HelixChannelSessionTotal.WithLabelValues("failure").Inc()
	HelixChannelSessionTotal.WithLabelValues("tampering").Inc()
	HelixChannelSessionTotal.WithLabelValues("decrypt_error").Inc()
	HelixChannelSessionTotal.WithLabelValues("closed").Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		got[mf.GetName()] = mf
	}

	const wantName = "llm_cluster_router_helixchannel_session_total"
	mf, ok := got[wantName]
	if !ok {
		t.Fatalf("missing metric %s; got %v", wantName, keys(got))
	}
	if mf.GetType() != dto.MetricType_COUNTER {
		t.Errorf("metric %s: want COUNTER, got %s", wantName, mf.GetType())
	}

	// Verify the success label has count == 2, all others == 1.
	counts := map[string]float64{}
	for _, m := range mf.GetMetric() {
		for _, lbl := range m.GetLabel() {
			if lbl.GetName() == "outcome" {
				counts[lbl.GetValue()] = m.GetCounter().GetValue()
			}
		}
	}
	if counts["success"] != 2 {
		t.Errorf("outcome=success: want 2, got %v", counts["success"])
	}
	for _, oc := range []string{"failure", "tampering", "decrypt_error", "closed"} {
		if counts[oc] != 1 {
			t.Errorf("outcome=%s: want 1, got %v", oc, counts[oc])
		}
	}
}

// TestHelixChannelSessionTotal_HelpText confirms the metric's
// help string mentions the canonical label name so Grafana panel
// auto-discovery works without manual editing.
func TestHelixChannelSessionTotal_HelpText(t *testing.T) {
	// Prometheus omits a metric family with no child series from Gather()
	// entirely, so this test has to create the series it then looks for
	// instead of inheriting one from whichever test ran before it.
	Reset()
	HelixChannelSessionTotal.WithLabelValues("success").Inc()

	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if strings.Contains(mf.GetName(), "helixchannel_session_total") {
			if !strings.Contains(mf.GetHelp(), "outcome") {
				t.Errorf("metric %s help text must mention 'outcome' label; got: %q", mf.GetName(), mf.GetHelp())
			}
			return
		}
	}
	t.Fatal("did not find helixchannel_session_total metric family")
}

func keys(m map[string]*dto.MetricFamily) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
