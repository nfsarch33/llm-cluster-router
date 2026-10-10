package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestHelixChannelMetrics_RegisterAndIncrement asserts the additive
// HelixChannel metric families from v18712-1 are registered on the
// production-isolated Prometheus registry and increment like the
// legacy listener families.
func TestHelixChannelMetrics_RegisterAndIncrement(t *testing.T) {
	// Absolute-value assertions (series count, byte sum) against
	// package-level vectors: start from a known zero so test order cannot
	// change the answer.
	Reset()

	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	HelixChannelConnectionsTotal.WithLabelValues("in").Inc()
	HelixChannelConnectionsTotal.WithLabelValues("out").Inc()
	HelixChannelBytesTotal.WithLabelValues("in").Add(42)
	HelixChannelBytesTotal.WithLabelValues("out").Add(84)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		got[mf.GetName()] = mf
	}

	if _, ok := got["llm_cluster_router_helixchannel_connections_total"]; !ok {
		t.Error("missing metric llm_cluster_router_helixchannel_connections_total")
	}
	if _, ok := got["llm_cluster_router_helixchannel_bytes_total"]; !ok {
		t.Error("missing metric llm_cluster_router_helixchannel_bytes_total")
	}

	conns := got["llm_cluster_router_helixchannel_connections_total"]
	if conns == nil {
		t.Fatal("nil HelixChannelConnectionsTotal family")
	}
	if len(conns.GetMetric()) != 2 {
		t.Errorf("HelixChannelConnectionsTotal series count = %d, want 2", len(conns.GetMetric()))
	}
	bytes := got["llm_cluster_router_helixchannel_bytes_total"]
	if bytes == nil {
		t.Fatal("nil HelixChannelBytesTotal family")
	}
	var totalBytes float64
	for _, m := range bytes.GetMetric() {
		totalBytes += m.GetCounter().GetValue()
	}
	if totalBytes != 126 {
		t.Errorf("HelixChannelBytesTotal sum = %v, want 126", totalBytes)
	}
}
