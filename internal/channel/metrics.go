package channel

import "github.com/prometheus/client_golang/prometheus"

// KeyRetiredTotal counts key retirements by route and reason.
//
// Registered name: llm_cluster_router_helixchannel_key_retired_total. The
// llm_cluster_router namespace matches the existing
// llm_cluster_router_helixchannel_* families elsewhere in the binary;
// dashboards and alert rules key off the namespaced form.
var KeyRetiredTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "llm_cluster_router",
	Name:      "helixchannel_key_retired_total",
	Help:      "HelixChannel API keys retired from rotation, by route and reason (cap|quota|error).",
}, []string{"route", "reason"})

// RegisterMetrics registers the channel metrics with reg.
//
// Registration is the caller's choice rather than an init() so a test can use
// prometheus.NewRegistry() and so importing this package never mutates the
// default registry.
func RegisterMetrics(reg prometheus.Registerer) error { return reg.Register(KeyRetiredTotal) }

// promRetireObserver is the default RetireObserver.
type promRetireObserver struct{}

func (promRetireObserver) KeyRetired(route string, reason RetireReason) {
	KeyRetiredTotal.WithLabelValues(route, string(reason)).Inc()
}
