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

// AdmissionRefusedTotal counts requests refused BEFORE any upstream call, by
// route and reason.
//
// Registered name: llm_cluster_router_helixchannel_admission_refused_total. It
// is separate from KeyRetiredTotal because a retirement is a key LEAVING
// rotation while this counts CALLERS turned away, and the two need different
// alerts: keys_exhausted sustained is a billing page, admission_limited
// sustained is a capacity signal — the route is being offered more concurrency
// than its per-window plan allows, with nothing wrong with any key.
//
// The reason label carries exactly the error code in the 503 body and in the
// audit line, so one vocabulary spans the response, the log and the series.
//
// The CONNECT leg reports here too, with reason tunnels_at_capacity and the
// literal route "connect" -- that leg has no configured route to name, and
// naming the TARGET instead would put a caller-controlled string in a metric
// label and mint a series per host. It is a capacity signal like
// admission_limited and not a fault: sustained, it means the gateway is being
// offered more simultaneous tunnels than connect.max_concurrent allows.
var AdmissionRefusedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "llm_cluster_router",
	Name:      "helixchannel_admission_refused_total",
	Help:      "HelixChannel requests refused before any upstream call, by route and reason (keys_exhausted|admission_limited|tunnels_at_capacity).",
}, []string{"route", "reason"})

// RegisterMetrics registers the channel metrics with reg.
//
// Registration is the caller's choice rather than an init() so a test can use
// prometheus.NewRegistry() and so importing this package never mutates the
// default registry.
func RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{KeyRetiredTotal, AdmissionRefusedTotal} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// promRetireObserver is the default RetireObserver.
type promRetireObserver struct{}

func (promRetireObserver) KeyRetired(route string, reason RetireReason) {
	KeyRetiredTotal.WithLabelValues(route, string(reason)).Inc()
}
