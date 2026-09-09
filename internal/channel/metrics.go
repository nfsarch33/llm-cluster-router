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

// ForwardFailedTotal counts upstream round trips that produced no response at
// all, by route and failure class.
//
// Registered name: llm_cluster_router_helixchannel_forward_failed_total.
//
// Every increment here is a 502 a caller received. Until this existed the
// gateway emitted NOTHING countable for that outcome — handleProxy wrote its
// audit line and returned — so on the metrics an upstream failing every request
// and an upstream receiving no requests were the same picture: the absence of
// success. That blind spot is how a sixty-second header-phase ceiling in the
// outbound transport went unattributed while it failed every long completion
// the gateway was asked to relay. The NDJSON always held the answer; nothing
// scraped the NDJSON.
//
// It is deliberately NOT the inverse of a success counter. Requests refused
// before any upstream call are AdmissionRefusedTotal's, and keeping the two
// apart is what lets an operator separate "we could not reach the provider"
// from "we would not ask it" — different pages, different fixes.
//
// The class label is errorClass(err) verbatim — timeout, canceled, refused,
// dns, tls, upstream_error — so one vocabulary spans the series, the audit
// line's error field and the runbook.
//
// class="timeout" is worth alerting on, with one caveat stated here rather than
// discovered later. errorClass cannot tell a route-budget deadline from a
// transport header ceiling: Go wraps the latter in an error whose Is method
// reports context.DeadlineExceeded, so both land on this label. The reason the
// series is nonetheless readable as "this route's budget is too small for what
// the provider was asked to generate" is that the transport no longer HAS a
// header ceiling, and NewHTTPForwarder's absence of one is pinned structurally
// by a test. The guarantee is that pin, not the classifier.
//
// EXPOSITION IS NOT WIRED. This family, like the two above it, is registered by
// the gateway command on the default registerer — and the gateway process
// serves no /metrics endpoint, so nothing scrapes any of them today. The
// counter is therefore correct, incremented, and currently unreadable from
// outside the process. Adding an endpoint is not a drive-by change: this
// server's public listener answers /healthz anonymously by design, and route
// names and key-inventory sizes are not things to hand to an unauthenticated
// caller, so it needs a deliberate decision about where it binds and who may
// read it.
var ForwardFailedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "llm_cluster_router",
	Name:      "helixchannel_forward_failed_total",
	Help:      "HelixChannel upstream round trips that returned no response, by route and class (timeout|canceled|refused|dns|tls|upstream_error).",
}, []string{"route", "class"})

// RegisterMetrics registers the channel metrics with reg.
//
// Registration is the caller's choice rather than an init() so a test can use
// prometheus.NewRegistry() and so importing this package never mutates the
// default registry.
func RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{KeyRetiredTotal, AdmissionRefusedTotal, ForwardFailedTotal} {
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
