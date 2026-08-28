// Package metrics registers all Prometheus metrics for the
// llm-cluster-router. Metrics are exported as package-level vars
// so they can be shared across router, proxy, and health packages.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// LLMRouterBuckets is the canonical histogram bucket set for
// LLM-streaming workloads: 50ms..120s.
var LLMRouterBuckets = []float64{
	0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120,
}

// RouterTokenRateBuckets is the bucket set for token throughput.
var RouterTokenRateBuckets = []float64{1, 2, 5, 10, 20, 40, 80, 120, 200}

var (
	// QuotaFallbackTotal counts vendor responses that matched the per-node
	// QuotaDetectRegex and triggered a failover off the vendor peer.
	QuotaFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llm_router_quota_fallback_total",
		Help: "Vendor quota-exhaustion events that triggered failover off a vendor peer.",
	}, []string{"model", "node", "vendor"})
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llm_router_requests_total",
		Help: "Total routed requests.",
	}, []string{"model", "node", "status"})

	RequestRetries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llm_router_request_retries_total",
		Help: "Requests retried due to idle connection resets.",
	}, []string{"model", "node"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_request_duration_seconds",
		Help:    "End-to-end request duration by model and node (LLM-tuned buckets, 50ms..120s).",
		Buckets: LLMRouterBuckets,
	}, []string{"model", "node"})

	RequestTTFT = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_request_ttft_seconds",
		Help:    "Time-to-first-byte from upstream by model and node (LLM-tuned buckets, 50ms..120s). Captures router perceived TTFT, not in-token TTFT.",
		Buckets: LLMRouterBuckets,
	}, []string{"model", "node"})

	QueueDepthGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "llm_router_queue_depth",
		Help: "Current router queue depth.",
	})

	QueueDepthByTierGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "llm_router_queue_depth_by_tier",
		Help: "Current router queue depth partitioned by selected tier.",
	}, []string{"tier"})

	InflightGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "llm_router_inflight_requests",
		Help: "Current number of inflight requests.",
	})

	GenerationTokensPerSecond = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_generation_tokens_per_second",
		Help:    "Completion token throughput inferred from OpenAI-compatible usage payloads.",
		Buckets: RouterTokenRateBuckets,
	}, []string{"model", "node"})

	PromptTokensPerSecond = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_prompt_tokens_per_second",
		Help:    "Prompt token throughput inferred from OpenAI-compatible usage payloads.",
		Buckets: RouterTokenRateBuckets,
	}, []string{"model", "node"})

	NodeHealthyGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "llm_router_node_healthy",
		Help: "Whether an upstream node is healthy.",
	}, []string{"node", "tier"})

	HealthLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_upstream_health_seconds",
		Help:    "Upstream health check latency.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"node"})

	FairShareRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llm_router_fairshare_rejected_total",
		Help: "Requests rejected by the per-user fair-share limiter.",
	}, []string{"user"})

	AuthRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llm_router_auth_rejected_total",
		Help: "Requests rejected by the bearer-token auth middleware (401).",
	}, []string{"path"})

	// LiveProbeThrottledTotal counts /healthz?live=1 requests that were
	// served the cached health view because the forced-probe rate bound
	// was exhausted. Those requests still answer 200, so this counter is
	// the ONLY signal that the bound is biting -- alert on a sustained
	// rate, which means either a misconfigured poller or somebody using
	// the endpoint as an amplifier.
	LiveProbeThrottledTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "llm_router_health_live_probe_throttled_total",
		Help: "Forced /healthz?live=1 probes refused by the rate bound and served from cache.",
	})
)
