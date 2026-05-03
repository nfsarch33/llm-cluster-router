package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "bench":
		if err := runBench(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "probe-gpu":
		if err := runProbeGPU(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <serve|bench|probe-gpu> [flags]\n", filepath.Base(os.Args[0]))
}

type config struct {
	Listen      string       `yaml:"listen"`
	MetricsAddr string       `yaml:"metrics_addr"`
	DebugAddr   string       `yaml:"debug_addr"`
	LogLevel    string       `yaml:"log_level"`
	AuthToken   string       `yaml:"auth_token"`
	Defaults    defaults     `yaml:"defaults"`
	HealthCheck healthConfig `yaml:"health_check"`
	Nodes       []nodeConfig `yaml:"nodes"`
}

type defaults struct {
	MaxQueueDepth  int           `yaml:"max_queue_depth"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	RequestTimeout durationValue `yaml:"request_timeout"`
	MaxBodySize    int64         `yaml:"max_body_size"`
}

type healthConfig struct {
	Interval           durationValue `yaml:"interval"`
	Timeout            durationValue `yaml:"timeout"`
	Path               string        `yaml:"path"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold"`
	HealthyThreshold   int           `yaml:"healthy_threshold"`
}

type durationValue struct {
	time.Duration
}

func (d *durationValue) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

type nodeConfig struct {
	Name     string   `yaml:"name"`
	URL      string   `yaml:"url"`
	Tier     string   `yaml:"tier"`
	Enabled  string   `yaml:"enabled"`
	Weight   int      `yaml:"weight"`
	Models   []string `yaml:"models"`
	APIKey   string   `yaml:"api_key"`
	Priority int      `yaml:"priority"`
}

// router serves OpenAI-compatible traffic across a fleet of upstream
// LLM nodes. The mutable subset of its state -- cfg, nodes, client,
// and semaphore -- can be replaced atomically via Reload() so the
// daemon can absorb config changes (new nodes, removed nodes, new
// auth token, retuned timeouts) without dropping inflight traffic.
//
// Reload semantics:
//   - The mu lock guards cfg/nodes/client/semaphore. Hot paths take
//     a single snapshot via snap() at the start of a request; that
//     snapshot is used for the lifetime of the request so the request
//     sees a consistent config even if Reload swaps state mid-flight.
//   - listen, metrics_addr, debug_addr, and max_body_size are
//     captured at server boot and require a process restart to
//     change; Reload of those keys is a no-op (logged at warn level
//     by callers in a future PR; see Band H roadmap).
//   - Inflight requests continue using the OLD semaphore. New
//     requests pick up the NEW semaphore. Briefly, both
//     concurrency budgets coexist; this is intentional and bounded
//     by the in-progress request count.
type router struct {
	cfg       config
	client    *http.Client
	semaphore chan struct{}
	nodes     []*upstreamNode

	mu sync.RWMutex // protects cfg, client, semaphore, nodes during Reload

	rr         atomic.Uint64
	queueDepth atomic.Int64
	inflight   atomic.Int64
}

// routerSnap is the consistent view of the reloadable router state
// taken by hot paths at the start of a request. Once captured, the
// snapshot is immutable for the rest of that request even if Reload
// fires in parallel.
type routerSnap struct {
	cfg       config
	nodes     []*upstreamNode
	client    *http.Client
	semaphore chan struct{}
}

// snap takes an RLock and copies the reloadable router state into a
// caller-owned routerSnap. The nodes slice is duplicated so callers
// can iterate it without coordinating with Reload; the *upstreamNode
// pointers themselves are shared (their internal atomic.Bools handle
// concurrent health-state updates).
func (r *router) snap() routerSnap {
	r.mu.RLock()
	defer r.mu.RUnlock()
	nodes := make([]*upstreamNode, len(r.nodes))
	copy(nodes, r.nodes)
	return routerSnap{
		cfg:       r.cfg,
		nodes:     nodes,
		client:    r.client,
		semaphore: r.semaphore,
	}
}

// AuthToken returns the bearer token currently expected by the
// router. It always reflects the most recent successful Reload.
// Callers who hold the value for longer than a single request
// should re-read it; an operator can rotate the token via SIGHUP.
func (r *router) AuthToken() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg.AuthToken
}

// Reload re-reads the on-disk config at path, builds a new node set
// + http.Client + semaphore from it, and atomically swaps them in.
// On any error -- file read, YAML parse, validation, node URL parse
// -- the previous state is preserved verbatim. The caller can wire
// this to SIGHUP via watchReloadSignal so an operator can rotate
// auth tokens, add nodes, or retune timeouts without restarting
// the daemon.
//
// Reload does NOT recreate the http.Server, the listener, the
// metrics or debug servers, or the body-size limit; those are bound
// at server boot. See the router doc comment for the restart-only
// keys.
func (r *router) Reload(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("router reload: load %s: %w", path, err)
	}
	nodes, client, sem, err := buildReloadable(cfg)
	if err != nil {
		return fmt.Errorf("router reload: build state: %w", err)
	}
	r.mu.Lock()
	r.cfg = cfg
	r.nodes = nodes
	r.client = client
	r.semaphore = sem
	r.mu.Unlock()
	log.Printf("router reload succeeded for %s (nodes=%d, max_concurrency=%d, request_timeout=%s)",
		path, len(nodes), cfg.Defaults.MaxConcurrency, cfg.Defaults.RequestTimeout.Duration)
	return nil
}

// watchReloadSignal blocks reading from sigCh and, on each SIGHUP,
// invokes r.Reload(path). The optional after hook fires after each
// attempted reload (regardless of outcome) and is provided so tests
// can synchronise on completion without waiting on a flaky timer.
//
// Other signals on the channel are ignored; the goroutine exits
// when sigCh is closed.
func watchReloadSignal(sigCh <-chan os.Signal, path string, r *router, after func()) {
	for sig := range sigCh {
		if sig != syscall.SIGHUP {
			continue
		}
		if err := r.Reload(path); err != nil {
			log.Printf("router reload failed: %v", err)
		}
		if after != nil {
			after()
		}
	}
}

// buildReloadable turns a parsed config into the four reloadable
// pieces of router state. It is shared by newRouter (initial boot)
// and Reload (atomic swap) so both paths apply identical validation
// and defaulting.
func buildReloadable(cfg config) ([]*upstreamNode, *http.Client, chan struct{}, error) {
	nodes := make([]*upstreamNode, 0, len(cfg.Nodes))
	for _, nc := range cfg.Nodes {
		if !nodeEnabled(nc.Enabled) {
			continue
		}
		if nc.Name == "" || nc.URL == "" {
			return nil, nil, nil, fmt.Errorf("node requires name and url")
		}
		if nc.Weight <= 0 {
			nc.Weight = 1
		}
		parsed, err := url.Parse(nc.URL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse node %s url: %w", nc.Name, err)
		}
		node := &upstreamNode{cfg: nc, baseURL: parsed}
		node.healthy.Store(true)
		nodeHealthyGauge.WithLabelValues(nc.Name, nc.Tier).Set(1)
		nodes = append(nodes, node)
	}
	client := &http.Client{
		Timeout: cfg.Defaults.RequestTimeout.Duration,
		Transport: &http.Transport{
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	sem := make(chan struct{}, cfg.Defaults.MaxConcurrency)
	return nodes, client, sem, nil
}

type upstreamNode struct {
	cfg             nodeConfig
	baseURL         *url.URL
	healthy         atomic.Bool
	consecutivePass atomic.Int64
	consecutiveFail atomic.Int64
}

type gpuProcess struct {
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name"`
	UsedMemoryMiB int    `json:"used_memory_mib"`
}

type gpuSnapshot struct {
	Index          int          `json:"index"`
	UUID           string       `json:"uuid"`
	PCIBusID       string       `json:"pci_bus_id"`
	Name           string       `json:"name"`
	MemoryTotalMiB int          `json:"memory_total_mib"`
	MemoryUsedMiB  int          `json:"memory_used_mib"`
	UtilizationGPU int          `json:"utilization_gpu_pct"`
	TemperatureC   int          `json:"temperature_c"`
	Processes      []gpuProcess `json:"processes,omitempty"`
}

type gpuProbeReport struct {
	CapturedAt string        `json:"captured_at"`
	GPUs       []gpuSnapshot `json:"gpus"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

// llmRouterBuckets is the canonical histogram bucket set for
// LLM-streaming workloads: 50ms..120s. The Prometheus defaults
// (5ms..10s) cap before any non-trivial generation finishes,
// flattening every long request into the +Inf bucket and losing
// p95/p99 resolution. These buckets are wide enough to keep label
// cardinality low while giving operators meaningful percentiles
// across the full vLLM/Ollama latency range.
var llmRouterBuckets = []float64{
	0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120,
}

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llm_router_requests_total",
		Help: "Total routed requests.",
	}, []string{"model", "node", "status"})
	requestRetries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "llm_router_request_retries_total",
		Help: "Requests retried due to idle connection resets.",
	}, []string{"model", "node"})
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_request_duration_seconds",
		Help:    "End-to-end request duration by model and node (LLM-tuned buckets, 50ms..120s).",
		Buckets: llmRouterBuckets,
	}, []string{"model", "node"})
	requestTTFT = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_request_ttft_seconds",
		Help:    "Time-to-first-byte from upstream by model and node (LLM-tuned buckets, 50ms..120s). Captures router perceived TTFT, not in-token TTFT.",
		Buckets: llmRouterBuckets,
	}, []string{"model", "node"})
	queueDepthGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "llm_router_queue_depth",
		Help: "Current router queue depth.",
	})
	inflightGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "llm_router_inflight_requests",
		Help: "Current number of inflight requests.",
	})
	nodeHealthyGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "llm_router_node_healthy",
		Help: "Whether an upstream node is healthy.",
	}, []string{"node", "tier"})
	healthLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "llm_router_upstream_health_seconds",
		Help:    "Upstream health check latency.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"node"})
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "router.sample.yml", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	r, err := newRouter(cfg)
	if err != nil {
		return err
	}

	go r.healthLoop(context.Background())

	if cfg.MetricsAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			log.Printf("metrics listening on %s", cfg.MetricsAddr)
			if err := http.ListenAndServe(cfg.MetricsAddr, mux); err != nil {
				log.Printf("metrics server stopped: %v", err)
			}
		}()
	}

	if cfg.DebugAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			log.Printf("debug listening on %s", cfg.DebugAddr)
			if err := http.ListenAndServe(cfg.DebugAddr, mux); err != nil {
				log.Printf("debug server stopped: %v", err)
			}
		}()
	}

	// Use a closure-form wrapper so the bearer token can be rotated
	// via SIGHUP without restarting the listener. Each request
	// consults r.AuthToken() afresh.
	authWrap := bearerAuthFunc(r.AuthToken)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", r.handleHealth)
	mux.HandleFunc("/v1/models", authWrap(r.handleModels))
	mux.HandleFunc("/v1/chat/completions", authWrap(r.handleProxy))
	mux.HandleFunc("/v1/completions", authWrap(r.handleProxy))
	mux.HandleFunc("/v1/embeddings", authWrap(r.handleProxy))
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           limitBody(cfg.Defaults.MaxBodySize, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Wire SIGHUP -> Reload so an operator can rotate auth tokens,
	// add or remove nodes, and retune health-check / concurrency
	// settings without dropping inflight requests. Listener address
	// and max_body_size are captured at boot and require restart.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go watchReloadSignal(sigCh, *configPath, r, nil)

	log.Printf("router listening on %s", cfg.Listen)
	return server.ListenAndServe()
}

func loadConfig(path string) (config, error) {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.MetricsAddr == "" {
		cfg.MetricsAddr = ":9091"
	}
	if cfg.Defaults.MaxQueueDepth <= 0 {
		cfg.Defaults.MaxQueueDepth = 8
	}
	if cfg.Defaults.MaxConcurrency <= 0 {
		cfg.Defaults.MaxConcurrency = 2
	}
	if cfg.Defaults.RequestTimeout.Duration <= 0 {
		cfg.Defaults.RequestTimeout.Duration = 120 * time.Second
	}
	if cfg.Defaults.MaxBodySize <= 0 {
		cfg.Defaults.MaxBodySize = 1 << 20
	}
	if cfg.HealthCheck.Interval.Duration <= 0 {
		cfg.HealthCheck.Interval.Duration = 15 * time.Second
	}
	if cfg.HealthCheck.Timeout.Duration <= 0 {
		cfg.HealthCheck.Timeout.Duration = 5 * time.Second
	}
	if cfg.HealthCheck.Path == "" {
		cfg.HealthCheck.Path = "/health"
	}
	if cfg.HealthCheck.UnhealthyThreshold <= 0 {
		cfg.HealthCheck.UnhealthyThreshold = 3
	}
	if cfg.HealthCheck.HealthyThreshold <= 0 {
		cfg.HealthCheck.HealthyThreshold = 1
	}
	if len(cfg.Nodes) == 0 {
		return cfg, errors.New("config must define at least one node")
	}
	cfg.AuthToken = expandEnvValue(cfg.AuthToken)
	for i := range cfg.Nodes {
		cfg.Nodes[i].APIKey = expandEnvValue(cfg.Nodes[i].APIKey)
		cfg.Nodes[i].Enabled = expandEnvValue(cfg.Nodes[i].Enabled)
		if err := validateUpstreamURL(cfg.Nodes[i].Name, cfg.Nodes[i].URL); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// forbiddenUpstreamHostSuffixes is the locked list of hostnames the
// router refuses to route to. The list is intentionally narrow: it
// targets corporate or managed gateways whose use would silently push
// every prompt — and any embedded secrets, PII, or proprietary data —
// across a trust boundary the operator did not opt into.
//
// Suffix matching is case-insensitive and applied after the URL host
// is lowercased. Both bare apex (zende.sk) and any subdomain
// (ai-gateway.zende.sk) are blocked. Adding a new entry is a one-line
// review in this file plus a regression test in main_test.go; do not
// add behind feature flags.
var forbiddenUpstreamHostSuffixes = []string{
	"zende.sk",
	"zendesk.com",
}

// validateUpstreamURL parses node.url and rejects it when the host
// matches a forbiddenUpstreamHostSuffixes entry. The check is
// case-insensitive and matches the apex domain plus any subdomain.
//
// Empty or malformed URLs are passed through; downstream node setup
// will surface those with a clearer error than this function can.
func validateUpstreamURL(nodeName, rawURL string) error {
	if rawURL == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return nil
	}
	for _, suffix := range forbiddenUpstreamHostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return fmt.Errorf(
				"node %q: forbidden upstream host %q (matches %q); "+
					"see router.sample.yml — this router is for self-hosted clusters only",
				nodeName, host, suffix,
			)
		}
	}
	return nil
}

func expandEnvValue(s string) string {
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return s
	}
	key := s[2 : len(s)-1]
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return ""
}

func bearerAuth(token string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		if token == "" {
			return next
		}
		return func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+token {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

// bearerAuthFunc is the dynamic-token form of bearerAuth. It calls
// getToken() on each request so SIGHUP-driven token rotation is
// picked up immediately without rebuilding the http.ServeMux. An
// empty token disables auth entirely (matching bearerAuth).
func bearerAuthFunc(getToken func() string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := getToken()
			if token == "" {
				next(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+token {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

func newRouter(cfg config) (*router, error) {
	nodes, client, sem, err := buildReloadable(cfg)
	if err != nil {
		return nil, err
	}
	return &router{
		cfg:       cfg,
		client:    client,
		semaphore: sem,
		nodes:     nodes,
	}, nil
}

func limitBody(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func (r *router) handleHealth(w http.ResponseWriter, _ *http.Request) {
	type nodeStatus struct {
		Name    string   `json:"name"`
		Tier    string   `json:"tier"`
		URL     string   `json:"url"`
		Models  []string `json:"models"`
		Healthy bool     `json:"healthy"`
	}
	snap := r.snap()
	nodes := make([]nodeStatus, 0, len(snap.nodes))
	healthy := 0
	for _, node := range snap.nodes {
		ok := node.healthy.Load()
		if ok {
			healthy++
		}
		nodes = append(nodes, nodeStatus{
			Name:    node.cfg.Name,
			Tier:    node.cfg.Tier,
			URL:     node.cfg.URL,
			Models:  node.cfg.Models,
			Healthy: ok,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                healthy > 0,
		"healthy_nodes":     healthy,
		"total_nodes":       len(snap.nodes),
		"queue_depth":       r.queueDepth.Load(),
		"inflight_requests": r.inflight.Load(),
		"max_queue_depth":   snap.cfg.Defaults.MaxQueueDepth,
		"max_concurrency":   snap.cfg.Defaults.MaxConcurrency,
		"nodes":             nodes,
	})
}

func (r *router) handleModels(w http.ResponseWriter, _ *http.Request) {
	snap := r.snap()
	seen := make(map[string]struct{})
	models := make([]map[string]string, 0)
	for _, node := range snap.nodes {
		if !node.healthy.Load() {
			continue
		}
		for _, model := range node.cfg.Models {
			if _, ok := seen[model]; ok {
				continue
			}
			seen[model] = struct{}{}
			models = append(models, map[string]string{
				"id":       model,
				"object":   "model",
				"owned_by": "llm-cluster-router",
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   models,
	})
}

func (r *router) handleProxy(w http.ResponseWriter, req *http.Request) {
	start := time.Now()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read request body: %v", err), http.StatusBadRequest)
		return
	}

	// Snapshot the reloadable state once at the top so the entire
	// request runs against a consistent config even if SIGHUP fires
	// mid-flight. The snapshot is cheap (one RLock + a slice copy)
	// and avoids the inconsistency of a request that picks a node
	// from one config and a timeout from a newer one.
	snap := r.snap()

	model := extractModel(body)
	tier := req.Header.Get("X-Tier")
	node := r.selectNodeFromSnap(snap, model, tier, "")
	if node == nil {
		http.Error(w, "no healthy upstream available for requested model", http.StatusServiceUnavailable)
		requestsTotal.WithLabelValues(model, "none", "unavailable").Inc()
		return
	}

	queueDepth := r.queueDepth.Add(1)
	queueDepthGauge.Set(float64(queueDepth))
	if int(queueDepth) > snap.cfg.Defaults.MaxQueueDepth {
		r.queueDepth.Add(-1)
		queueDepthGauge.Set(float64(r.queueDepth.Load()))
		http.Error(w, "router queue is full", http.StatusTooManyRequests)
		requestsTotal.WithLabelValues(model, node.cfg.Name, "queue_full").Inc()
		return
	}

	select {
	case snap.semaphore <- struct{}{}:
		r.queueDepth.Add(-1)
		queueDepthGauge.Set(float64(r.queueDepth.Load()))
		defer func() {
			<-snap.semaphore
		}()
	case <-req.Context().Done():
		r.queueDepth.Add(-1)
		queueDepthGauge.Set(float64(r.queueDepth.Load()))
		http.Error(w, "request cancelled while queued", http.StatusRequestTimeout)
		requestsTotal.WithLabelValues(model, node.cfg.Name, "cancelled").Inc()
		return
	}

	r.inflight.Add(1)
	inflightGauge.Set(float64(r.inflight.Load()))
	defer func() {
		r.inflight.Add(-1)
		inflightGauge.Set(float64(r.inflight.Load()))
	}()

	upstreamURL := *node.baseURL
	upstreamURL.Path = strings.TrimRight(node.baseURL.Path, "/") + req.URL.Path
	upstreamURL.RawQuery = req.URL.RawQuery

	ctx, cancel := context.WithTimeout(req.Context(), snap.cfg.Defaults.RequestTimeout.Duration)
	defer cancel()

	upstreamReq, err := http.NewRequestWithContext(ctx, req.Method, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, fmt.Sprintf("build upstream request: %v", err), http.StatusInternalServerError)
		requestsTotal.WithLabelValues(model, node.cfg.Name, "build_error").Inc()
		return
	}
	copyHeaders(upstreamReq.Header, req.Header)
	if node.cfg.APIKey != "" {
		upstreamReq.Header.Set("Authorization", "Bearer "+node.cfg.APIKey)
	}

	resp, err := snap.client.Do(upstreamReq)
	if err != nil && isRetryableConnError(err) {
		requestRetries.WithLabelValues(model, node.cfg.Name).Inc()
		retryReq, retryErr := http.NewRequestWithContext(ctx, req.Method, upstreamURL.String(), bytes.NewReader(body))
		if retryErr == nil {
			copyHeaders(retryReq.Header, req.Header)
			if node.cfg.APIKey != "" {
				retryReq.Header.Set("Authorization", "Bearer "+node.cfg.APIKey)
			}
			resp, err = snap.client.Do(retryReq)
		}
	}
	if err != nil {
		node.healthy.Store(false)
		nodeHealthyGauge.WithLabelValues(node.cfg.Name, node.cfg.Tier).Set(0)
		if fallback := r.selectNodeFromSnap(snap, model, tier, node.cfg.Name); fallback != nil {
			fallbackURL := *fallback.baseURL
			fallbackURL.Path = strings.TrimRight(fallback.baseURL.Path, "/") + req.URL.Path
			fallbackURL.RawQuery = req.URL.RawQuery
			fallbackReq, fallbackErr := http.NewRequestWithContext(ctx, req.Method, fallbackURL.String(), bytes.NewReader(body))
			if fallbackErr == nil {
				copyHeaders(fallbackReq.Header, req.Header)
				if fallback.cfg.APIKey != "" {
					fallbackReq.Header.Set("Authorization", "Bearer "+fallback.cfg.APIKey)
				}
				resp, err = snap.client.Do(fallbackReq)
				if err == nil {
					node = fallback
				} else {
					requestRetries.WithLabelValues(model, fallback.cfg.Name).Inc()
				}
			}
		}
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream request failed: %v", err), http.StatusBadGateway)
		requestsTotal.WithLabelValues(model, node.cfg.Name, "bad_gateway").Inc()
		return
	}
	defer resp.Body.Close()

	// TTFT here is "router-perceived time-to-first-byte" -- from
	// request-arrival to upstream returning headers. It is NOT
	// in-token TTFT (we don't parse SSE chunks here); for that the
	// client must measure from the first `data:` line on the
	// streamed body. Still, this is a useful upstream-side latency
	// signal because vLLM batching delays appear here.
	requestTTFT.WithLabelValues(model, node.cfg.Name).Observe(time.Since(start).Seconds())

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(flushWriter{ResponseWriter: w}, resp.Body); err != nil && !errors.Is(err, context.Canceled) {
		requestsTotal.WithLabelValues(model, node.cfg.Name, "stream_error").Inc()
		return
	}

	statusLabel := strconv.Itoa(resp.StatusCode)
	requestsTotal.WithLabelValues(model, node.cfg.Name, statusLabel).Inc()
	requestDuration.WithLabelValues(model, node.cfg.Name).Observe(time.Since(start).Seconds())
}

// selectNode is the legacy entrypoint kept for direct test usage.
// Production callers should prefer selectNodeFromSnap so the entire
// request shares a single config snapshot.
func (r *router) selectNode(model, targetTier string) *upstreamNode {
	return r.selectNodeExcluding(model, targetTier, "")
}

// selectNodeExcluding is the legacy form of selectNodeFromSnap that
// still takes an RLock for tests that don't have a snapshot in
// hand. New production code paths take a snap up front.
func (r *router) selectNodeExcluding(model, targetTier, excludeName string) *upstreamNode {
	return r.selectNodeFromSnap(r.snap(), model, targetTier, excludeName)
}

func (r *router) selectNodeFromSnap(snap routerSnap, model, targetTier, excludeName string) *upstreamNode {
	type bucket struct {
		priority   int
		candidates []*upstreamNode
	}

	targetTier = strings.TrimSpace(targetTier)
	buckets := make(map[int]*bucket)
	for _, node := range snap.nodes {
		if !node.healthy.Load() {
			continue
		}
		if excludeName != "" && node.cfg.Name == excludeName {
			continue
		}
		if targetTier != "" && node.cfg.Tier != targetTier {
			continue
		}
		if model == "" || supportsModel(node.cfg.Models, model) {
			p := node.cfg.Priority
			b, ok := buckets[p]
			if !ok {
				b = &bucket{priority: p}
				buckets[p] = b
			}
			for i := 0; i < node.cfg.Weight; i++ {
				b.candidates = append(b.candidates, node)
			}
		}
	}
	if len(buckets) == 0 {
		return nil
	}

	priorities := make([]int, 0, len(buckets))
	for p := range buckets {
		priorities = append(priorities, p)
	}
	sort.Ints(priorities)

	candidates := buckets[priorities[0]].candidates
	idx := int(r.rr.Add(1)-1) % len(candidates)
	return candidates[idx]
}

func nodeEnabled(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "" || value == "1" || value == "true" || value == "yes" || value == "on"
}

func (r *router) healthLoop(ctx context.Context) {
	r.runHealthPass(ctx)
	// Re-read the interval before every tick so a SIGHUP reload
	// that retunes health_check.interval takes effect on the next
	// pass instead of being pinned to the boot-time value.
	for {
		snap := r.snap()
		interval := snap.cfg.HealthCheck.Interval.Duration
		if interval <= 0 {
			interval = 15 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			r.runHealthPass(ctx)
		}
	}
}

func (r *router) runHealthPass(ctx context.Context) {
	snap := r.snap()
	hc := snap.cfg.HealthCheck
	var wg sync.WaitGroup
	for _, node := range snap.nodes {
		wg.Add(1)
		go func(node *upstreamNode) {
			defer wg.Done()
			start := time.Now()
			pass := probeNode(ctx, hc, node)
			healthLatency.WithLabelValues(node.cfg.Name).Observe(time.Since(start).Seconds())
			if pass {
				node.consecutiveFail.Store(0)
				passes := node.consecutivePass.Add(1)
				if passes >= int64(hc.HealthyThreshold) {
					node.healthy.Store(true)
					nodeHealthyGauge.WithLabelValues(node.cfg.Name, node.cfg.Tier).Set(1)
				}
			} else {
				node.consecutivePass.Store(0)
				fails := node.consecutiveFail.Add(1)
				if fails >= int64(hc.UnhealthyThreshold) {
					node.healthy.Store(false)
					nodeHealthyGauge.WithLabelValues(node.cfg.Name, node.cfg.Tier).Set(0)
				}
			}
		}(node)
	}
	wg.Wait()
}

func probeNode(parent context.Context, hc healthConfig, node *upstreamNode) bool {
	ctx, cancel := context.WithTimeout(parent, hc.Timeout.Duration)
	defer cancel()

	for _, path := range healthProbePaths(hc.Path) {
		ok, status := probeNodePath(ctx, node, path)
		if ok {
			return true
		}
		if status != http.StatusNotFound {
			return false
		}
	}
	return false
}

func healthProbePaths(primary string) []string {
	paths := []string{primary}
	if primary != "/v1/models" {
		paths = append(paths, "/v1/models")
	}
	return paths
}

func probeNodePath(ctx context.Context, node *upstreamNode, path string) (bool, int) {
	target := *node.baseURL
	target.Path = strings.TrimRight(node.baseURL.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false, 0
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, resp.StatusCode
}

func isRetryableConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "server closed idle connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}

func extractModel(body []byte) string {
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Model
}

func supportsModel(models []string, model string) bool {
	for _, candidate := range models {
		if candidate == model {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

type flushWriter struct {
	http.ResponseWriter
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.ResponseWriter.Write(p)
	if flusher, ok := fw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	baseURL := fs.String("url", "http://127.0.0.1:8080", "router base URL")
	model := fs.String("model", "qwen3.5-27b", "model name")
	apiKey := fs.String("api-key", "local", "bearer token")
	prompt := fs.String("prompt", "Bench the live local route and reply with a short acknowledgement.", "benchmark prompt")
	requests := fs.Int("requests", 4, "number of requests")
	concurrency := fs.Int("concurrency", 1, "number of concurrent requests")
	maxTokens := fs.Int("max-tokens", 64, "maximum completion tokens per request")
	timeout := fs.Duration("timeout", 3*time.Minute, "request timeout")
	cancelAfter := fs.Duration("cancel-after", 1500*time.Millisecond, "cancel one probe request after this duration")
	output := fs.String("output", filepath.Join(os.TempDir(), "llm-cluster-router-benchmark.json"), "benchmark report path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := &http.Client{Timeout: *timeout}
	metricsURL := strings.TrimRight(*baseURL, "/") + "/metrics"
	results := make([]requestResult, *requests)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	maxQueueDepth := new(atomic.Int64)
	go pollMetric(ctx, client, metricsURL, "llm_router_queue_depth", maxQueueDepth)

	work := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range work {
				results[idx] = runBenchRequest(client, *baseURL, *model, *apiKey, *prompt, *timeout, *maxTokens)
			}
		}()
	}

	for i := 0; i < *requests; i++ {
		work <- i
	}
	close(work)
	wg.Wait()

	cancelResult := runCancelProbe(*baseURL, *model, *apiKey, *prompt, *cancelAfter, *maxTokens)
	healthBefore, _ := fetchJSON(client, strings.TrimRight(*baseURL, "/")+"/healthz")
	modelsPayload, _ := fetchJSON(client, strings.TrimRight(*baseURL, "/")+"/v1/models")

	report := buildReport(*baseURL, *model, results, cancelResult, maxQueueDepth.Load())
	report.HealthSnapshot = healthBefore
	report.ModelsSnapshot = modelsPayload

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote benchmark report to %s\n", *output)
	fmt.Println(string(data))
	return nil
}

func runProbeGPU(args []string) error {
	fs := flag.NewFlagSet("probe-gpu", flag.ContinueOnError)
	output := fs.String("output", "", "optional path to write JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	gpus, err := collectGPUSnapshots(context.Background(), runCommand)
	if err != nil {
		return err
	}

	report := gpuProbeReport{
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
		GPUs:       gpus,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	if *output == "" {
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}

	return os.WriteFile(*output, append(data, '\n'), 0o644)
}

func collectGPUSnapshots(ctx context.Context, runner commandRunner) ([]gpuSnapshot, error) {
	gpuCSV, err := runner(ctx, "nvidia-smi",
		"--query-gpu=index,uuid,pci.bus_id,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
		"--format=csv,noheader",
	)
	if err != nil {
		return nil, err
	}
	gpus, err := parseGPUCSV(string(gpuCSV))
	if err != nil {
		return nil, err
	}

	computeCSV, err := runner(ctx, "nvidia-smi",
		"--query-compute-apps=gpu_uuid,pid,process_name,used_memory",
		"--format=csv,noheader",
	)
	if err != nil {
		return nil, err
	}
	processes, err := parseComputeAppsCSV(string(computeCSV))
	if err != nil {
		return nil, err
	}
	return attachGPUProcesses(gpus, processes), nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func parseGPUCSV(raw string) ([]gpuSnapshot, error) {
	lines := splitCSVLines(raw)
	gpus := make([]gpuSnapshot, 0, len(lines))
	for _, line := range lines {
		fields := splitCSVFields(line)
		if len(fields) != 8 {
			return nil, fmt.Errorf("unexpected gpu field count %d in %q", len(fields), line)
		}

		index, err := parseMetricInt(fields[0])
		if err != nil {
			return nil, fmt.Errorf("parse gpu index: %w", err)
		}
		memoryTotal, err := parseMetricInt(fields[4])
		if err != nil {
			return nil, fmt.Errorf("parse total memory: %w", err)
		}
		memoryUsed, err := parseMetricInt(fields[5])
		if err != nil {
			return nil, fmt.Errorf("parse used memory: %w", err)
		}
		utilization, err := parseMetricInt(fields[6])
		if err != nil {
			return nil, fmt.Errorf("parse utilization: %w", err)
		}
		temperature, err := parseMetricInt(fields[7])
		if err != nil {
			return nil, fmt.Errorf("parse temperature: %w", err)
		}

		gpus = append(gpus, gpuSnapshot{
			Index:          index,
			UUID:           fields[1],
			PCIBusID:       fields[2],
			Name:           fields[3],
			MemoryTotalMiB: memoryTotal,
			MemoryUsedMiB:  memoryUsed,
			UtilizationGPU: utilization,
			TemperatureC:   temperature,
		})
	}
	return gpus, nil
}

func parseComputeAppsCSV(raw string) (map[string][]gpuProcess, error) {
	lines := splitCSVLines(raw)
	processes := make(map[string][]gpuProcess)
	for _, line := range lines {
		fields := splitCSVFields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("unexpected compute app field count %d in %q", len(fields), line)
		}

		pid, err := parseMetricInt(fields[1])
		if err != nil {
			return nil, fmt.Errorf("parse pid: %w", err)
		}
		usedMemory, err := parseOptionalMetricInt(fields[3])
		if err != nil {
			return nil, fmt.Errorf("parse process memory: %w", err)
		}

		processes[fields[0]] = append(processes[fields[0]], gpuProcess{
			PID:           pid,
			ProcessName:   fields[2],
			UsedMemoryMiB: usedMemory,
		})
	}
	return processes, nil
}

func attachGPUProcesses(gpus []gpuSnapshot, processes map[string][]gpuProcess) []gpuSnapshot {
	merged := make([]gpuSnapshot, len(gpus))
	copy(merged, gpus)
	for i := range merged {
		merged[i].Processes = processes[merged[i].UUID]
	}
	return merged
}

func splitCSVLines(raw string) []string {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	return filtered
}

func splitCSVFields(line string) []string {
	parts := strings.Split(line, ",")
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		fields = append(fields, strings.TrimSpace(part))
	}
	return fields
}

func parseMetricInt(raw string) (int, error) {
	cleaned := strings.TrimSpace(raw)
	for _, suffix := range []string{"MiB", "%"} {
		cleaned = strings.TrimSpace(strings.TrimSuffix(cleaned, suffix))
	}
	return strconv.Atoi(cleaned)
}

func parseOptionalMetricInt(raw string) (int, error) {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" || cleaned == "N/A" || cleaned == "[N/A]" {
		return 0, nil
	}
	return parseMetricInt(cleaned)
}

type requestResult struct {
	OK                  bool
	Error               string
	TTFTMillis          float64
	LatencyMillis       float64
	PromptTokens        int
	CompletionTokens    int
	GenerationTokensSec float64
	PromptTokensSec     float64
}

type cancelProbeResult struct {
	CancelledCleanly bool    `json:"cancelled_cleanly"`
	Error            string  `json:"error,omitempty"`
	ElapsedMillis    float64 `json:"elapsed_ms"`
}

type benchmarkReport struct {
	CapturedAt                string            `json:"captured_at"`
	BaseURL                   string            `json:"base_url"`
	Model                     string            `json:"model"`
	Requests                  int               `json:"requests"`
	SuccessfulRequests        int               `json:"successful_requests"`
	FailedRequests            int               `json:"failed_requests"`
	SuccessRate               float64           `json:"success_rate"`
	P50TTFTMillis             float64           `json:"p50_ttft_ms"`
	P95TTFTMillis             float64           `json:"p95_ttft_ms"`
	P50LatencyMillis          float64           `json:"p50_latency_ms"`
	P95LatencyMillis          float64           `json:"p95_latency_ms"`
	AvgGenerationTokensPerSec float64           `json:"avg_generation_tokens_per_sec"`
	AvgPromptTokensPerSec     float64           `json:"avg_prompt_tokens_per_sec"`
	ObservedMaxQueueDepth     int64             `json:"observed_max_queue_depth"`
	CancelProbe               cancelProbeResult `json:"cancel_probe"`
	HealthSnapshot            map[string]any    `json:"health_snapshot,omitempty"`
	ModelsSnapshot            map[string]any    `json:"models_snapshot,omitempty"`
	Failures                  []string          `json:"failures,omitempty"`
	RawResults                []requestResult   `json:"raw_results"`
}

func runBenchRequest(client *http.Client, baseURL, model, apiKey, prompt string, timeout time.Duration, maxTokens int) requestResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	payload := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"stream":     true,
		"stream_options": map[string]any{
			"include_usage": true,
		},
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return requestResult{Error: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return requestResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return requestResult{Error: fmt.Sprintf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(payload)))}
	}

	var ttft time.Duration
	var firstTokenSeen bool
	var promptTokens int
	var completionTokens int
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			continue
		}
		if !firstTokenSeen && hasDeltaContent(payload) {
			ttft = time.Since(start)
			firstTokenSeen = true
		}
		if usage, ok := payload["usage"].(map[string]any); ok {
			promptTokens = int(numberValue(usage["prompt_tokens"]))
			completionTokens = int(numberValue(usage["completion_tokens"]))
		}
	}
	if err := scanner.Err(); err != nil {
		return requestResult{Error: err.Error()}
	}

	latency := time.Since(start)
	result := requestResult{
		OK:               true,
		TTFTMillis:       durationMillis(ttft),
		LatencyMillis:    durationMillis(latency),
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		PromptTokensSec:  safeRate(promptTokens, latency),
	}
	if completionTokens > 0 && latency > ttft {
		result.GenerationTokensSec = float64(completionTokens) / (latency.Seconds() - ttft.Seconds())
	}
	return result
}

func runCancelProbe(baseURL, model, apiKey, prompt string, cancelAfter time.Duration, maxTokens int) cancelProbeResult {
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientTimeout := cancelAfter + 5*time.Second
	if clientTimeout < 5*time.Second {
		clientTimeout = 5 * time.Second
	}

	payload := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"stream":     true,
		"messages": []map[string]string{
			{"role": "user", "content": prompt + " Keep streaming so cancellation can be observed."},
		},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return cancelProbeResult{Error: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	go func() {
		time.Sleep(cancelAfter)
		cancel()
	}()

	resp, err := (&http.Client{Timeout: clientTimeout}).Do(req)
	if err != nil {
		return cancelProbeResult{
			CancelledCleanly: strings.Contains(strings.ToLower(err.Error()), "context canceled"),
			Error:            err.Error(),
			ElapsedMillis:    durationMillis(time.Since(start)),
		}
	}
	defer resp.Body.Close()
	_, readErr := io.Copy(io.Discard, resp.Body)
	cancelled := readErr != nil && strings.Contains(strings.ToLower(readErr.Error()), "context canceled")
	return cancelProbeResult{
		CancelledCleanly: cancelled,
		Error:            errorString(readErr),
		ElapsedMillis:    durationMillis(time.Since(start)),
	}
}

func buildReport(baseURL, model string, results []requestResult, cancelResult cancelProbeResult, maxQueueDepth int64) benchmarkReport {
	ttfts := make([]float64, 0, len(results))
	latencies := make([]float64, 0, len(results))
	failures := make([]string, 0)
	var okCount int
	var genRateSum float64
	var promptRateSum float64

	for _, result := range results {
		if result.OK {
			okCount++
			ttfts = append(ttfts, result.TTFTMillis)
			latencies = append(latencies, result.LatencyMillis)
			genRateSum += result.GenerationTokensSec
			promptRateSum += result.PromptTokensSec
		} else {
			failures = append(failures, result.Error)
		}
	}

	avgGen := 0.0
	avgPrompt := 0.0
	if okCount > 0 {
		avgGen = genRateSum / float64(okCount)
		avgPrompt = promptRateSum / float64(okCount)
	}

	return benchmarkReport{
		CapturedAt:                time.Now().UTC().Format(time.RFC3339),
		BaseURL:                   baseURL,
		Model:                     model,
		Requests:                  len(results),
		SuccessfulRequests:        okCount,
		FailedRequests:            len(results) - okCount,
		SuccessRate:               percent(okCount, len(results)),
		P50TTFTMillis:             percentile(ttfts, 50),
		P95TTFTMillis:             percentile(ttfts, 95),
		P50LatencyMillis:          percentile(latencies, 50),
		P95LatencyMillis:          percentile(latencies, 95),
		AvgGenerationTokensPerSec: avgGen,
		AvgPromptTokensPerSec:     avgPrompt,
		ObservedMaxQueueDepth:     maxQueueDepth,
		CancelProbe:               cancelResult,
		Failures:                  failures,
		RawResults:                results,
	}
}

func pollMetric(ctx context.Context, client *http.Client, metricsURL, metric string, target *atomic.Int64) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, err := client.Get(metricsURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			value := parsePrometheusGauge(string(body), metric)
			for {
				current := target.Load()
				if value <= current {
					break
				}
				if target.CompareAndSwap(current, value) {
					break
				}
			}
		}
	}
}

func fetchJSON(client *http.Client, target string) (map[string]any, error) {
	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func parsePrometheusGauge(payload, name string) int64 {
	for _, line := range strings.Split(payload, "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		f, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		return int64(f)
	}
	return 0
}

func hasDeltaContent(payload map[string]any) bool {
	choices, ok := payload["choices"].([]any)
	if !ok || len(choices) == 0 {
		return false
	}
	first, ok := choices[0].(map[string]any)
	if !ok {
		return false
	}
	delta, ok := first["delta"].(map[string]any)
	if !ok {
		return false
	}
	content, ok := delta["content"].(string)
	return ok && strings.TrimSpace(content) != ""
}

func numberValue(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func durationMillis(d time.Duration) float64 {
	return float64(d.Milliseconds())
}

func safeRate(tokens int, latency time.Duration) float64 {
	if tokens == 0 || latency <= 0 {
		return 0
	}
	return float64(tokens) / latency.Seconds()
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	position := (p / 100) * float64(len(sorted)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	weight := position - float64(lower)
	return sorted[lower] + (sorted[upper]-sorted[lower])*weight
}

func percent(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return (float64(numerator) / float64(denominator)) * 100
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var _ = httputil.ReverseProxy{}
