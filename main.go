package main

// runx-public-repo-gate: allow-file personal_path_id
//
// This file intentionally references the `ai-gateway.zende.sk` host as
// part of the upstream block-list security declaration
// (`forbiddenUpstreamHostSuffixes`). The literal anchors a security
// guardrail: the router refuses to forward prompts/secrets to corporate
// AI gateways the operator did not opt into. Adding a new entry is a
// one-line review here plus a regression test in main_test.go; do not
// add behind feature flags. Sunset: after the 2026-05-28 ZD AI-gateway
// contract cleanup the literal can be removed entirely and this
// directive reverted. See `backlog/v321-public-repo-cleanup.md`
// (story v321-3) for context.

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

	cfg "github.com/nfsarch33/llm-cluster-router/internal/config"
	"github.com/nfsarch33/llm-cluster-router/internal/health"
	"github.com/nfsarch33/llm-cluster-router/internal/metrics"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
	rtr "github.com/nfsarch33/llm-cluster-router/internal/router"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// Type aliases bridge the config package types back into package main
// so existing tests and code compile without changes. These will be
// removed incrementally as downstream packages consume config directly.
type (
	config        = cfg.Config
	defaults      = cfg.Defaults
	healthConfig  = cfg.HealthConfig
	durationValue = cfg.DurationValue
	nodeConfig    = cfg.NodeConfig
)

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

	queueTierMu      sync.Mutex
	queueDepthByTier map[string]int64
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
		node.breaker = newCircuitBreaker(5, 30*time.Second).WithName(nc.Name)
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
	keyIdx          atomic.Uint64

	// breaker is the per-upstream circuit breaker. It is
	// consulted by selectNodeFromSnap so an upstream that is
	// returning errors faster than the slower health-check loop
	// notices is removed from rotation immediately. Defaults to a
	// 5-failure threshold + 30s cooldown; future PRs can expose
	// these as per-node config.
	breaker *circuitBreaker
}

// nextAPIKey returns the next API key via round-robin when multiple
// keys are configured (api_keys), falls back to the single api_key,
// or returns "" when no key is set.
func (n *upstreamNode) nextAPIKey() string {
	if len(n.cfg.APIKeys) > 0 {
		idx := n.keyIdx.Add(1) - 1
		return n.cfg.APIKeys[idx%uint64(len(n.cfg.APIKeys))]
	}
	return n.cfg.APIKey
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

// Metric aliases bridge the metrics package vars back into package
// main so all existing code compiles unchanged.
var (
	llmRouterBuckets          = metrics.LLMRouterBuckets
	routerTokenRateBuckets    = metrics.RouterTokenRateBuckets
	requestsTotal             = metrics.RequestsTotal
	requestRetries            = metrics.RequestRetries
	requestDuration           = metrics.RequestDuration
	requestTTFT               = metrics.RequestTTFT
	queueDepthGauge           = metrics.QueueDepthGauge
	queueDepthByTierGauge     = metrics.QueueDepthByTierGauge
	inflightGauge             = metrics.InflightGauge
	generationTokensPerSecond = metrics.GenerationTokensPerSecond
	promptTokensPerSecond     = metrics.PromptTokensPerSecond
	nodeHealthyGauge          = metrics.NodeHealthyGauge
	healthLatency             = metrics.HealthLatency
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

// loadConfig delegates to the config package.
var loadConfig = cfg.LoadConfig

// Delegate to config package; keep package-level names so tests compile.
var forbiddenUpstreamHostSuffixes = cfg.ForbiddenUpstreamHostSuffixes
var validateUpstreamURL = cfg.ValidateUpstreamURL
var expandEnvValue = cfg.ExpandEnvValue

var bearerAuth = proxy.BearerAuth
var bearerAuthFunc = proxy.BearerAuthFunc

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

var limitBody = proxy.LimitBody

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

	tierLabel := metricLabel(node.cfg.Tier, "unknown")
	queueDepth := r.queueDepth.Add(1)
	queueDepthGauge.Set(float64(queueDepth))
	r.addQueueDepthByTier(tierLabel, 1)
	dequeue := func() {
		queueDepthGauge.Set(float64(r.queueDepth.Add(-1)))
		r.addQueueDepthByTier(tierLabel, -1)
	}
	if int(queueDepth) > snap.cfg.Defaults.MaxQueueDepth {
		dequeue()
		http.Error(w, "router queue is full", http.StatusTooManyRequests)
		requestsTotal.WithLabelValues(model, node.cfg.Name, "queue_full").Inc()
		return
	}

	select {
	case snap.semaphore <- struct{}{}:
		dequeue()
		defer func() {
			<-snap.semaphore
		}()
	case <-req.Context().Done():
		dequeue()
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
	if key := node.nextAPIKey(); key != "" {
		upstreamReq.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := snap.client.Do(upstreamReq)
	if err != nil && isRetryableConnError(err) {
		requestRetries.WithLabelValues(model, node.cfg.Name).Inc()
		retryReq, retryErr := http.NewRequestWithContext(ctx, req.Method, upstreamURL.String(), bytes.NewReader(body))
		if retryErr == nil {
			copyHeaders(retryReq.Header, req.Header)
			if key := node.nextAPIKey(); key != "" {
				retryReq.Header.Set("Authorization", "Bearer "+key)
			}
			resp, err = snap.client.Do(retryReq)
		}
	}
	if err != nil {
		node.healthy.Store(false)
		nodeHealthyGauge.WithLabelValues(node.cfg.Name, node.cfg.Tier).Set(0)
		if node.breaker != nil {
			node.breaker.RecordFailure()
		}
		if fallback := r.selectNodeFromSnap(snap, model, tier, node.cfg.Name); fallback != nil {
			fallbackURL := *fallback.baseURL
			fallbackURL.Path = strings.TrimRight(fallback.baseURL.Path, "/") + req.URL.Path
			fallbackURL.RawQuery = req.URL.RawQuery
			fallbackReq, fallbackErr := http.NewRequestWithContext(ctx, req.Method, fallbackURL.String(), bytes.NewReader(body))
			if fallbackErr == nil {
				copyHeaders(fallbackReq.Header, req.Header)
				if key := fallback.nextAPIKey(); key != "" {
					fallbackReq.Header.Set("Authorization", "Bearer "+key)
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
	capturedBody := &limitedBuffer{limit: 2 << 20}
	bodyReader := io.TeeReader(resp.Body, capturedBody)
	if _, err := io.Copy(flushWriter{ResponseWriter: w}, bodyReader); err != nil && !errors.Is(err, context.Canceled) {
		requestsTotal.WithLabelValues(model, node.cfg.Name, "stream_error").Inc()
		return
	}
	observeTokenRates(model, node.cfg.Name, time.Since(start), capturedBody.Bytes())

	statusLabel := strconv.Itoa(resp.StatusCode)
	requestsTotal.WithLabelValues(model, node.cfg.Name, statusLabel).Inc()
	requestDuration.WithLabelValues(model, node.cfg.Name).Observe(time.Since(start).Seconds())
	// 5xx upstream responses count as breaker failures even when
	// the transport delivered the bytes. 4xx is treated as
	// upstream-rejected-the-input (caller's fault), not a node
	// problem, so we only record a success for <500.
	if node.breaker != nil {
		if resp.StatusCode >= 500 {
			node.breaker.RecordFailure()
		} else {
			node.breaker.RecordSuccess()
		}
	}
}

func (r *router) addQueueDepthByTier(tier string, delta int64) {
	r.queueTierMu.Lock()
	defer r.queueTierMu.Unlock()
	if r.queueDepthByTier == nil {
		r.queueDepthByTier = make(map[string]int64)
	}
	next := r.queueDepthByTier[tier] + delta
	if next < 0 {
		next = 0
	}
	r.queueDepthByTier[tier] = next
	queueDepthByTierGauge.WithLabelValues(tier).Set(float64(next))
}

var metricLabel = rtr.MetricLabel

type limitedBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 || b.buf.Len() < b.limit {
		remaining := b.limit - b.buf.Len()
		if b.limit <= 0 || remaining > len(p) {
			remaining = len(p)
		}
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

func observeTokenRates(model, node string, elapsed time.Duration, body []byte) {
	if elapsed <= 0 {
		return
	}
	promptTokens, completionTokens, ok := extractUsageTokens(body)
	if !ok {
		return
	}
	seconds := elapsed.Seconds()
	if completionTokens > 0 {
		generationTokensPerSecond.WithLabelValues(model, node).Observe(float64(completionTokens) / seconds)
	}
	if promptTokens > 0 {
		promptTokensPerSecond.WithLabelValues(model, node).Observe(float64(promptTokens) / seconds)
	}
}

func extractUsageTokens(body []byte) (int, int, bool) {
	for _, rawLine := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if prompt, completion, ok := usageTokensFromJSON([]byte(payload)); ok {
			return prompt, completion, true
		}
	}
	return usageTokensFromJSON(body)
}

func usageTokensFromJSON(body []byte) (int, int, bool) {
	var payload struct {
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Usage == nil {
		return 0, 0, false
	}
	return payload.Usage.PromptTokens, payload.Usage.CompletionTokens, true
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
		// Skip nodes whose circuit breaker is open. Allow() is
		// the routing-time check; nodes constructed via test
		// helpers without a breaker fall through (nil-safe).
		if node.breaker != nil && !node.breaker.Allow() {
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

var nodeEnabled = rtr.NodeEnabled

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
	return health.ProbeNode(parent, hc.Timeout.Duration, hc.Path, node.baseURL)
}

var isRetryableConnError = health.IsRetryableConnError

var extractModel = rtr.ExtractModel
var supportsModel = rtr.SupportsModel

var writeJSON = proxy.WriteJSON
var copyHeaders = proxy.CopyHeaders

type flushWriter = proxy.FlushWriter

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
