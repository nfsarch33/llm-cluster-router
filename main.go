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
	"log/slog"
	"math"
	"net"
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
	"github.com/nfsarch33/llm-cluster-router/internal/fairshare"
	"github.com/nfsarch33/llm-cluster-router/internal/gpuprobe"
	"github.com/nfsarch33/llm-cluster-router/internal/health"
	"github.com/nfsarch33/llm-cluster-router/internal/keypool"
	"github.com/nfsarch33/llm-cluster-router/internal/metrics"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
	"github.com/nfsarch33/llm-cluster-router/internal/quota"
	"github.com/nfsarch33/llm-cluster-router/internal/relcheck"
	rtr "github.com/nfsarch33/llm-cluster-router/internal/router"
	"github.com/nfsarch33/llm-cluster-router/internal/smartroute"
	"github.com/nfsarch33/llm-cluster-router/internal/tunnel"
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
	cfg           config
	client        *http.Client
	semaphore     chan struct{}
	nodes         []*upstreamNode
	fairScheduler *fairshare.Scheduler
	smart         *smartroute.Router

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
	smart     *smartroute.Router
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
		smart:     r.smart,
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
	smart, err := loadSmartRoute(cfg)
	if err != nil {
		return fmt.Errorf("router reload: %w", err)
	}
	r.mu.Lock()
	r.cfg = cfg
	r.nodes = nodes
	r.client = client
	r.semaphore = sem
	r.smart = smart
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
// loadSmartRoute builds the optional smartroute router from config. A
// disabled feature or empty policy path returns nil, which every call site
// treats as pass-through — misconfiguration fails loudly at boot/reload
// instead of silently misrouting traffic.
func loadSmartRoute(c config) (*smartroute.Router, error) {
	if !c.SmartRoute.Enabled || c.SmartRoute.PolicyFile == "" {
		return nil, nil
	}
	p, err := smartroute.LoadPolicy(c.SmartRoute.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("smart_route: %w", err)
	}
	return smartroute.NewRouter(p), nil
}

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
		node.keys = keypool.New(nc.APIKeys, cfg.Defaults.KeyCooldown.Duration)
		node.quotaDet = quota.New(nc.QuotaDetectRegex,
			os.Getenv("LLM_ROUTER_SLACK_WEBHOOK_URL"), cfg.SlackChannel, slog.Default())
		ctThreshold, ctCooldown := nc.ResolvedCircuit(cfg.Defaults)
		node.breaker = newCircuitBreaker(ctThreshold, ctCooldown).WithName(nc.Name)
		nodeHealthyGauge.WithLabelValues(nc.Name, nc.Tier).Set(1)
		if nc.Tunnel.Enabled {
			// Capture the runtime config in the closure so each
			// node's transport dials through its own SSH jump,
			// not someone else's. The transport reuses the same
			// Timeout / Idle settings as the router-wide client
			// for symmetry.
			rt, err := nc.Tunnel.ToRuntime()
			if err != nil {
				return nil, nil, nil, fmt.Errorf("tunnel config on node %s: %w", nc.Name, err)
			}
			sshCfg := tunnel.SSHTunnelConfig{
				Host:           rt.Host,
				Port:           rt.Port,
				User:           rt.User,
				IdentityFile:   rt.IdentityFile,
				LocalPort:      rt.LocalPort,
				ConnectTimeout: rt.ConnectTimeout,
			}
			dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tunnel.DialContext(ctx, sshCfg, network, addr)
			}
			node.tunnelClient = &http.Client{
				Timeout: cfg.Defaults.RequestTimeout.Duration,
				Transport: &http.Transport{
					DialContext:         dial,
					MaxIdleConns:        20,
					MaxIdleConnsPerHost: 4,
					IdleConnTimeout:     30 * time.Second,
				},
			}
		}
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

	// keys rotates api_keys with per-key quota cooldowns (nil-safe; empty
	// pool falls back to the single api_key path).
	keys *keypool.Pool
	// quotaDet matches vendor quota-exhaustion bodies (quota_detect_regex);
	// nil when the node has no pattern configured.
	quotaDet *quota.Detector

	// breaker is the per-upstream circuit breaker. It is
	// consulted by selectNodeFromSnap so an upstream that is
	// returning errors faster than the slower health-check loop
	// notices is removed from rotation immediately. Threshold and
	// cooldown come from config (defaults.circuit, with optional
	// per-node overrides), defaulting to 5 failures / 30s when unset.
	breaker *circuitBreaker

	// tunnelClient, when non-nil, sends this node's outbound
	// traffic through the configured SSH jump (see internal/tunnel).
	// nil means "no tunnel; route via the router-wide http.Client
	// just like every other non-tunnelled node".
	tunnelClient *http.Client
}

// sshtunnelRuntime is the runtime mirror of config.TunnelConfig,
// constructed only when the operator sets tunnel.enabled:true on a
// node. Keeping the alias here avoids exporting the runtime type from
// the config package for callers that only need to pass it to the
// tunnel package.
type sshtunnelRuntime = cfg.SSHTunnelRuntime

// nextAPIKey returns the next API key via round-robin when multiple
// keys are configured (api_keys), falls back to the single api_key,
// or returns "" when no key is set.
func (n *upstreamNode) nextAPIKey() string {
	k, _ := n.nextAPIKeyIdx()
	return k
}

// nextAPIKeyIdx returns the key plus its pool index (-1 for the single-key
// path) so quota handling can cool exactly the key that hit the wall.
func (n *upstreamNode) nextAPIKeyIdx() (string, int) {
	if n.keys != nil && n.keys.Size() > 0 {
		return n.keys.Next()
	}
	if len(n.cfg.APIKeys) > 0 { // node built outside buildReloadable (tests)
		idx := n.keyIdx.Add(1) - 1
		return n.cfg.APIKeys[idx%uint64(len(n.cfg.APIKeys))], int(idx % uint64(len(n.cfg.APIKeys)))
	}
	return n.cfg.APIKey, -1
}

type (
	gpuProcess     = gpuprobe.Process
	gpuSnapshot    = gpuprobe.Snapshot
	gpuProbeReport = gpuprobe.Report
)

// Metric aliases bridge the metrics package vars back into package
// main so all existing code compiles unchanged.
var (
	llmRouterBuckets          = metrics.LLMRouterBuckets
	routerTokenRateBuckets    = metrics.RouterTokenRateBuckets
	requestsTotal             = metrics.RequestsTotal
	quotaFallbackTotal        = metrics.QuotaFallbackTotal
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
	fairShareRejectedTotal    = metrics.FairShareRejectedTotal
)

// Keep bridge aliases referenced for golangci-lint unused check.
var (
	_ = llmRouterBuckets
	_ = routerTokenRateBuckets
	_ = forbiddenUpstreamHostSuffixes
	_ = validateUpstreamURL
)

// buildVersion is stamped by the Makefile via
// -ldflags "-X main.buildVersion=$(git describe --tags --always --dirty)".
// "dev" (unstamped local builds) exempts the binary from release-check
// warnings and from any network probe.
var buildVersion = "dev"

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
	//
	// Wire the auth-reject hook so the proxy package can emit
	// llm_router_auth_rejected_total without importing internal/metrics.
	proxy.SetAuthRejectHook(func(path string) {
		metrics.AuthRejectedTotal.WithLabelValues(path).Inc()
	})
	authWrap := bearerAuthFunc(r.AuthToken)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", r.handleHealth)
	mux.HandleFunc("/health", r.handleHealth)
	mux.HandleFunc("/readyz", r.handleReadyz) // q10b-8: readiness gate (kubelet/sentrux)
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

	// v18712-2: select the ListenerFactory via the canonical
	// selector. HELIXCHANNEL_ENABLED=true (default) wires the
	// AES/mTLS factory that fronts every router deployment;
	// setting HELIXCHANNEL_ENABLED=false keeps the legacy plain
	// HTTP listener for back-compat. See ADR-085.
	enabled := helixChannelEnabledFromEnv()
	factory := proxy.SelectListenerFactory(enabled)
	log.Printf("router listener channel=%s helixchannel_enabled=%t", factory.Channel(), enabled)

	ln, _, err := factory.Listen(context.Background(), cfg.Listen)
	if err != nil {
		return fmt.Errorf("listener bind: %w", err)
	}
	defer ln.Close()

	// Fleet rule: every distributed tool self-checks its version and WARNS
	// (never blocks) when a newer tag exists. Async + cached + 6s budget.
	go relcheck.WarnIfOutdated(slog.Default(), "nfsarch33", "llm-cluster-router", buildVersion)
	log.Printf("router listening on %s", cfg.Listen)
	return server.Serve(ln)
}

// helixChannelEnabledFromEnv reads the HELIXCHANNEL_ENABLED env
// var and returns true when the AES/mTLS factory should be used.
// The default is true (HelixChannel on by default for v18712+);
// set HELIXCHANNEL_ENABLED=false to opt out and use the legacy
// plain HTTP listener. Empty/unset values default to true.
//
// Parsing is intentionally tolerant: any value other than
// case-insensitive "false", "0", or "no" is treated as enabled.
func helixChannelEnabledFromEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("HELIXCHANNEL_ENABLED")))
	switch v {
	case "", "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
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
	r := &router{
		cfg:       cfg,
		client:    client,
		semaphore: sem,
		nodes:     nodes,
	}
	smart, err := loadSmartRoute(cfg)
	if err != nil {
		return nil, err
	}
	r.smart = smart
	if cfg.FairShare.Enabled {
		r.fairScheduler = fairshare.New(fairshare.Config{
			MaxRequestsPerUser: cfg.FairShare.MaxRequestsPerUser,
			Window:             cfg.FairShare.Window.Duration,
			Burst:              cfg.FairShare.Burst,
		})
	}
	return r, nil
}

var limitBody = proxy.LimitBody

func (r *router) handleHealth(w http.ResponseWriter, req *http.Request) {
	type nodeStatus struct {
		Name    string   `json:"name"`
		Tier    string   `json:"tier"`
		URL     string   `json:"url"`
		Models  []string `json:"models"`
		Healthy bool     `json:"healthy"`
		ProbeMs int64    `json:"probe_ms,omitempty"`
	}
	// q4-c-lcr-stale-health (Q5 Phase 6): allow caller to force a live
	// probe so /healthz reports fresh upstream state, not the cached
	// `node.healthy` flag updated only every hc.Interval (default 30s).
	//   ?live=1            -> probe each node now
	//   ?timeout=500ms     -> per-node probe timeout (default 2s)
	live := req.URL.Query().Get("live") == "1"
	probeTimeout := 2 * time.Second
	if v := req.URL.Query().Get("timeout"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 10*time.Second {
			probeTimeout = d
		}
	}
	hc := r.snap().cfg.HealthCheck
	snap := r.snap()
	nodes := make([]nodeStatus, 0, len(snap.nodes))
	healthy := 0
	for _, node := range snap.nodes {
		var ok bool
		var probeMs int64
		if live && !node.cfg.HealthCheckDisabled {
			probeCtx, cancel := context.WithTimeout(req.Context(), probeTimeout)
			startProbe := time.Now()
			ok = probeNode(probeCtx, hc, node)
			cancel()
			probeMs = time.Since(startProbe).Milliseconds()
		} else {
			ok = node.healthy.Load()
		}
		if ok {
			healthy++
		}
		nodes = append(nodes, nodeStatus{
			Name:    node.cfg.Name,
			Tier:    node.cfg.Tier,
			URL:     node.cfg.URL,
			Models:  node.cfg.Models,
			Healthy: ok,
			ProbeMs: probeMs,
		})
	}

	resp := map[string]any{
		"ok":                healthy > 0,
		"healthy_nodes":     healthy,
		"total_nodes":       len(snap.nodes),
		"queue_depth":       r.queueDepth.Load(),
		"inflight_requests": r.inflight.Load(),
		"max_queue_depth":   snap.cfg.Defaults.MaxQueueDepth,
		"max_concurrency":   snap.cfg.Defaults.MaxConcurrency,
		"nodes":             nodes,
	}
	if live {
		resp["live_probe"] = true
		resp["probe_timeout"] = probeTimeout.String()
	}
	writeJSON(w, http.StatusOK, resp)
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

// maxFailoverAttempts bounds how many distinct upstreams a single request may
// try before giving up. The exclude-set already guarantees each upstream is
// tried at most once per request, so this is a belt-and-braces ceiling that
// makes "no infinite loop" hold even if selection logic regresses.
const maxFailoverAttempts = 5

// isFailoverStatus reports whether an upstream HTTP status should trigger
// failover to the next node in the chain (and count as a breaker failure).
// 429 (rate-limited) and any 5xx (502/503 capacity, 500 upstream error) mean
// "this upstream cannot serve the request right now"; a 4xx other than 429 is
// the caller's fault (bad input) and is relayed back without failover.
func isFailoverStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// doUpstream issues the proxied request to a single node and returns the raw
// upstream response (caller owns Body.Close) or a transport error. It applies
// the existing one-shot transparent retry for idle-connection resets so a
// stale keep-alive conn does not look like a node failure. The per-node API
// key (single or round-robin) is attached here.
func (r *router) doUpstream(ctx context.Context, snap routerSnap, node *upstreamNode, method, reqPath, rawQuery string, srcHeader http.Header, body []byte, model string) (*http.Response, int, error) {
	upstreamURL := *node.baseURL
	upstreamURL.Path = strings.TrimRight(node.baseURL.Path, "/") + reqPath
	upstreamURL.RawQuery = rawQuery

	usedKeyIdx := -1
	build := func() (*http.Request, error) {
		ureq, err := http.NewRequestWithContext(ctx, method, upstreamURL.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		copyHeaders(ureq.Header, srcHeader)
		if key, kidx := node.nextAPIKeyIdx(); key != "" {
			ureq.Header.Set("Authorization", "Bearer "+key)
			usedKeyIdx = kidx
		}
		return ureq, nil
	}

	ureq, err := build()
	if err != nil {
		return nil, usedKeyIdx, err
	}
	// Per-node tunnel client (configured via node.tunnel.enabled)
	// carries the node-specific SSH identity; when set, route through
	// it instead of the shared router-wide client. The node-level
	// Timeout/Transport settings mirror the router-wide ones so a
	// failure mode looks identical to the operator regardless of
	// whether the leg was tunnelled or direct.
	client := snap.client
	if node.tunnelClient != nil {
		client = node.tunnelClient
	}
	resp, err := client.Do(ureq)
	if err != nil && isRetryableConnError(err) {
		requestRetries.WithLabelValues(model, node.cfg.Name).Inc()
		if retryReq, rerr := build(); rerr == nil {
			resp, err = client.Do(retryReq)
		}
	}
	return resp, usedKeyIdx, err
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

	tier := req.Header.Get("X-Tier")
	if snap.smart != nil {
		agent := smartroute.DetectAgent(req)
		if !snap.smart.AgentAllowed(agent) {
			http.Error(w, fmt.Sprintf("route disabled for agent %q by smartroute policy", agent), http.StatusForbidden)
			requestsTotal.WithLabelValues(extractModel(body), "none", "agent_disabled").Inc()
			return
		}
		if d, derr := snap.smart.Decide(req, body); derr == nil {
			if nb, rerr := snap.smart.Rewrite(body, d); rerr == nil {
				body = nb
			}
			if tier == "" {
				tier = d.Tier
			}
		}
	}
	model := extractModel(body)
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

	if r.fairScheduler != nil {
		user := req.Header.Get("X-User")
		if user == "" {
			auth := req.Header.Get("Authorization")
			token := strings.TrimPrefix(auth, "Bearer ")
			user = fairshare.UserFromToken(token)
		}
		if user != "" && !r.fairScheduler.Acquire(user) {
			fairShareRejectedTotal.WithLabelValues(user).Inc()
			http.Error(w, `{"error":"per-user rate limit exceeded"}`, http.StatusTooManyRequests)
			requestsTotal.WithLabelValues(model, node.cfg.Name, "fairshare_rejected").Inc()
			return
		}
		if user != "" {
			defer r.fairScheduler.Release(user)
		}
	}

	r.inflight.Add(1)
	inflightGauge.Set(float64(r.inflight.Load()))
	defer func() {
		r.inflight.Add(-1)
		inflightGauge.Set(float64(r.inflight.Load()))
	}()

	// Tier-aware failover loop. Each iteration tries one upstream and, on a
	// transport error OR a failover-worthy status (429 / 5xx), records a
	// breaker failure and advances to the next untried candidate down the
	// priority-ordered chain (M3-key1 -> M3-key2 -> fallback tier). The
	// exclude-set guarantees each upstream is tried at most once; the
	// maxFailoverAttempts ceiling guarantees the loop always terminates.
	//
	// Each attempt gets its OWN request-timeout context (derived from the
	// client's context) rather than sharing one budget across the whole
	// chain. This is what lets a request fail over after a primary *timeout*:
	// a shared, already-expired deadline would make every downstream attempt
	// fail instantly. The cancel for whichever response we ultimately stream
	// is deferred so its body stays readable during streaming; losing
	// attempts' contexts are cancelled immediately.
	//
	// We only fail over BEFORE any bytes are written to the client, so a
	// healthy upstream's stream is never interrupted. If every candidate
	// fails, the last real upstream response (e.g. a genuine 502) is relayed
	// so the caller sees the true status instead of a synthetic one.
	tried := make(map[string]struct{}, maxFailoverAttempts)
	var (
		okResp     *http.Response // a non-failover (servable) upstream response
		okNode     *upstreamNode
		okCancel   context.CancelFunc
		heldResp   *http.Response // most recent failover-status response, relayed if chain exhausts
		heldNode   *upstreamNode
		heldCancel context.CancelFunc
		lastErr    error
		candidate  = node
		attemptIdx int
	)
	for ; candidate != nil && attemptIdx < maxFailoverAttempts; attemptIdx++ {
		tried[candidate.cfg.Name] = struct{}{}
		attemptCtx, attemptCancel := context.WithTimeout(req.Context(), snap.cfg.Defaults.RequestTimeout.Duration)
		resp, usedKeyIdx, err := r.doUpstream(attemptCtx, snap, candidate, req.Method, req.URL.Path, req.URL.RawQuery, req.Header, body, model)
		if err != nil {
			attemptCancel()
			// Self-heal: only the health loop can flip `healthy` back to true.
			// For a node with health_check_disabled (e.g. a bridge with no
			// /health endpoint) the loop is skipped, so storing healthy=false
			// here would strand it forever — the original "never recovers"
			// bug. In that case we rely solely on the circuit breaker, which
			// self-recovers via a half-open probe after its cooldown. Probed
			// nodes keep the fast-eject behaviour (the loop will restore them).
			if !candidate.cfg.HealthCheckDisabled {
				candidate.healthy.Store(false)
				nodeHealthyGauge.WithLabelValues(candidate.cfg.Name, candidate.cfg.Tier).Set(0)
			}
			if candidate.breaker != nil {
				candidate.breaker.RecordFailure()
			}
			lastErr = err
			next := r.selectNodeFromSnapExcluding(snap, model, tier, tried)
			if next != nil {
				requestRetries.WithLabelValues(model, candidate.cfg.Name).Inc()
			}
			candidate = next
			continue
		}
		if isFailoverStatus(resp.StatusCode) {
			// Key-level quota isolation: a 429 (or a vendor body matching
			// quota_detect_regex) cools only the key that served the attempt.
			// The response body is peeked with a bounded read and restored,
			// so a held response can still be relayed if the chain exhausts.
			quotaHit := resp.StatusCode == http.StatusTooManyRequests
			if candidate.quotaDet != nil {
				peek, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				resp.Body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(peek), resp.Body), resp.Body}
				if candidate.quotaDet.Matches(peek) {
					quotaHit = true
					quotaFallbackTotal.WithLabelValues(model, candidate.cfg.Name, candidate.cfg.Vendor).Inc()
					candidate.quotaDet.Notify(model, candidate.cfg.Name, candidate.cfg.Vendor, peek)
				}
			}
			if quotaHit && usedKeyIdx >= 0 && candidate.keys != nil {
				candidate.keys.MarkExhausted(usedKeyIdx)
				// Only score the NODE breaker when every key is cooling —
				// one dead plan must not evict a node with healthy plans.
				if !candidate.keys.AllCooling() {
					requestsTotal.WithLabelValues(model, candidate.cfg.Name, "key_cooled_"+strconv.Itoa(resp.StatusCode)).Inc()
					if heldResp != nil {
						heldResp.Body.Close()
						heldCancel()
					}
					heldResp, heldNode, heldCancel = resp, candidate, attemptCancel
					lastErr = nil
					// Retry the SAME node once more on the next healthy key
					// by not adding it to the exclude set this pass.
					delete(tried, candidate.cfg.Name)
					next := r.selectNodeFromSnapExcluding(snap, model, tier, tried)
					tried[candidate.cfg.Name] = struct{}{}
					if next != nil && next.cfg.Name == candidate.cfg.Name {
						requestRetries.WithLabelValues(model, candidate.cfg.Name).Inc()
						candidate = next
						continue
					}
				}
			}
			if candidate.breaker != nil {
				candidate.breaker.RecordFailure()
			}
			requestsTotal.WithLabelValues(model, candidate.cfg.Name, "failover_"+strconv.Itoa(resp.StatusCode)).Inc()
			if heldResp != nil {
				heldResp.Body.Close()
				heldCancel()
			}
			heldResp, heldNode, heldCancel = resp, candidate, attemptCancel
			lastErr = nil
			next := r.selectNodeFromSnapExcluding(snap, model, tier, tried)
			if next != nil {
				requestRetries.WithLabelValues(model, candidate.cfg.Name).Inc()
			}
			candidate = next
			continue
		}
		okResp, okNode, okCancel = resp, candidate, attemptCancel
		if candidate.breaker != nil {
			candidate.breaker.RecordSuccess()
		}
		break
	}

	var resp *http.Response
	switch {
	case okResp != nil:
		node, resp = okNode, okResp
		defer okCancel()
		if heldResp != nil {
			heldResp.Body.Close()
			heldCancel()
		}
	case heldResp != nil:
		// Chain exhausted with no healthy upstream; relay the real upstream
		// response (true status + body) rather than a synthetic error.
		node, resp = heldNode, heldResp
		defer heldCancel()
	default:
		// Every candidate failed at the transport layer.
		http.Error(w, fmt.Sprintf("upstream request failed: %v", lastErr), http.StatusBadGateway)
		requestsTotal.WithLabelValues(model, node.cfg.Name, "bad_gateway").Inc()
		return
	}
	defer func() { _ = resp.Body.Close() }()

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
	// Breaker success/failure is recorded inside the failover loop above
	// (every attempt's outcome is scored exactly once), so we do not
	// re-score the relayed response here — doing so would double-count.
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
	var excluded map[string]struct{}
	if excludeName != "" {
		excluded = map[string]struct{}{excludeName: {}}
	}
	return r.selectNodeFromSnapExcluding(snap, model, targetTier, excluded)
}

// selectNodeFromSnapExcluding is the set-aware form of node selection used by
// the multi-hop failover loop in handleProxy. It applies the same
// health/breaker/tier/model filters and priority-bucket + weighted
// round-robin selection as selectNodeFromSnap, but skips every node whose
// name is in `excluded`. This lets a request walk the ordered fallback chain
// (e.g. minimax-m3-key1 -> minimax-m3-key2 -> local-gpu fallback) without
// re-trying an upstream that already failed for this request. Lower-priority
// buckets are only consulted once every node in a higher-priority bucket is
// either unhealthy, breaker-open, or already excluded — which is exactly how
// the strict M3 -> fallback ordering is expressed in config (M3 keys share the
// lowest priority; the fallback tier sits at a higher priority number).
func (r *router) selectNodeFromSnapExcluding(snap routerSnap, model, targetTier string, excluded map[string]struct{}) *upstreamNode {
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
		if _, skip := excluded[node.cfg.Name]; skip {
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
		// Self-heal: a node with health_check_disabled:true is never
		// re-probed, so once the proxy marks it unhealthy on a transient
		// error it can never recover until a restart. Skipping it here is
		// the documented (discouraged) behaviour; the breaker still governs
		// routing for these nodes. Leave the flag false so the loop below
		// flips healthy back to true after the upstream recovers.
		if node.cfg.HealthCheckDisabled {
			continue
		}
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

var collectGPUSnapshots = gpuprobe.CollectSnapshots

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

var parseGPUCSV = gpuprobe.ParseGPUCSV
var parseComputeAppsCSV = gpuprobe.ParseComputeAppsCSV
var attachGPUProcesses = gpuprobe.AttachProcesses

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
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
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
			_ = resp.Body.Close()
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
	defer func() { _ = resp.Body.Close() }()
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

// quotaDetectorForNode returns a quota.Detector for the given node, or nil
// if the node has no quota pattern configured. The webhook URL/channel are
// resolved from the global config. The helper is package-private so callers
// can simply call quotaDetectorForNode(snap.cfg, node.cfg) before invoking
// detector.Notify.
var _ = quota.New

// Ready evaluates the canonical readiness contract for the router.
//
//   - At least one upstream must be healthy (healthy_nodes >= 1).
//   - The current queue depth must be at or below the configured
//     ceiling (queue_depth <= Defaults.MaxQueueDepth).
//   - No breaker on any upstream may currently be Open
//     (otherwise the router would return errors to callers even
//     though /healthz might still claim "ok").
//
// Returns (ready bool, reason string). When ready=true the reason
// is empty; otherwise the reason explains which gate failed so
// /readyz callers (kubelet, sentrux, load balancers) can render a
// useful operator message.
//
// Added by q10b-8 to GREEN the Ginkgo spec in readyz_ginkgo_test.go.
// Pure function: takes only r.snap() and atomic counters, no mutex
// promotion; safe for concurrent invocation from many probe goroutines.
func (r *router) Ready() (bool, string) {
	snap := r.snap()
	healthy := 0
	for _, node := range snap.nodes {
		if node.healthy.Load() {
			healthy++
		}
	}
	if healthy == 0 {
		return false, "no healthy upstream nodes"
	}

	maxQD := int64(snap.cfg.Defaults.MaxQueueDepth)
	if cur := r.queueDepth.Load(); cur > maxQD {
		return false, fmt.Sprintf("queue depth %d exceeds ceiling %d", cur, maxQD)
	}

	for _, node := range snap.nodes {
		if node.breaker != nil && node.breaker.Stats().State == circuitOpen {
			return false, fmt.Sprintf("upstream %q breaker is open", node.cfg.Name)
		}
	}

	return true, ""
}

// handleReadyz exposes the readiness gate over /readyz. Returns 200
// when Ready() reports true, 503 otherwise. JSON body always carries
// {ready, reason} so probes can log without parsing free-text.
//
// Added by q10b-8.
func (r *router) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	ready, reason := r.Ready()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"ready":  ready,
		"reason": reason,
	})
}
