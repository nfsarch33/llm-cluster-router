package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testCtx returns a background context for direct runHealthPass calls in unit
// tests (the production loop owns cancellation via healthLoop).
func testCtx() context.Context { return context.Background() }

// --- shared fault-injection helpers (used by failover_test + chaos_test) ----

// upstreamBehavior is the deterministic per-request fault the test upstream
// should inject. A zero value means "200 OK with a default body".
type upstreamBehavior struct {
	status     int           // HTTP status to return (0 => 200)
	body       string        // response body (empty => default OK body)
	retryAfter string        // Retry-After header value (set only when non-empty)
	delay      time.Duration // injected latency before responding
}

// programmableUpstream is an OpenAI-compatible httptest server whose
// /v1/chat/completions behaviour is decided by an injected fault hook keyed
// on the (1-based) hit number, giving fully deterministic chaos scenarios.
type programmableUpstream struct {
	*httptest.Server
	name string
	hits atomic.Int64
}

func newProgrammableUpstream(t *testing.T, name, model string, fault func(hit int64) upstreamBehavior) *programmableUpstream {
	t.Helper()
	pu := &programmableUpstream{name: name}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"object":"list","data":[{"id":%q,"object":"model"}]}`, model)
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		hit := pu.hits.Add(1)
		b := fault(hit)
		if b.delay > 0 {
			time.Sleep(b.delay)
		}
		if b.retryAfter != "" {
			w.Header().Set("Retry-After", b.retryAfter)
		}
		status := b.status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if b.body != "" {
			_, _ = fmt.Fprint(w, b.body)
		} else {
			_, _ = fmt.Fprintf(w, `{"id":"x","model":%q,"choices":[{"message":{"role":"assistant","content":%q}}]}`, model, "ok-from-"+name)
		}
	})
	pu.Server = httptest.NewServer(mux)
	t.Cleanup(pu.Close)
	return pu
}

// always returns a fault hook that injects the same behavior on every hit.
func always(b upstreamBehavior) func(int64) upstreamBehavior {
	return func(int64) upstreamBehavior { return b }
}

// newTestNode builds an upstreamNode wired for routing. When threshold>0 a
// per-node breaker is attached (optionally with a fake clock).
func newTestNode(t *testing.T, name, rawURL, tier string, priority, weight int, models []string, breakerThreshold int, cooldown time.Duration, clock func() time.Time) *upstreamNode {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url %q: %v", rawURL, err)
	}
	n := &upstreamNode{
		cfg: nodeConfig{
			Name:     name,
			URL:      rawURL,
			Tier:     tier,
			Priority: priority,
			Weight:   weight,
			Models:   models,
			Enabled:  "true",
		},
		baseURL: parsed,
	}
	n.healthy.Store(true)
	if breakerThreshold > 0 {
		b := newCircuitBreaker(breakerThreshold, cooldown).WithName(name)
		if clock != nil {
			b = b.WithClock(clock)
		}
		n.breaker = b
	}
	return n
}

// newFailoverRouter constructs a minimal router around the supplied nodes.
func newFailoverRouter(nodes []*upstreamNode, timeout time.Duration) *router {
	return &router{
		cfg: config{
			Defaults: defaults{
				MaxQueueDepth:  256,
				MaxConcurrency: 16,
				RequestTimeout: durationValue{Duration: timeout},
				MaxBodySize:    1 << 20,
			},
		},
		client:    &http.Client{Timeout: timeout},
		semaphore: make(chan struct{}, 16),
		nodes:     nodes,
	}
}

// doChat issues a chat-completion request through the router handler and
// returns the recorded status and body.
func doChat(r *router, model string) (int, string) {
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.handleProxy(w, req)
	return w.Code, w.Body.String()
}

// --- unit tests --------------------------------------------------------------

func TestIsFailoverStatus(t *testing.T) {
	t.Parallel()
	cases := map[int]bool{
		http.StatusOK:                  false,
		http.StatusBadRequest:          false,
		http.StatusUnauthorized:        false,
		http.StatusNotFound:            false,
		http.StatusTooManyRequests:     true,
		http.StatusInternalServerError: true,
		http.StatusBadGateway:          true,
		http.StatusServiceUnavailable:  true,
		http.StatusGatewayTimeout:      true,
	}
	for code, want := range cases {
		if got := isFailoverStatus(code); got != want {
			t.Errorf("isFailoverStatus(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestSelectNodeFromSnapExcluding_SkipsExcludedSet(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	a := newTestNode(t, "a", "http://127.0.0.1:9001", "reasoning", 0, 1, []string{model}, 0, 0, nil)
	b := newTestNode(t, "b", "http://127.0.0.1:9002", "reasoning", 0, 1, []string{model}, 0, 0, nil)
	r := &router{nodes: []*upstreamNode{a, b}}
	snap := r.snap()

	excluded := map[string]struct{}{"a": {}}
	got := r.selectNodeFromSnapExcluding(snap, model, "", excluded)
	if got == nil || got.cfg.Name != "b" {
		t.Fatalf("expected node b when a excluded, got %v", got)
	}
	excluded["b"] = struct{}{}
	if got := r.selectNodeFromSnapExcluding(snap, model, "", excluded); got != nil {
		t.Fatalf("expected nil when all nodes excluded, got %s", got.cfg.Name)
	}
}

func TestHandleProxy_FailsOverOn502Response(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	primary := newProgrammableUpstream(t, "primary", model, always(upstreamBehavior{
		status: http.StatusBadGateway, body: `{"error":"m3 saturated"}`,
	}))
	fallback := newProgrammableUpstream(t, "fallback", model, always(upstreamBehavior{}))

	pNode := newTestNode(t, "m3-primary", primary.URL, "reasoning", 0, 1, []string{model}, 5, time.Minute, nil)
	fNode := newTestNode(t, "m3-fallback", fallback.URL, "reasoning", 10, 1, []string{model}, 5, time.Minute, nil)
	r := newFailoverRouter([]*upstreamNode{pNode, fNode}, 5*time.Second)

	code, body := doChat(r, model)
	if code != http.StatusOK {
		t.Fatalf("expected 200 via fallback, got %d body=%s", code, body)
	}
	if !strings.Contains(body, "ok-from-fallback") {
		t.Fatalf("expected fallback body, got %s", body)
	}
	if primary.hits.Load() != 1 || fallback.hits.Load() != 1 {
		t.Fatalf("expected primary=1 fallback=1 hits, got primary=%d fallback=%d", primary.hits.Load(), fallback.hits.Load())
	}
	if pNode.breaker.GetState() != circuitClosed { // 1 failure < threshold 5
		t.Fatalf("primary breaker should still be closed after a single 502, got %s", pNode.breaker.GetState())
	}
}

func TestHandleProxy_FailsOverOn429Response(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	for _, withRetryAfter := range []bool{false, true} {
		name := "no_retry_after"
		ra := ""
		if withRetryAfter {
			name = "with_retry_after"
			ra = "2"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			primary := newProgrammableUpstream(t, "primary", model, always(upstreamBehavior{
				status: http.StatusTooManyRequests, body: `{"error":"rate limited"}`, retryAfter: ra,
			}))
			fallback := newProgrammableUpstream(t, "fallback", model, always(upstreamBehavior{}))
			pNode := newTestNode(t, "m3-primary", primary.URL, "reasoning", 0, 1, []string{model}, 5, time.Minute, nil)
			fNode := newTestNode(t, "m3-fallback", fallback.URL, "reasoning", 10, 1, []string{model}, 5, time.Minute, nil)
			r := newFailoverRouter([]*upstreamNode{pNode, fNode}, 5*time.Second)

			code, body := doChat(r, model)
			if code != http.StatusOK {
				t.Fatalf("expected failover to 200 on 429 (retryAfter=%q), got %d body=%s", ra, code, body)
			}
			if !strings.Contains(body, "ok-from-fallback") {
				t.Fatalf("expected fallback body, got %s", body)
			}
		})
	}
}

func TestHandleProxy_RelaysRealStatusWhenChainExhausted(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	up1 := newProgrammableUpstream(t, "up1", model, always(upstreamBehavior{status: http.StatusBadGateway, body: `{"error":"down-1"}`}))
	up2 := newProgrammableUpstream(t, "up2", model, always(upstreamBehavior{status: http.StatusServiceUnavailable, body: `{"error":"down-2"}`}))
	n1 := newTestNode(t, "n1", up1.URL, "reasoning", 0, 1, []string{model}, 5, time.Minute, nil)
	n2 := newTestNode(t, "n2", up2.URL, "reasoning", 0, 1, []string{model}, 5, time.Minute, nil)
	r := newFailoverRouter([]*upstreamNode{n1, n2}, 5*time.Second)

	code, body := doChat(r, model)
	// The client should see a *real* upstream failover status (502 or 503),
	// not a synthetic one, and the matching upstream body.
	if code != http.StatusBadGateway && code != http.StatusServiceUnavailable {
		t.Fatalf("expected relayed 502/503 when all upstreams fail, got %d body=%s", code, body)
	}
	if !strings.Contains(body, "down-") {
		t.Fatalf("expected a relayed upstream error body, got %s", body)
	}
	// No infinite loop: each upstream is tried at most once.
	if up1.hits.Load() != 1 || up2.hits.Load() != 1 {
		t.Fatalf("expected each upstream tried once, got up1=%d up2=%d", up1.hits.Load(), up2.hits.Load())
	}
}

func TestHandleProxy_NoFailoverOnClientError(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	primary := newProgrammableUpstream(t, "primary", model, always(upstreamBehavior{status: http.StatusBadRequest, body: `{"error":"bad input"}`}))
	fallback := newProgrammableUpstream(t, "fallback", model, always(upstreamBehavior{}))
	pNode := newTestNode(t, "primary", primary.URL, "reasoning", 0, 1, []string{model}, 5, time.Minute, nil)
	fNode := newTestNode(t, "fallback", fallback.URL, "reasoning", 10, 1, []string{model}, 5, time.Minute, nil)
	r := newFailoverRouter([]*upstreamNode{pNode, fNode}, 5*time.Second)

	code, body := doChat(r, model)
	if code != http.StatusBadRequest {
		t.Fatalf("4xx should be relayed without failover, got %d body=%s", code, body)
	}
	if fallback.hits.Load() != 0 {
		t.Fatalf("fallback must not be hit for a 4xx client error, got %d", fallback.hits.Load())
	}
	if pNode.breaker.GetState() != circuitClosed {
		t.Fatalf("a 4xx must not count as a breaker failure, state=%s", pNode.breaker.GetState())
	}
}

// --- self-heal (health-loop) unit tests -------------------------------------

func TestRunHealthPass_SkipsHealthCheckDisabledNode(t *testing.T) {
	t.Parallel()
	// A disabled node pointed at a dead URL must NOT be probed (and so must
	// not be flipped unhealthy by the loop). This documents the footgun:
	// once disabled, the loop can no longer recover it either.
	dead := newTestNode(t, "disabled", "http://127.0.0.1:1", "reasoning", 0, 1, []string{"minimax-m3"}, 0, 0, nil)
	dead.cfg.HealthCheckDisabled = true
	dead.healthy.Store(true)

	r := newFailoverRouter([]*upstreamNode{dead}, time.Second)
	r.cfg.HealthCheck = healthConfig{
		Interval:           durationValue{Duration: time.Second},
		Timeout:            durationValue{Duration: 100 * time.Millisecond},
		Path:               "/health",
		UnhealthyThreshold: 1,
		HealthyThreshold:   1,
	}
	r.runHealthPass(testCtx())
	if !dead.healthy.Load() {
		t.Fatalf("disabled node should be skipped by the probe and keep its prior healthy state")
	}
}

func TestRunHealthPass_RecoversEnabledNodeAfterUpstreamHealthy(t *testing.T) {
	t.Parallel()
	// This is the self-heal contract: with health_check_disabled:false, a node
	// previously marked unhealthy is re-probed and restored once the upstream
	// answers a health check.
	up := newProgrammableUpstream(t, "recovering", "minimax-m3", always(upstreamBehavior{}))
	node := newTestNode(t, "m3", up.URL, "reasoning", 0, 1, []string{"minimax-m3"}, 0, 0, nil)
	node.healthy.Store(false) // simulate a prior transport-error trip

	r := newFailoverRouter([]*upstreamNode{node}, time.Second)
	r.cfg.HealthCheck = healthConfig{
		Interval:           durationValue{Duration: time.Second},
		Timeout:            durationValue{Duration: time.Second},
		Path:               "/health",
		UnhealthyThreshold: 1,
		HealthyThreshold:   1,
	}
	r.runHealthPass(testCtx())
	if !node.healthy.Load() {
		t.Fatalf("enabled node should self-heal back to healthy after a successful probe")
	}
}
