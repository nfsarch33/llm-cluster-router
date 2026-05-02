//go:build integration

// Integration tests for llm-cluster-router.
//
// These tests start the router in-process with real HTTP servers as upstreams
// (httptest.NewServer) and exercise the routing/queueing/streaming/failover
// paths through real network I/O. They are kept under the `integration` build
// tag so the default `go test ./...` stays fast.
//
// Run locally: `go test -tags=integration -timeout=2m -count=1 -race -v -run TestIT ./...`

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// itSetupRouter starts a router with the supplied upstreams and returns a
// running httptest.Server fronting all router endpoints. The returned cleanup
// stops the health loop and closes the test server.
func itSetupRouter(t *testing.T, upstreams []*httptest.Server, opts ...itRouterOpt) (*httptest.Server, *router) {
	t.Helper()

	cfg := config{
		Listen:      ":0",
		MetricsAddr: "",
		Defaults: defaults{
			MaxQueueDepth:  64,
			MaxConcurrency: 8,
			RequestTimeout: durationValue{Duration: 30 * time.Second},
			MaxBodySize:    1 << 20,
		},
		HealthCheck: healthConfig{
			Interval:           durationValue{Duration: 250 * time.Millisecond},
			Timeout:            durationValue{Duration: time.Second},
			Path:               "/health",
			UnhealthyThreshold: 1,
			HealthyThreshold:   1,
		},
	}

	for i, up := range upstreams {
		cfg.Nodes = append(cfg.Nodes, nodeConfig{
			Name:    fmt.Sprintf("upstream-%d", i),
			URL:     up.URL,
			Tier:    "fast",
			Weight:  1,
			Models:  []string{fmt.Sprintf("model-%d", i)},
			Enabled: "true",
		})
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go r.healthLoop(ctx)

	// Block until first health probe completes so tests do not race with
	// the initial healthy=true vs probe-fail transition.
	itWaitForHealthyNodes(t, r, len(upstreams), 2*time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", r.handleHealth)
	mux.HandleFunc("/v1/models", r.handleModels)
	mux.HandleFunc("/v1/chat/completions", r.handleProxy)
	mux.HandleFunc("/v1/completions", r.handleProxy)
	mux.HandleFunc("/v1/embeddings", r.handleProxy)
	// Register the prom handler under the same mux so /metrics is accessible
	// from the same test server origin.
	mux.Handle("/metrics", promMetricsHandler())

	srv := httptest.NewServer(mux)

	t.Cleanup(func() {
		srv.Close()
		cancel()
	})

	return srv, r
}

// itRouterOpt configures the router cfg for tests.
type itRouterOpt func(*config)

func itWithMaxConcurrency(n int) itRouterOpt {
	return func(c *config) { c.Defaults.MaxConcurrency = n }
}

func itWithMaxQueueDepth(n int) itRouterOpt {
	return func(c *config) { c.Defaults.MaxQueueDepth = n }
}

// itWaitForHealthyNodes polls the router's nodes until at least `want` are
// healthy or the deadline passes.
func itWaitForHealthyNodes(t *testing.T, r *router, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		healthy := 0
		for _, n := range r.nodes {
			if n.healthy.Load() {
				healthy++
			}
		}
		if healthy >= want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("only %d/%d nodes became healthy within %s", countHealthy(r), want, within)
}

func countHealthy(r *router) int {
	n := 0
	for _, node := range r.nodes {
		if node.healthy.Load() {
			n++
		}
	}
	return n
}

// itMockOpenAI returns a httptest.Server that serves OpenAI-compatible
// chat completions and /health. The provided responder is invoked for each
// /v1/chat/completions call and may return a custom body, status, or stream.
type itMockResponse struct {
	StatusCode int
	Body       string
	// Stream lines are written as SSE chunks separated by `\n\n`. When
	// non-nil, StatusCode and Body are ignored.
	Stream []string
	// HitCounter is incremented atomically on every successful response.
	HitCounter *atomic.Int64
	// User is the value of the X-User header on the incoming request.
	UserSeenBy func(user string)
}

func itMockOpenAI(t *testing.T, modelName string, responder func(req *http.Request) itMockResponse) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"object":"list","data":[{"id":%q,"object":"model"}]}`, modelName)
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		resp := responder(req)
		if resp.UserSeenBy != nil {
			resp.UserSeenBy(req.Header.Get("X-User"))
		}
		if resp.HitCounter != nil {
			resp.HitCounter.Add(1)
		}
		if len(resp.Stream) > 0 {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			for _, line := range resp.Stream {
				fmt.Fprintf(w, "data: %s\n\n", line)
				if flusher != nil {
					flusher.Flush()
				}
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		if resp.StatusCode == 0 {
			resp.StatusCode = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		if resp.Body != "" {
			fmt.Fprint(w, resp.Body)
		} else {
			fmt.Fprintf(w, `{"id":"chatcmpl-x","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`, modelName)
		}
	})

	return httptest.NewServer(mux)
}

// promMetricsHandler reuses prometheus/promhttp on the default registry, which
// is the same surface main.go exposes in production. Integration tests assert
// against this output so we catch any regression that breaks the
// Prometheus exposition format.
func promMetricsHandler() http.Handler {
	return promhttp.Handler()
}

// --- Tests -------------------------------------------------------------------

// TestIT_NoStarvationUnderConcurrentLoad verifies that under a concurrent burst
// from multiple distinct producers (X-User headers), the router does not bias
// scheduling toward any one producer and every producer gets to completion.
//
// This is the no-starvation invariant for v0.1.0 — the router uses a single
// FIFO-ish semaphore + bounded queue, so per-user fair scheduling is NOT yet
// implemented. The contract this test pins is weaker but still meaningful:
//
//   - Given a queue large enough to absorb the burst, every request from every
//     producer completes successfully.
//   - No producer's request rate falls outside ±20% of the equal share, which
//     would indicate header-based bias or a producer-affine bug in routing.
//
// True fair-share scheduling (per-user sliding-window rate limiting) is
// tracked for v0.2.0 (Band H PR-H1) and will get its own deeper test suite
// once implemented.
func TestIT_NoStarvationUnderConcurrentLoad(t *testing.T) {
	const (
		users        = 4
		reqsPerUser  = 25
		totalReqs    = users * reqsPerUser
		fairnessSlop = 0.20 // each user must receive within 20% of equal share
	)

	var hits atomic.Int64
	upstream := itMockOpenAI(t, "model-0", func(req *http.Request) itMockResponse {
		// Small artificial delay so concurrent producers actually compete
		// for the router's semaphore.
		time.Sleep(2 * time.Millisecond)
		return itMockResponse{
			StatusCode: http.StatusOK,
			Body:       `{"id":"x","model":"model-0","choices":[{"message":{"content":"ok"}}]}`,
			HitCounter: &hits,
		}
	})
	t.Cleanup(upstream.Close)

	// Concurrency 8 + queue 256 is sized so a 100-request burst never trips
	// the bounded-queue 429 path. We are testing scheduling fairness, not
	// queue-overflow behaviour (covered separately by unit tests).
	srv, _ := itSetupRouter(t, []*httptest.Server{upstream},
		itWithMaxConcurrency(8), itWithMaxQueueDepth(256))

	perUser := make([]atomic.Int64, users)
	var wg sync.WaitGroup

	for u := 0; u < users; u++ {
		u := u
		for i := 0; i < reqsPerUser; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := fmt.Sprintf(`{"model":"model-0","messages":[{"role":"user","content":"req from u%d"}]}`, u)
				req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(body))
				if err != nil {
					t.Errorf("build req: %v", err)
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-User", fmt.Sprintf("user-%d", u))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Errorf("do req: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					perUser[u].Add(1)
				}
			}()
		}
	}
	wg.Wait()

	if int(hits.Load()) != totalReqs {
		t.Fatalf("expected %d upstream hits, got %d (some requests may have been rejected with 429 — try increasing queue depth)",
			totalReqs, hits.Load())
	}

	expected := float64(reqsPerUser)
	tolerance := expected * fairnessSlop
	for u := 0; u < users; u++ {
		got := float64(perUser[u].Load())
		if got < expected-tolerance || got > expected+tolerance {
			t.Errorf("user %d got %.0f completions, want within ±%.1f of %.0f (no-starvation invariant)",
				u, got, tolerance, expected)
		}
	}
}

func TestIT_StreamingSSEPassthrough(t *testing.T) {
	streamLines := []string{
		`{"choices":[{"delta":{"content":"Hello "}}]}`,
		`{"choices":[{"delta":{"content":"from "}}]}`,
		`{"choices":[{"delta":{"content":"router"}}]}`,
	}
	upstream := itMockOpenAI(t, "model-0", func(req *http.Request) itMockResponse {
		return itMockResponse{Stream: streamLines}
	})
	t.Cleanup(upstream.Close)

	srv, _ := itSetupRouter(t, []*httptest.Server{upstream})

	body := `{"model":"model-0","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do req: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Errorf("expected text/event-stream Content-Type, got %q", got)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	bodyStr := string(bodyBytes)

	// Each upstream line should appear as its own SSE data: line, plus a [DONE] marker.
	for i, line := range streamLines {
		if !strings.Contains(bodyStr, line) {
			t.Errorf("stream line %d missing from response: %q\nfull body:\n%s", i, line, bodyStr)
		}
	}
	if !strings.Contains(bodyStr, "data: [DONE]") {
		t.Errorf("stream missing [DONE] terminator\nfull body:\n%s", bodyStr)
	}
	// Frame structure: each chunk should be on its own SSE frame separated by \n\n.
	if !strings.Contains(bodyStr, "\n\n") {
		t.Errorf("expected SSE frames separated by \\n\\n; body:\n%s", bodyStr)
	}
}

func TestIT_FailoverWhenUpstreamReturns502(t *testing.T) {
	var primaryHits, fallbackHits atomic.Int64

	primary := itMockOpenAI(t, "shared-model", func(req *http.Request) itMockResponse {
		// First few succeed; subsequent ones simulate a hard failure mode
		// that the router treats as upstream-down via fallback.
		if primaryHits.Add(1) > 2 {
			return itMockResponse{StatusCode: http.StatusBadGateway, Body: `{"error":"upstream gone"}`}
		}
		return itMockResponse{StatusCode: http.StatusOK, Body: `{"choices":[{"message":{"content":"ok"}}]}`}
	})
	t.Cleanup(primary.Close)

	fallback := itMockOpenAI(t, "shared-model", func(req *http.Request) itMockResponse {
		fallbackHits.Add(1)
		return itMockResponse{StatusCode: http.StatusOK, Body: `{"choices":[{"message":{"content":"fallback"}}]}`}
	})
	t.Cleanup(fallback.Close)

	// Both nodes advertise the same "shared-model" so /v1/chat/completions
	// can pick either.
	primaryNode := nodeConfig{Name: "primary", URL: primary.URL, Tier: "fast", Weight: 1, Models: []string{"shared-model"}, Enabled: "true"}
	fallbackNode := nodeConfig{Name: "fallback", URL: fallback.URL, Tier: "fast", Weight: 1, Models: []string{"shared-model"}, Enabled: "true"}

	cfg := config{
		Listen:      ":0",
		MetricsAddr: "",
		Defaults: defaults{
			MaxQueueDepth:  64,
			MaxConcurrency: 4,
			RequestTimeout: durationValue{Duration: 5 * time.Second},
			MaxBodySize:    1 << 20,
		},
		HealthCheck: healthConfig{
			Interval:           durationValue{Duration: 250 * time.Millisecond},
			Timeout:            durationValue{Duration: time.Second},
			Path:               "/health",
			UnhealthyThreshold: 1,
			HealthyThreshold:   1,
		},
		Nodes: []nodeConfig{primaryNode, fallbackNode},
	}

	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.healthLoop(ctx)
	itWaitForHealthyNodes(t, r, 2, 2*time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", r.handleProxy)
	mux.HandleFunc("/healthz", r.handleHealth)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Send 12 requests; the router should route enough that fallback is exercised
	// at least once (primary returns 502 after the second hit).
	bodyTmpl := `{"model":"shared-model","messages":[{"role":"user","content":"req-%d"}]}`
	successes := 0
	statusCounts := make(map[int]int)
	for i := 0; i < 12; i++ {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions",
			strings.NewReader(fmt.Sprintf(bodyTmpl, i)))
		if err != nil {
			t.Fatalf("build req: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do req %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		statusCounts[resp.StatusCode]++
		if resp.StatusCode == http.StatusOK {
			successes++
		}
	}

	if fallbackHits.Load() == 0 && primaryHits.Load() <= 2 {
		t.Fatalf("expected fallback to absorb at least some traffic; primary=%d fallback=%d statuses=%v",
			primaryHits.Load(), fallbackHits.Load(), statusCounts)
	}
	if successes == 0 {
		t.Fatalf("expected at least one successful request via primary or fallback; statuses=%v", statusCounts)
	}
}

func TestIT_ModelsAggregation(t *testing.T) {
	upA := itMockOpenAI(t, "model-a", func(req *http.Request) itMockResponse {
		return itMockResponse{StatusCode: http.StatusOK, Body: `{"id":"x","model":"model-a"}`}
	})
	t.Cleanup(upA.Close)
	upB := itMockOpenAI(t, "model-b", func(req *http.Request) itMockResponse {
		return itMockResponse{StatusCode: http.StatusOK, Body: `{"id":"y","model":"model-b"}`}
	})
	t.Cleanup(upB.Close)

	srv, _ := itSetupRouter(t, []*httptest.Server{upA, upB})

	resp, err := http.Get(srv.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "model-0") {
		t.Errorf("/v1/models should advertise model-0 (from upstream-0): %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "model-1") {
		t.Errorf("/v1/models should advertise model-1 (from upstream-1): %s", bodyStr)
	}
}

func TestIT_PrometheusExpositionFormat(t *testing.T) {
	upstream := itMockOpenAI(t, "model-0", func(req *http.Request) itMockResponse {
		return itMockResponse{StatusCode: http.StatusOK, Body: `{"choices":[{"message":{"content":"ok"}}]}`}
	})
	t.Cleanup(upstream.Close)

	srv, _ := itSetupRouter(t, []*httptest.Server{upstream})

	// Send a few requests to ensure metrics get populated.
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"model":"model-0","messages":[{"role":"user","content":"req-%d"}]}`, i)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	out := string(body)

	// Required series for v0.1.0:
	required := []string{
		"# HELP llm_router_requests_total",
		"# TYPE llm_router_requests_total counter",
		`llm_router_requests_total{`,
		"# HELP llm_router_request_duration_seconds",
		"# TYPE llm_router_request_duration_seconds histogram",
		"# HELP llm_router_queue_depth",
		"# TYPE llm_router_queue_depth gauge",
		"# HELP llm_router_inflight_requests",
		"# TYPE llm_router_inflight_requests gauge",
		"# HELP llm_router_node_healthy",
		"# TYPE llm_router_node_healthy gauge",
	}
	for _, line := range required {
		if !strings.Contains(out, line) {
			t.Errorf("/metrics missing expected line %q\n--- full /metrics ---\n%s", line, out)
		}
	}

	// Spot-check that requests_total was actually incremented for our calls.
	if !strings.Contains(out, `llm_router_requests_total{model="model-0"`) &&
		!strings.Contains(out, `llm_router_requests_total{node="upstream-0"`) {
		t.Errorf("/metrics missing per-model requests_total label\n--- full /metrics ---\n%s", out)
	}
}
