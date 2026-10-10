package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	cfgpkg "github.com/nfsarch33/llm-cluster-router/internal/config"
	"github.com/nfsarch33/llm-cluster-router/internal/metrics"
)

// quotaRouter builds a router over one primary (3 keys, quota regex) and one
// fallback node, both against controllable httptest upstreams.
func quotaRouter(t *testing.T, primary, fallback http.HandlerFunc) (*router, *httptest.Server, *httptest.Server) {
	t.Helper()
	up1 := httptest.NewServer(primary)
	t.Cleanup(up1.Close)
	up2 := httptest.NewServer(fallback)
	t.Cleanup(up2.Close)

	c := config{
		Defaults: cfgpkg.Defaults{
			MaxConcurrency: 4,
			MaxQueueDepth:  8,
			RequestTimeout: cfgpkg.DurationValue{Duration: 5 * time.Second},
			KeyCooldown:    cfgpkg.DurationValue{Duration: time.Minute},
		},
		Nodes: []cfgpkg.NodeConfig{
			{
				Name: "minimax-primary", URL: up1.URL, Tier: "0", Enabled: "true", Weight: 1,
				Models:           []string{"m1"},
				APIKeys:          []string{"key-a", "key-b", "key-c"},
				Vendor:           "minimax",
				QuotaDetectRegex: `insufficient.?balance|quota.?exceeded`,
			},
			{
				Name: "fallback", URL: up2.URL, Tier: "1", Enabled: "true", Weight: 1,
				Models: []string{"m1"}, APIKey: "fb-key",
			},
		},
	}
	r, err := newRouter(c)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	for _, n := range r.nodes {
		n.healthy.Store(true)
	}
	return r, up1, up2
}

func postChat(t *testing.T, r *router) *httptest.ResponseRecorder {
	return postChatTier(t, r, "")
}

// postChatTier pins X-Tier when a test needs deterministic node selection.
func postChatTier(t *testing.T, r *router, tier string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"m1","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	if tier != "" {
		req.Header.Set("X-Tier", tier)
	}
	w := httptest.NewRecorder()
	r.handleProxy(w, req)
	return w
}

// TestHandleProxy_AttachesRotatedBearerKeys covers the previously-untested
// Authorization-attach line in the LIVE request path: three requests must
// carry the three configured keys round-robin.
func TestHandleProxy_AttachesRotatedBearerKeys(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	r, _, _ := quotaRouter(t,
		func(w http.ResponseWriter, req *http.Request) {
			mu.Lock()
			seen = append(seen, req.Header.Get("Authorization"))
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
		func(w http.ResponseWriter, req *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) },
	)

	for i := 0; i < 3; i++ {
		if w := postChatTier(t, r, "0"); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, w.Code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]bool{"Bearer key-a": true, "Bearer key-b": true, "Bearer key-c": true}
	if len(seen) != 3 {
		t.Fatalf("upstream saw %d requests, want 3", len(seen))
	}
	for _, h := range seen {
		if !want[h] {
			t.Errorf("unexpected Authorization %q", h)
		}
		delete(want, h)
	}
	if len(want) != 0 {
		t.Errorf("keys never used: %v (rotation broken)", want)
	}
}

// TestHandleProxy_QuotaBodyMatchIncrementsMetricAndCoolsKey is the RED test
// the audit demanded: a vendor body matching quota_detect_regex must (a)
// increment llm_router_quota_fallback_total, (b) cool the key that hit the
// wall, and (c) still serve the request via retry/fallback.
func TestHandleProxy_QuotaBodyMatchIncrementsMetricAndCoolsKey(t *testing.T) {
	before := testutil.ToFloat64(metrics.QuotaFallbackTotal.WithLabelValues("m1", "minimax-primary", "minimax"))

	var mu sync.Mutex
	failedKeys := map[string]bool{}
	r, _, _ := quotaRouter(t,
		func(w http.ResponseWriter, req *http.Request) {
			auth := req.Header.Get("Authorization")
			mu.Lock()
			first := len(failedKeys) == 0
			if first {
				failedKeys[auth] = true
			}
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":{"code":1008,"message":"insufficient balance"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
		func(w http.ResponseWriter, req *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) },
	)

	w := postChat(t, r)
	if w.Code != http.StatusOK {
		t.Fatalf("request should survive a quota hit via key retry/fallback, got %d: %s", w.Code, w.Body.String())
	}

	after := testutil.ToFloat64(metrics.QuotaFallbackTotal.WithLabelValues("m1", "minimax-primary", "minimax"))
	if after != before+1 {
		t.Errorf("llm_router_quota_fallback_total = %v, want %v (metric must increment on body match)", after, before+1)
	}
	if got := r.nodes[0].keys.Cooling(); got != 1 {
		t.Errorf("Cooling() = %d, want exactly the exhausted key cooling", got)
	}
}

// TestHandleProxy_CooledKeyLeavesRotation: after a quota hit on one key,
// subsequent requests must never present that key again within the cooldown.
func TestHandleProxy_CooledKeyLeavesRotation(t *testing.T) {
	var mu sync.Mutex
	var afterCool []string
	poisonedOnce := false
	r, _, _ := quotaRouter(t,
		func(w http.ResponseWriter, req *http.Request) {
			auth := req.Header.Get("Authorization")
			mu.Lock()
			poison := !poisonedOnce && auth == "Bearer key-a"
			if poison {
				poisonedOnce = true
			} else {
				afterCool = append(afterCool, auth)
			}
			mu.Unlock()
			if poison {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"quota exceeded"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
		func(w http.ResponseWriter, req *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) },
	)

	// Drive until key-a has been poisoned, then several more rounds.
	for i := 0; i < 7; i++ {
		if w := postChat(t, r); w.Code != http.StatusOK {
			t.Fatalf("request %d failed: %d", i, w.Code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !poisonedOnce {
		t.Fatal("test never exercised the poisoned key")
	}
	for _, h := range afterCool {
		if h == "Bearer key-a" {
			t.Fatalf("cooled key-a reappeared in rotation: %v", afterCool)
		}
	}
}

// TestHandleProxy_QueueFullReturns429 covers the backpressure branch.
func TestHandleProxy_QueueFullReturns429(t *testing.T) {
	release := make(chan struct{})
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(func() { close(release); blocked.Close() })

	c := config{
		Defaults: cfgpkg.Defaults{
			MaxConcurrency: 1,
			MaxQueueDepth:  1,
			RequestTimeout: cfgpkg.DurationValue{Duration: 10 * time.Second},
		},
		Nodes: []cfgpkg.NodeConfig{{
			Name: "slow", URL: blocked.URL, Tier: "0", Enabled: "true", Weight: 1, Models: []string{"m1"},
		}},
	}
	r, err := newRouter(c)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	for _, n := range r.nodes {
		n.healthy.Store(true)
	}

	var wg sync.WaitGroup
	codes := make(chan int, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- postChat(t, r).Code
		}()
	}
	// All six are in flight against MaxConcurrency=1 + MaxQueueDepth=1; at
	// least one must be shed with 429 before the upstream is released.
	deadline := time.After(5 * time.Second)
	got429 := false
	for i := 0; i < 6 && !got429; i++ {
		select {
		case code := <-codes:
			got429 = code == http.StatusTooManyRequests
		case <-deadline:
			i = 6
		}
	}
	release <- struct{}{} // unblock remaining
	go func() { wg.Wait() }()
	if !got429 {
		t.Error("queue overflow never produced a 429 (backpressure branch untested/broken)")
	}
}

// TestNodeBreaker_NotTrippedWhileOtherKeysHealthy: one dead plan must not
// evict the node — the breaker only scores when ALL keys are cooling.
func TestNodeBreaker_NotTrippedWhileOtherKeysHealthy(t *testing.T) {
	r, _, _ := quotaRouter(t,
		func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("Authorization") == "Bearer key-a" {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"quota exceeded"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
		func(w http.ResponseWriter, req *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) },
	)

	for i := 0; i < 6; i++ {
		if w := postChat(t, r); w.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if !r.nodes[0].breaker.Allow() {
		t.Error("primary breaker tripped although two of three keys are healthy")
	}
	// The primary must still be serving (not everything failed over).
	if r.nodes[0].keys.Cooling() == 0 {
		t.Error("expected exactly the poisoned key to be cooling")
	}
}
