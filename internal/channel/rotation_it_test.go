//go:build integration

// Package channel integration suite for pooled credentials and rotation.
//
// Every test here is named TestIT_* on purpose: a file carrying the integration
// build tag whose tests are named anything else never runs under
// `go test -tags integration -run 'TestIT_'` and looks green forever.
//
// Run: go test -race -tags integration -run 'TestIT_' ./internal/channel/
package channel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// collectingAuditor collects audit events and signals when the expected number
// has arrived. Over a real listener the response reaches the client before
// handleProxy logs, so the test needs a happens-before edge — a channel, not a
// sleep.
type collectingAuditor struct {
	mu     sync.Mutex
	events []AuditEvent
	want   int
	done   chan struct{}
	closed bool
}

func newCollectingAuditor(want int) *collectingAuditor {
	return &collectingAuditor{want: want, done: make(chan struct{})}
}

func (c *collectingAuditor) Log(e AuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	if !c.closed && len(c.events) >= c.want {
		c.closed = true
		close(c.done)
	}
}

func (c *collectingAuditor) await(d time.Duration) ([]AuditEvent, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-c.done:
	case <-timer.C:
		c.mu.Lock()
		got := len(c.events)
		c.mu.Unlock()
		return nil, fmt.Errorf("timed out after %s with %d of %d audit events", d, got, c.want)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AuditEvent(nil), c.events...), nil
}

// realGateway serves a Server over a real loopback listener.
func realGateway(t *testing.T, srv *Server) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	gw := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second},
	}
	gw.Start()
	t.Cleanup(gw.Close)
	return gw
}

// TestIT_PooledRouteRotatesAcrossRealHTTP drives a pooled route over a real
// loopback listener with the real round-robin policy, so the rotation, the
// audit attribution and the /healthz inventory are proven end to end rather
// than through a stub.
func TestIT_PooledRouteRotatesAcrossRealHTTP(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("Authorization")]++
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	keys := []string{"it-key1-not-real", "it-key2-not-real", "it-key3-not-real"}
	dir := t.TempDir()
	files := make([]string, 0, len(keys))
	for i, k := range keys {
		files = append(files, writeKeyFile(t, dir, "it"+strconv.Itoa(i)+".key", k+"\n"))
	}

	const total = 60
	audit := newCollectingAuditor(total)
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: upstream.URL, Auth: AuthInject,
		KeyFiles: files, Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), audit)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	gateway := realGateway(t, srv)

	client := &http.Client{Timeout: 10 * time.Second}
	for i := range total {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, gateway.URL+"/mm/v1/models", nil)
		if err != nil {
			t.Fatalf("build request %d: %v", i, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, resp.StatusCode)
		}
	}

	mu.Lock()
	for _, k := range keys {
		if got := seen["Bearer "+k]; got != total/len(keys) {
			t.Errorf("key %q served %d requests, want %d", k, got, total/len(keys))
		}
	}
	mu.Unlock()

	// The response reaches the client before handleProxy writes its audit line,
	// so the events are awaited on a channel rather than read behind a sleep.
	events, err := audit.await(10 * time.Second)
	if err != nil {
		t.Fatalf("await audit events: %v", err)
	}
	if len(events) != total {
		t.Errorf("audit lines = %d, want %d", len(events), total)
	}
	slots := map[int]int{}
	for i, ev := range events {
		if ev.KeyIndex == nil {
			t.Fatalf("audit line %d has no key_index", i)
		}
		if *ev.KeyIndex < 0 || *ev.KeyIndex >= len(keys) {
			t.Errorf("audit line %d key_index = %d, want a slot in [0,%d)", i, *ev.KeyIndex, len(keys))
		}
		slots[*ev.KeyIndex]++
	}
	for i := range keys {
		if slots[i] != total/len(keys) {
			t.Errorf("audit attributed %d requests to slot %d, want %d", slots[i], i, total/len(keys))
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, gateway.URL+"/healthz", nil)
	if err != nil {
		t.Fatalf("build healthz request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var health struct {
		Keys map[string]KeyInventory `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	want := KeyInventory{Mode: AuthInject, Pooled: true, Keys: 3, Available: 3}
	if got := health.Keys["mm"]; got != want {
		t.Errorf("healthz keys[mm] = %+v, want %+v", got, want)
	}
}

// TestIT_RotationExhaustionAndRecoveryCycle drives a real two-key gateway over
// real HTTP until both plans are spent, asserts the 503 + Retry-After answer
// (never a 502), and then asserts the route heals by itself when the accounting
// window rolls.
func TestIT_RotationExhaustionAndRecoveryCycle(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer k") {
			t.Errorf("upstream Authorization = %q, want an injected rotation key", got)
		}
		_, _ = io.WriteString(w, `{"usage":{"total_tokens":5}}`)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: upstream.URL,
		Auth: AuthInject, Enabled: true,
		KeyFiles: []string{
			writeKeyFile(t, dir, "k1.key", "k1-not-real\n"),
			writeKeyFile(t, dir, "k2.key", "k2-not-real\n"),
		},
		Rotation: &RotationConfig{Budget: Budget{
			Window: 2 * time.Second, Requests: 1, SoftRatio: 1, EstimateTokens: 1,
		}},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	gateway := realGateway(t, srv)

	get := func() (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			gateway.URL+"/mm/v1/chat/completions", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET through the gateway: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}

	for i := range 2 {
		if code, _ := get(); code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 while a plan is live", i, code)
		}
	}

	code, retryAfter := get()
	if code == http.StatusBadGateway {
		t.Fatal("status = 502 with both plans spent; a billing outage must not page as a broken upstream")
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 with both plans spent", code)
	}
	secs, err := strconv.Atoi(retryAfter)
	if err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer count of seconds", retryAfter)
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream saw %d calls, want 2: the 503 must be answered without a round trip", got)
	}
	if inv := srv.KeyInventory()["mm"]; !inv.Degraded || inv.Available != 0 {
		t.Errorf("KeyInventory = %+v, want a degraded pool while every plan is spent", inv)
	}

	// Bounded settle-poll for the tumbling window to roll. The store has no
	// timer, so recovery is observed by asking rather than by being told.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code, _ := get(); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("route never recovered after its accounting window should have rolled")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := upstreamCalls.Load(); got < 3 {
		t.Errorf("upstream calls = %d, want the recovered request to have reached it", got)
	}
}

// TestIT_HeaderPooledRouteWithARequestBudget exercises the composition neither
// source branch built, over real HTTP: a header-auth pooled route with a
// per-key REQUEST budget (a header upstream reports no usage.total_tokens, so a
// token budget would be charged entirely from estimates).
func TestIT_HeaderPooledRouteWithARequestBudget(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("x-api-key")]++
		mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("inbound Authorization reached the upstream as %q", got)
		}
		_, _ = io.WriteString(w, `{"results":[]}`)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	const total = 4
	audit := newCollectingAuditor(total + 1)
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "exa", Prefix: "/exa/", Upstream: upstream.URL,
		Auth: AuthHeaderInject, KeyHeader: "x-api-key", Enabled: true,
		KeyFiles: []string{
			writeKeyFile(t, dir, "exa1.key", "exa-it-one-not-real\n"),
			writeKeyFile(t, dir, "exa2.key", "exa-it-two-not-real\n"),
		},
		Rotation: &RotationConfig{
			Policy:        PolicyLeastUsed,
			MaxRetryAfter: time.Minute,
			Budget:        Budget{Window: time.Hour, Requests: 2, SoftRatio: 1},
		},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), audit)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	gateway := realGateway(t, srv)

	call := func() *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, gateway.URL+"/exa/search", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer caller-token-not-real")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET through the gateway: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}

	for i := range total {
		if resp := call(); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, resp.StatusCode)
		}
	}
	mu.Lock()
	for _, k := range []string{"exa-it-one-not-real", "exa-it-two-not-real"} {
		if got := seen[k]; got != 2 {
			t.Errorf("key %q served %d requests, want 2 (its whole request budget)", k, got)
		}
	}
	mu.Unlock()

	drained := call()
	if drained.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 once every request budget is spent", drained.StatusCode)
	}
	if ra := drained.Header.Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("Retry-After = %q, want a positive number of seconds", ra)
	}

	events, err := audit.await(10 * time.Second)
	if err != nil {
		t.Fatalf("await audit events: %v", err)
	}
	for i, ev := range events {
		if ev.AuthMode != string(AuthHeaderInject) {
			t.Errorf("audit line %d auth_mode = %q, want %q", i, ev.AuthMode, AuthHeaderInject)
		}
		if ev.Status == http.StatusServiceUnavailable {
			continue
		}
		if ev.KeyIndex == nil {
			t.Fatalf("audit line %d has no key_index; a pooled header route must attribute its key", i)
		}
		if !ev.TokensEstimated {
			t.Errorf("audit line %d tokens_estimated = false; a header upstream reports no usage", i)
		}
		if ev.Tokens != 0 {
			t.Errorf("audit line %d carries tokens=%d the upstream never reported", i, ev.Tokens)
		}
	}
}

// TestIT_ConcurrentBurstIsAdmissionControlledOverRealHTTP is the R1 guarantee
// over a real loopback listener, a real client and a real connection pool,
// rather than through an in-process handler call.
//
// The claim being proven is a production-concurrency claim, so it is worth
// making once against the real stack: a per-key hard cap of 5 under a 60-way
// simultaneous burst admits exactly 5 requests to the upstream and answers the
// other 55 with 503, never contacting the upstream for them.
//
// Determinism comes from the release gate, not from timing: every request
// notices exactly once — on arrival at the upstream, or on being refused
// without a round trip — so the upstream is released only when the whole burst
// has come to rest. That predicate is reached whether admission control works
// or not, which is what lets one assertion separate the two without a timeout.
func TestIT_ConcurrentBurstIsAdmissionControlledOverRealHTTP(t *testing.T) {
	const (
		burst  = 60
		reqCap = 5
	)
	gate := newReleaseGate(burst)
	// A probe, not a bare httptest server: "the upstream saw exactly N" is
	// only true of an upstream no other process can reach, and the gate below
	// makes it worse than a miscount -- a note raised by a stray request
	// releases the burst before it has come to rest. See upstreamProbe.
	upstream := newUpstreamProbe(t, func(w http.ResponseWriter, _ *http.Request) {
		gate.note()
		gate.wait()
		_, _ = io.WriteString(w, `{"usage":{"total_tokens":1}}`)
	})

	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{
			Window: time.Hour, Requests: reqCap, SoftRatio: 1, EstimateTokens: 1,
		}}), nil, nil)
	gateway := realGateway(t, srv)

	var served, refused atomic.Int64
	var wg sync.WaitGroup
	wg.Add(burst)
	for range burst {
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				gateway.URL+"/mm/v1/chat/completions", nil)
			if err != nil {
				t.Errorf("build request: %v", err)
				gate.note()
				return
			}
			resp, err := http.DefaultClient.Do(upstream.stamp(req))
			if err != nil {
				t.Errorf("GET through the gateway: %v", err)
				gate.note()
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				served.Add(1)
			case http.StatusServiceUnavailable:
				refused.Add(1)
				gate.note() // refused without a round trip: this request is at rest
			default:
				refused.Add(1)
				gate.note()
				t.Errorf("status = %d, want 200 or 503", resp.StatusCode)
			}
		}()
	}
	wg.Wait()

	// Two keys, five requests each: the plan is ten, not five.
	const plan = 2 * reqCap
	if got := upstream.hitCount(); got != plan {
		t.Errorf("upstream saw %d of %d burst requests against a %d-request cap on each of 2 keys, want %d",
			got, burst, reqCap, plan)
	}
	if served.Load() != plan || refused.Load() != burst-plan {
		t.Errorf("served=%d refused=%d, want %d served and %d answered 503",
			served.Load(), refused.Load(), plan, burst-plan)
	}
	for i, k := range storeFor(t, srv, "mm").Snapshot("mm") {
		if k.Requests != reqCap {
			t.Errorf("key %d settled %d requests, want exactly its %d-request plan", i, k.Requests, reqCap)
		}
		if k.InFlight != 0 {
			t.Errorf("key %d InFlight = %d after the burst settled, want 0", i, k.InFlight)
		}
	}
}
