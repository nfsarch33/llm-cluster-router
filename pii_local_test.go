package main

import (
	"sync/atomic"

	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/piiroute"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
)

// The PII-local rule at the SELECTION level (the detector and the
// selection predicate have their own rows in internal/piiroute): a
// payload classified personal may only be served by a pii_local node,
// and when none exists the router returns nil — the handler then fails
// closed with 503 pii_no_local_node; a cloud node is never selected.
// MUTANT: drop the PersonalBlocks filter in selectNodeFromSnapExcluding
// and the cloud row goes red (the personal payload lands on cloud-m3).
func TestSelectNodePersonalNeverClouds(t *testing.T) {
	t.Parallel()

	cfg := config{
		Defaults: defaults{
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
		},
		Nodes: []nodeConfig{
			{Name: "cloud-m3", URL: "http://cloud.example", Tier: "fast", Models: []string{"alpha"}, Weight: 1, Enabled: "true", Priority: 1},
			{Name: "cloud-alt", URL: "http://cloud2.example", Tier: "fast", Models: []string{"alpha"}, Weight: 1, Enabled: "true", Priority: 2},
		},
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	snap := r.snap()

	// Cloud-only pool: a personal payload selects NOTHING (nil is the
	// handler's cue to refuse), while ordinary traffic still routes.
	if got := r.selectNodeFromSnap(snap, "alpha", "", "", proxy.ClassInternal, true); got != nil {
		t.Fatalf("a personal payload must never select a cloud node, got %q", got.cfg.Name)
	}
	if got := r.selectNodeFromSnap(snap, "alpha", "", "", proxy.ClassInternal, false); got == nil {
		t.Fatal("ordinary traffic must still route on the cloud pool")
	}

	// THE BLAST-RADIUS ROW (round 1): a cloud-only config never arms the
	// rule, so the reviewer's probe body — an email in a git commit
	// --author line — must still ROUTE (the handler's personal flag is
	// detection && armed, and armed is false with zero pii_local nodes).
	if piiroute.RuleArmed("", false) {
		t.Fatal("the rule must not arm on a config with zero pii_local nodes")
	}
	unarmed := piiroute.DetectPersonal([]byte(`git commit --author="dev <dev@users.noreply.github.com>" -m fix`)) && piiroute.RuleArmed("", false)
	if unarmed {
		t.Fatal("on an unarmed config the email body must stay non-personal for routing (observability-only)")
	}
	if got := r.selectNodeFromSnap(snap, "alpha", "", "", proxy.ClassInternal, unarmed); got == nil {
		t.Fatal("the round-1 probe body must still route on a cloud-only config with the rule off")
	}

	// With a pii_local node present, personal selects it — and ONLY it,
	// even at a worse priority than every cloud node.
	cfg.Nodes = append(cfg.Nodes, nodeConfig{
		Name: "local-qwen", URL: "http://local.example", Tier: "fast",
		Models: []string{"alpha"}, Weight: 1, Enabled: "true", Priority: 9, PIILocal: true,
	})
	r2, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter(2): %v", err)
	}
	snap2 := r2.snap()
	for i := 0; i < 8; i++ { // weighted round-robin: every pick must be local
		got := r2.selectNodeFromSnap(snap2, "alpha", "", "", proxy.ClassInternal, true)
		if got == nil || got.cfg.Name != "local-qwen" {
			t.Fatalf("pick %d: personal payload must always land on local-qwen, got %+v", i, got)
		}
	}

	// The detector drives it end to end: a body with an email is personal.
	if !piiroute.DetectPersonal([]byte(`Reply to sam.wong@example.com`)) {
		t.Fatal("detector regression: email payload must classify personal")
	}
}

// Round 2: END-TO-END handler rows over a real httptest upstream — the
// armed gate, the fail-closed 503 (enforce with no marked node), the
// rule-off pass-through, and the personal-payload routing to the
// marked node.
func TestPIIRuleHandlerEndToEnd(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	t.Cleanup(upstream.Close)
	upURL, _ := url.Parse(upstream.URL)

	personalBody := `{"model":"alpha","messages":[{"role":"user","content":"email sarah@example.com about order #A-10493"}]}`
	cleanBody := `{"model":"alpha","messages":[{"role":"user","content":"summarise the quarterly trends"}]}`

	newTestRouter := func(mode string, mark bool) *router {
		r := &router{
			cfg: config{
				Defaults:     defaults{MaxQueueDepth: 8, MaxConcurrency: 1, RequestTimeout: durationValue{Duration: time.Second}, MaxBodySize: 1 << 20},
				PIILocalRule: mode,
			},
			client:    &http.Client{Timeout: time.Second},
			semaphore: make(chan struct{}, 1),
		}
		node := &upstreamNode{
			cfg:     nodeConfig{Name: "cloud", Tier: "fast", Priority: 1, Weight: 1, Models: []string{"alpha"}, PIILocal: mark},
			baseURL: upURL,
		}
		node.healthy.Store(true)
		r.nodes = []*upstreamNode{node}
		armed := piiroute.RuleArmed(mode, mark)
		r.piiRuleArmed.Store(armed)
		return r
	}

	post := func(r *router, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.handleProxy(rec, req)
		return rec.Code
	}

	// auto + unmarked: the probe body ROUTES (rule off, observability only).
	if got := post(newTestRouter("", false), personalBody); got != http.StatusOK {
		t.Fatalf("rule off: personal body must still route, got %d", got)
	}
	// enforce + unmarked: FAIL CLOSED — personal is refused 503.
	if got := post(newTestRouter("enforce", false), personalBody); got != http.StatusServiceUnavailable {
		t.Fatalf("enforce with no marked node must refuse personal, got %d", got)
	}
	// enforce + marked: personal routes (to the marked node).
	if got := post(newTestRouter("enforce", true), personalBody); got != http.StatusOK {
		t.Fatalf("enforce with a marked node must route personal, got %d", got)
	}
	// off + marked: personal routes freely (rule disabled by config).
	if got := post(newTestRouter("off", true), personalBody); got != http.StatusOK {
		t.Fatalf("off must route personal freely, got %d", got)
	}
	// Clean traffic routes in every mode.
	for _, mode := range []string{"", "auto", "enforce", "off"} {
		if got := post(newTestRouter(mode, false), cleanBody); got != http.StatusOK {
			t.Fatalf("clean body must route in mode %q, got %d", mode, got)
		}
	}
}

// Round 3: the FAILOVER walk carries the classification. A marked node
// that FAILS (500) must not spill a personal payload to the healthy
// unmarked fallback: the request ends 503 (fail closed) or on another
// marked node — never on the unmarked one.
// MUTANT: personal dropped to false at the failover call sites and this
// row goes red exactly there — the payload lands on the unmarked
// fallback.
func TestPIIRuleFailoverNeverSpillsToUnmarked(t *testing.T) {
	t.Parallel()

	markedUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream boom", http.StatusInternalServerError)
	}))
	t.Cleanup(markedUp.Close)
	var unmarkedHits int32
	unmarkedUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&unmarkedHits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	t.Cleanup(unmarkedUp.Close)
	markedURL, _ := url.Parse(markedUp.URL)
	unmarkedURL, _ := url.Parse(unmarkedUp.URL)

	r := &router{
		cfg: config{
			Defaults:     defaults{MaxQueueDepth: 8, MaxConcurrency: 1, RequestTimeout: durationValue{Duration: 2 * time.Second}, MaxBodySize: 1 << 20},
			PIILocalRule: "enforce",
		},
		client:    &http.Client{Timeout: 2 * time.Second},
		semaphore: make(chan struct{}, 1),
	}
	marked := &upstreamNode{
		cfg:     nodeConfig{Name: "marked", Tier: "fast", Priority: 1, Weight: 1, Models: []string{"alpha"}, PIILocal: true},
		baseURL: markedURL,
	}
	unmarked := &upstreamNode{
		cfg:     nodeConfig{Name: "cloud-fallback", Tier: "fast", Priority: 2, Weight: 1, Models: []string{"alpha"}},
		baseURL: unmarkedURL,
	}
	marked.healthy.Store(true)
	unmarked.healthy.Store(true)
	r.nodes = []*upstreamNode{marked, unmarked}
	r.piiRuleArmed.Store(true)

	body := `{"model":"alpha","messages":[{"role":"user","content":"email sarah@example.com about the order"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.handleProxy(rec, req)

	// The review's contract: personal ends 503 or on a marked node —
	// never on the unmarked one. The marked node's own 500 may pass
	// through (it IS a marked-node outcome); the assertion that bites
	// is the unmarked upstream NEVER seeing the payload.
	if got := atomic.LoadInt32(&unmarkedHits); got != 0 {
		t.Fatalf("personal payload SPILLED to the unmarked fallback (%d hits)", got)
	}
}
