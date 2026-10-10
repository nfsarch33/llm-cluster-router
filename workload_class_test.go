package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
)

// The token-plan stand-in: an internal-only node whose hit count is the
// thing customer traffic must never move.
func tokenPlanNode(t *testing.T, hits *atomic.Int64) *upstreamNode {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"x","model":"m3","choices":[{"message":{"role":"assistant","content":"token-plan"}}]}`)
	}))
	t.Cleanup(srv.Close)
	n := newTestNode(t, "token-plan", srv.URL, "3", 1, 1, []string{"m3"}, 0, 0, nil)
	n.cfg.Workloads = []string{"internal"}
	return n
}

func customerNode(t *testing.T, up *httptest.Server, healthy bool) *upstreamNode {
	t.Helper()
	n := newTestNode(t, "customer-qwen", up.URL, "0", 2, 1, []string{"m3", "qwen"}, 0, 0, nil)
	n.healthy.Store(healthy)
	return n
}

func classRouter(nodes ...*upstreamNode) *router {
	return newFailoverRouter(nodes, 5*time.Second)
}

func doChatClass(r *router, model, token, tenant string, spoofHeader bool) (*httptest.ResponseRecorder, string) {
	// the spoofing wrapper: a customer caller relabelling itself internal
	classHeader := ""
	if spoofHeader {
		classHeader = "internal"
	}
	return doChatClassHeader(r, model, token, tenant, classHeader)
}

// TestCustomerTrafficNeverReachesTokenPlanNode (the fail-closed case):
// every customer-eligible node is DOWN, the internal-only (paid-plan)
// node is healthy — the customer request must get 503 + Retry-After and
// the paid-plan node must record ZERO hits.
// Mutant: removing the workloads filter (or the class check) lets the
// customer request through to the internal-only node and fails this test.
func TestCustomerTrafficNeverReachesTokenPlanNode(t *testing.T) {
	var tpHits atomic.Int64
	tp := tokenPlanNode(t, &tpHits)
	down := customerNode(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})), false)
	down.cfg.Models = []string{"m3", "qwen"} // serves m3 too: the class filter is the only guard
	r := classRouter(tp, down)

	// model m3 is served by BOTH nodes: only the class filter can keep
	// this customer request off the token-plan node.
	w, _ := doChatClass(r, "m3", "customer-tok", "acme", false)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail closed, never spill to the token-plan node)", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Fatal("503 must carry Retry-After so the job queue holds the request")
	}
	if tpHits.Load() != 0 {
		t.Fatalf("token-plan node saw %d hits — customer traffic reached the internal-only node", tpHits.Load())
	}
}

// TestInternalTokenStillReachesTokenPlanNode is the positive control: with
// the same node set, the internal token routes to the token-plan node.
// Mutant: a class filter that excludes everything fails this test.
func TestInternalTokenStillReachesTokenPlanNode(t *testing.T) {
	var tpHits atomic.Int64
	tp := tokenPlanNode(t, &tpHits)
	r := classRouter(tp)

	w, body := doChatClass(r, "m3", "internal-tok", "", false)
	if w.Code != http.StatusOK || !strings.Contains(body, "token-plan") {
		t.Fatalf("internal request: status %d body %q — the internal lane must still reach the token-plan node", w.Code, body)
	}
	if tpHits.Load() != 1 {
		t.Fatalf("token-plan hits = %d, want 1", tpHits.Load())
	}
}

// TestCustomerClassComesFromTokenNotHeader: a customer token spoofing an
// internal class header is still classed customer (and, with no eligible
// node, still fails closed).
func TestCustomerClassComesFromTokenNotHeader(t *testing.T) {
	var tpHits atomic.Int64
	tp := tokenPlanNode(t, &tpHits)
	r := classRouter(tp)

	w, _ := doChatClass(r, "m3", "customer-tok", "acme", true)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("spoofed class header must be ignored: status %d, want 503", w.Code)
	}
	if tpHits.Load() != 0 {
		t.Fatalf("spoof reached the token-plan node (%d hits)", tpHits.Load())
	}
}

// TestSpoofedCustomerHeaderOnInternalToken: an internal caller spoofing
// the customer class header must stay internal — the tenant requirement
// and the class routing must not move. Mutant: ClassFromRequest trusting a
// caller header fails this (the request would 400 for a missing tenant).
func TestSpoofedCustomerHeaderOnInternalToken(t *testing.T) {
	var tpHits atomic.Int64
	tp := tokenPlanNode(t, &tpHits)
	r := classRouter(tp)

	w, body := doChatClassHeader(r, "m3", "internal-tok", "", "customer")
	if w.Code != http.StatusOK || !strings.Contains(body, "token-plan") {
		t.Fatalf("internal token + spoofed customer header: status %d — the class must come from the token, not the header", w.Code)
	}
	if tpHits.Load() != 1 {
		t.Fatalf("token-plan hits = %d, want 1", tpHits.Load())
	}
}

// TestCustomerRequiresTenantHeader: a customer-class request without
// X-HLXN-Tenant is refused before dispatch.
func TestCustomerRequiresTenantHeader(t *testing.T) {
	var tpHits atomic.Int64
	tp := tokenPlanNode(t, &tpHits)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(up.Close)
	r := classRouter(tp, customerNode(t, up, true))

	w, body := doChatClass(r, "qwen", "customer-tok", "", false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %q, want 400 (tenant required)", w.Code, body)
	}
}

// TestCustomerRoutesToEligibleNodeWhenHealthy: with a healthy
// customer-eligible node present, the customer request lands there and the
// token-plan node stays at zero.
func TestCustomerRoutesToEligibleNodeWhenHealthy(t *testing.T) {
	var tpHits atomic.Int64
	tp := tokenPlanNode(t, &tpHits)
	var custHits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		custHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"x","model":"qwen","choices":[{"message":{"role":"assistant","content":"local"}}]}`)
	}))
	t.Cleanup(up.Close)
	r := classRouter(tp, customerNode(t, up, true))

	// m3 again: both nodes serve it, so reaching the customer node (not
	// the token-plan one) proves the class routing.
	w, body := doChatClass(r, "m3", "customer-tok", "acme", false)
	if w.Code != http.StatusOK || !strings.Contains(body, "local") {
		t.Fatalf("customer request: status %d body %q", w.Code, body)
	}
	if tpHits.Load() != 0 || custHits.Load() != 1 {
		t.Fatalf("hits: token-plan %d customer %d, want 0/1", tpHits.Load(), custHits.Load())
	}
}

func doChatClassHeader(r *router, model, token, tenant, classHeader string) (*httptest.ResponseRecorder, string) {
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if tenant != "" {
		req.Header.Set("X-HLXN-Tenant", tenant)
	}
	if classHeader != "" {
		req.Header.Set("X-Workload-Class", classHeader)
	}
	w := httptest.NewRecorder()
	proxy.ClassBearerAuthFunc(func() string { return "internal-tok" }, func() []string { return []string{"customer-tok"} })(
		r.handleProxy)(w, req)
	return w, w.Body.String()
}
