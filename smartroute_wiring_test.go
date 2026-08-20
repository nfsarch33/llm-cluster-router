package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cfgpkg "github.com/nfsarch33/llm-cluster-router/internal/config"
	"github.com/nfsarch33/llm-cluster-router/internal/smartroute"
)

// newSmartRouteRouter boots a router with smartroute enabled against a mock
// upstream and returns both, plus the model the upstream last received.
func newSmartRouteRouter(t *testing.T) (*router, *string) {
	t.Helper()

	var lastModel string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		var p struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(b, &p)
		lastModel = p.Model
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	t.Cleanup(upstream.Close)

	policy := `
enabled: true
default_class: chat
agents:
  cursor: true
  claude-code: true
  kilo-code: true
  codex: false
classes:
  - name: chat
    route:
      model: qwen3.8-27b-local
      tier: "0"
`
	policyPath := filepath.Join(t.TempDir(), "smartroute.yml")
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	c := config{
		Defaults: cfgpkg.Defaults{
			MaxConcurrency: 4,
			MaxQueueDepth:  8,
			RequestTimeout: cfgpkg.DurationValue{Duration: 5 * time.Second},
		},
		Nodes: []cfgpkg.NodeConfig{{
			Name:    "mock",
			URL:     upstream.URL,
			Tier:    "0",
			Enabled: "true",
			Weight:  1,
			Models:  []string{"qwen3.8-27b-local"},
		}},
		SmartRoute: cfgpkg.SmartRouteConfig{Enabled: true, PolicyFile: policyPath},
	}
	r, err := newRouter(c)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	for _, n := range r.nodes {
		n.healthy.Store(true)
	}
	return r, &lastModel
}

func proxyRequest(t *testing.T, r *router, agentHeader, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if agentHeader != "" {
		req.Header.Set(smartroute.HeaderAgent, agentHeader)
	}
	w := httptest.NewRecorder()
	r.handleProxy(w, req)
	return w
}

// TestSmartRouteWiring_DisabledAgentGets403 pins the per-agent boolean gate
// end to end through the real proxy handler: codex is flagged false in the
// policy, so its requests must be refused before any upstream is contacted.
func TestSmartRouteWiring_DisabledAgentGets403(t *testing.T) {
	r, lastModel := newSmartRouteRouter(t)

	w := proxyRequest(t, r, "codex", `{"model":"auto","messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("codex request: status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "codex") {
		t.Errorf("403 body should name the blocked agent, got %q", w.Body.String())
	}
	if *lastModel != "" {
		t.Errorf("upstream was contacted (model=%q) despite the agent gate", *lastModel)
	}
}

// TestSmartRouteWiring_EnabledAgentAutoModelRewritten proves the happy path:
// an enabled agent sending model:"auto" reaches the upstream with the
// policy's concrete model injected.
func TestSmartRouteWiring_EnabledAgentAutoModelRewritten(t *testing.T) {
	r, lastModel := newSmartRouteRouter(t)

	w := proxyRequest(t, r, "kilo-code", `{"model":"auto","messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("kilo-code request: status = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	if *lastModel != "qwen3.8-27b-local" {
		t.Errorf("upstream saw model %q, want the policy-injected qwen3.8-27b-local", *lastModel)
	}
}

// TestSmartRouteWiring_UnidentifiedCallerPasses: callers with no agent header
// and an unrecognized User-Agent must be unaffected by the gate.
func TestSmartRouteWiring_UnidentifiedCallerPasses(t *testing.T) {
	r, _ := newSmartRouteRouter(t)
	w := proxyRequest(t, r, "", `{"model":"qwen3.8-27b-local","messages":[{"role":"user","content":"hi"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("unidentified caller: status = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
}

// TestSmartRouteWiring_DisabledFeatureIsInert: with smart_route absent from
// config, even a codex-identified request passes — the whole feature is one
// boolean away from not existing.
func TestSmartRouteWiring_DisabledFeatureIsInert(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	c := config{
		Defaults: cfgpkg.Defaults{MaxConcurrency: 4, MaxQueueDepth: 8, RequestTimeout: cfgpkg.DurationValue{Duration: 5 * time.Second}},
		Nodes: []cfgpkg.NodeConfig{{
			Name: "mock", URL: upstream.URL, Tier: "0", Enabled: "true", Weight: 1,
			Models: []string{"m1"},
		}},
	}
	r, err := newRouter(c)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	for _, n := range r.nodes {
		n.healthy.Store(true)
	}
	w := proxyRequest(t, r, "codex", `{"model":"m1","messages":[]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("feature-off codex request: status = %d, want 200", w.Code)
	}
}
