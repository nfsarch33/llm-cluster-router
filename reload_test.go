package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// writeConfigFile dumps a YAML config into tempdir/config.yml so the
// reload tests can exercise the on-disk path the production daemon
// uses.
func writeConfigFile(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// fastUpstreamConfig produces a minimal config that points at the two
// httptest servers we boot inside the reload tests. We pick a long
// healthcheck interval so the loop doesn't race with assertions on
// node health state.
func fastUpstreamConfig(name, url, model string) string {
	return fmt.Sprintf(`
listen: 127.0.0.1:0
log_level: warn
defaults:
  max_queue_depth: 4
  max_concurrency: 2
  request_timeout: 5s
  max_body_size: 1048576
health_check:
  interval: 1m
  timeout: 1s
  path: /v1/models
nodes:
  - name: %s
    url: %s
    tier: fast
    enabled: "true"
    weight: 1
    models: [%s]
`, name, url, model)
}

// TestReload_AddsAndRemovesNodes asserts that calling Reload on a
// running router atomically swaps the node set: a new node added
// to the on-disk config appears in /v1/models, and an old node
// removed from the config disappears.
func TestReload_AddsAndRemovesNodes(t *testing.T) {
	t.Parallel()

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"alpha","object":"model"}]}`))
	}))
	t.Cleanup(upstreamA.Close)
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"beta","object":"model"}]}`))
	}))
	t.Cleanup(upstreamB.Close)

	dir := t.TempDir()
	cfgPath := writeConfigFile(t, dir, fastUpstreamConfig("node-a", upstreamA.URL, "alpha"))
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(r.handleModels))
	t.Cleanup(srv.Close)

	if got := modelIDs(t, srv.URL); !setEquals(got, []string{"alpha"}) {
		t.Fatalf("initial models: got %v, want [alpha]", got)
	}

	if err := os.WriteFile(cfgPath, []byte(fastUpstreamConfig("node-b", upstreamB.URL, "beta")), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if err := r.Reload(cfgPath); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := modelIDs(t, srv.URL); !setEquals(got, []string{"beta"}) {
		t.Fatalf("post-reload models: got %v, want [beta]", got)
	}
}

// TestReload_PreservesStateOnInvalidConfig asserts that a reload
// against a malformed config file is rejected and leaves the
// previous config + nodes intact.
func TestReload_PreservesStateOnInvalidConfig(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	cfgPath := writeConfigFile(t, dir, fastUpstreamConfig("node-a", upstream.URL, "alpha"))
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(r.handleModels))
	t.Cleanup(srv.Close)

	// Garbage YAML: missing nodes section + invalid duration.
	if err := os.WriteFile(cfgPath, []byte("listen: 127.0.0.1:0\ndefaults:\n  request_timeout: garbage\n"), 0o600); err != nil {
		t.Fatalf("rewrite invalid config: %v", err)
	}
	if err := r.Reload(cfgPath); err == nil {
		t.Fatal("expected Reload to reject invalid config")
	}
	if got := modelIDs(t, srv.URL); !setEquals(got, []string{"alpha"}) {
		t.Fatalf("post-reload models after rejection: got %v, want [alpha]", got)
	}
}

// TestReload_UpdatesAuthToken asserts that flipping the auth token in
// the config file makes the new token immediately effective.
func TestReload_UpdatesAuthToken(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	body := fastUpstreamConfig("node-a", upstream.URL, "alpha") + "auth_token: token-one\n"
	cfgPath := writeConfigFile(t, dir, body)
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}

	if got := r.AuthToken(); got != "token-one" {
		t.Fatalf("initial token: got %q, want token-one", got)
	}

	body2 := fastUpstreamConfig("node-a", upstream.URL, "alpha") + "auth_token: token-two\n"
	if err := os.WriteFile(cfgPath, []byte(body2), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if err := r.Reload(cfgPath); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := r.AuthToken(); got != "token-two" {
		t.Fatalf("post-reload token: got %q, want token-two", got)
	}
}

// TestSIGHUPCallsReload asserts the daemon's signal-handling loop
// calls Reload when the process receives SIGHUP. We don't open a
// real listener; we drive the loop via watchSighup directly.
func TestSIGHUPCallsReload(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	cfgPath := writeConfigFile(t, dir, fastUpstreamConfig("node-a", upstream.URL, "alpha"))
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	doneCh := make(chan struct{})
	var calls atomic.Int64
	hookForTest := func() { calls.Add(1) }
	go func() {
		watchReloadSignal(sigCh, cfgPath, r, hookForTest)
		close(doneCh)
	}()

	sigCh <- syscall.SIGHUP

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("watchReloadSignal did not invoke reload hook within 2s of SIGHUP")
	}
	close(sigCh)
	<-doneCh
}

func modelIDs(t *testing.T, url string) []string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("models request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode models: %v", err)
	}
	out := make([]string, 0, len(body.Data))
	for _, m := range body.Data {
		out = append(out, m.ID)
	}
	return out
}

func setEquals(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gotSet := map[string]struct{}{}
	for _, g := range got {
		gotSet[g] = struct{}{}
	}
	for _, w := range want {
		if _, ok := gotSet[w]; !ok {
			return false
		}
	}
	return true
}
