// q5-stale-health-test.go — RED/GREEN test for q4-c-lcr-stale-health.
//
// Sprint v18750-Q5 Phase 6.
//
// Bug: handleHealth reads node.healthy.Load() which is updated by the
// background runHealthPass loop every hc.Interval (default 30s). If an
// upstream node becomes unreachable between passes, /healthz reports
// stale healthy=true (L-016 / q4-c-lcr-stale-health).
//
// Fix: when caller passes ?live=1, do a live HTTP probe per node
// with optional ?timeout=<duration> (default 2s) and return the fresh
// state. Without ?live=1, behavior is unchanged (backward compat).
//
// This test uses httptest.NewServer to stand up a stub upstream, then
// starts the actual router binary and queries its /healthz endpoint.

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestQ5_LiveProbe_OverridesStaleHealthy runs the actual llm-cluster-router
// binary with a stub upstream that returns 503. Without the fix,
// /healthz?live=1 would return healthy_nodes=1 (using cached state).
// With the fix, it must return healthy_nodes=0.
func TestQ5_LiveProbe_OverridesStaleHealthy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test; skip in short mode")
	}
	// 1. Start stub upstream that returns 503 on /health
	stubUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/health") || strings.HasSuffix(r.URL.Path, "/healthz") {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer stubUpstream.Close()

	// 2. Find the router binary (already built by `go build ./...`)
	repoRoot, _ := os.Getwd()
	binary := filepath.Join(repoRoot, "bin", "llm-cluster-router")
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("binary not built yet at %s; run `go build -o %s`", binary, binary)
	}

	// 3. Write a minimal config file pointing at the stub
	cfgPath := filepath.Join(t.TempDir(), "lcr-q5.yaml")
	cfg := `listen: "127.0.0.1:18991"
metrics_addr: "127.0.0.1:19093"
defaults:
  max_queue_depth: 4
  max_concurrency: 1
nodes:
  - name: "stub-down"
    url: "` + stubUpstream.URL + `"
    tier: "test"
    priority: 0
    weight: 1
    models: ["qwen-test"]
health_check:
  interval: "30s"
  timeout: "500ms"
  path: "/health"
  healthy_threshold: 1
  unhealthy_threshold: 2
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	// 4. Start router with -listen=0 so it picks a free port; capture stdout/stderr
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "serve", "-config", cfgPath)
	cmd.Stdout = os.Stderr // route stdout to test stderr for debug
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start router: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	// 5. Wait for the router to come up
	url := "http://127.0.0.1:18991"
	if !waitForReady(url+"/healthz", 5*time.Second) {
		t.Fatalf("router did not come up on %s", url)
	}

	// 6. Probe /healthz WITHOUT ?live=1: may return cached healthy (stale)
	//    We don't assert on this; the bug only manifests when live=1.
	cachedResp := mustGET(t, url+"/healthz")
	t.Logf("cached /healthz: %s", cachedResp)

	// 7. Probe /healthz?live=1: MUST reflect fresh upstream state (503 = unhealthy)
	liveResp := mustGET(t, url+"/healthz?live=1&timeout=500ms")
	t.Logf("live /healthz: %s", liveResp)

	var live struct {
		HealthyNodes float64 `json:"healthy_nodes"`
		LiveProbe    bool    `json:"live_probe"`
		Nodes        []struct {
			Name    string `json:"name"`
			Healthy bool   `json:"healthy"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(liveResp), &live); err != nil {
		t.Fatalf("decode live response: %v", err)
	}
	if !live.LiveProbe {
		t.Fatalf("response missing live_probe:true marker; got: %s", liveResp)
	}

	// === THE RED ASSERTION ===
	// After fix: healthy_nodes should be 0 (upstream returns 503).
	if live.HealthyNodes != 0 {
		t.Fatalf("BUG: /healthz?live=1 returned healthy_nodes=%v (want 0); "+
			"upstream returned 503 but the live probe did not override the stale cache. "+
			"Got: %s", live.HealthyNodes, liveResp)
	}
}

func waitForReady(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func mustGET(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status %d: %s", url, resp.StatusCode, body)
	}
	return string(body)
}
