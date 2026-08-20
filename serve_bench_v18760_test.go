// Copyright (c) 2026 nfsarch33. Test-only; do not export.
//
// serve_bench_v18760_test.go covers the router binary's operational
// surface that previously only ran in production: the bench workflow
// end-to-end (request fan-out, metrics polling, report synthesis, file
// output), the serve boot path, the health/readiness gates, and the
// pure report/metric helpers. Every network interaction targets live
// httptest upstreams — no mocked transports.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/gpuprobe"
)

// captureStdoutV18760 swaps os.Stdout while fn runs and returns what
// was written (runBench and runProbeGPU print to stdout directly).
func captureStdoutV18760(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	runErr := fn()
	os.Stdout = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out, runErr
}

// newStubRouterEndpoint serves the four surfaces runBench touches:
// streaming chat completions, /metrics with a queue-depth gauge,
// /healthz and /v1/models. firstChunkDelay guarantees the bench run
// spans at least one 200ms pollMetric tick.
func newStubRouterEndpoint(t *testing.T, firstChunkDelay time.Duration, queueDepth int) *httptest.Server {
	t.Helper()
	var inflight atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		inflight.Add(1)
		defer inflight.Add(-1)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("no flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		time.Sleep(firstChunkDelay)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok \"}}]}\n\n")
		fl.Flush()
		_, _ = io.WriteString(w, "data: {\"usage\":{\"prompt_tokens\":16,\"completion_tokens\":4}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		fl.Flush()
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "# HELP llm_router_queue_depth depth\n# TYPE llm_router_queue_depth gauge\nllm_router_queue_depth %d\n", queueDepth)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true,"healthy_nodes":1}`)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"stub-model"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRunBench_EndToEndWritesReport(t *testing.T) {
	srv := newStubRouterEndpoint(t, 300*time.Millisecond, 3)
	out := filepath.Join(t.TempDir(), "bench.json")

	stdout, err := captureStdoutV18760(t, func() error {
		return runBench([]string{
			"--url", srv.URL,
			"--model", "stub-model",
			"--requests", "3",
			"--concurrency", "2",
			"--max-tokens", "8",
			"--timeout", "30s",
			"--cancel-after", "100ms",
			"--output", out,
		})
	})
	if err != nil {
		t.Fatalf("runBench = %v, want nil", err)
	}
	if !strings.Contains(stdout, "wrote benchmark report to") {
		t.Fatalf("stdout %q missing report banner", stdout)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	var report benchmarkReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("report not JSON: %v", err)
	}
	if report.Requests != 3 || report.SuccessfulRequests != 3 || report.FailedRequests != 0 {
		t.Fatalf("report counts = %d/%d/%d, want 3/3/0 (failures: %v)",
			report.Requests, report.SuccessfulRequests, report.FailedRequests, report.Failures)
	}
	if report.SuccessRate != 100 {
		t.Fatalf("success rate = %v, want 100", report.SuccessRate)
	}
	if report.P50TTFTMillis <= 0 || report.P95LatencyMillis <= 0 {
		t.Fatalf("percentiles not populated: %+v", report)
	}
	if report.ObservedMaxQueueDepth != 3 {
		t.Fatalf("observed queue depth = %d, want 3 (pollMetric must have sampled the gauge)", report.ObservedMaxQueueDepth)
	}
	if report.AvgGenerationTokensPerSec <= 0 || report.AvgPromptTokensPerSec <= 0 {
		t.Fatalf("token rates not populated: gen=%v prompt=%v", report.AvgGenerationTokensPerSec, report.AvgPromptTokensPerSec)
	}
	if report.HealthSnapshot == nil || report.ModelsSnapshot == nil {
		t.Fatal("health/models snapshots missing from report")
	}
}

func TestRunBench_BadFlagRejected(t *testing.T) {
	if err := runBench([]string{"--definitely-not-a-flag"}); err == nil {
		t.Fatal("unknown flag = nil, want parse error")
	}
}

func TestRunServe_BadConfigAndBadFlag(t *testing.T) {
	if err := runServe([]string{"--config", t.TempDir() + "/missing.yml"}); err == nil {
		t.Fatal("missing config = nil, want error")
	}
	if err := runServe([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag = nil, want parse error")
	}
}

// writeServeConfig renders a minimal serve config bound to listenAddr
// with one upstream node.
func writeServeConfig(t *testing.T, listenAddr, upstreamURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "router.yml")
	cfgYAML := fmt.Sprintf(`listen: %q
defaults:
  max_queue_depth: 4
  max_concurrency: 2
  request_timeout: 5s
  max_body_size: 1048576
health_check:
  interval: 50ms
  timeout: 1s
  path: /v1/models
  healthy_threshold: 1
  unhealthy_threshold: 2
nodes:
  - name: stub-node
    url: %q
    tier: fast
    enabled: "true"
    weight: 1
    models: ["stub-model"]
`, listenAddr, upstreamURL)
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestRunServe_BootsAndAnswersHealth boots the real serve path on an
// ephemeral port (plain HTTP listener; HELIXCHANNEL_ENABLED=false) and
// asserts /healthz answers and /readyz flips ready once the health loop
// has probed the live upstream. runServe has no shutdown seam (it runs
// until process exit), so the server goroutine intentionally outlives
// the test inside the shared test binary.
func TestRunServe_BootsAndAnswersHealth(t *testing.T) {
	t.Setenv("HELIXCHANNEL_ENABLED", "false")
	upstream := newStubRouterEndpoint(t, 0, 0)

	lf := listenFreeTCPRoot(t)
	port := lf.Port()
	_ = lf.Close()
	listen := fmt.Sprintf("127.0.0.1:%d", port)
	cfgPath := writeServeConfig(t, listen, upstream.URL)

	go func() { _ = runServe([]string{"--config", cfgPath}) }()

	deadline := time.Now().Add(10 * time.Second)
	healthOK := false
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + listen + "/healthz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(body), `"total_nodes":1`) {
				healthOK = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !healthOK {
		t.Fatal("serve path never answered /healthz")
	}

	readyOK := false
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + listen + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				readyOK = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !readyOK {
		t.Fatal("/readyz never reported ready despite a live upstream")
	}
}

func TestRunServe_ListenerBindConflictSurfaced(t *testing.T) {
	t.Setenv("HELIXCHANNEL_ENABLED", "false")
	upstream := newStubRouterEndpoint(t, 0, 0)
	lf := listenFreeTCPRoot(t)
	defer func() { _ = lf.Close() }()
	listen := fmt.Sprintf("127.0.0.1:%d", lf.Port())
	cfgPath := writeServeConfig(t, listen, upstream.URL)

	err := runServe([]string{"--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "listener bind") {
		t.Fatalf("err = %v, want listener bind failure", err)
	}
}

// tcpPortHandle reserves an ephemeral loopback port for serve tests
// (packages cannot share test helpers, so this mirrors the
// cmd/helixchannel listener handle).
type tcpPortHandle struct{ ln net.Listener }

func (h *tcpPortHandle) Port() int    { return h.ln.Addr().(*net.TCPAddr).Port }
func (h *tcpPortHandle) Close() error { return h.ln.Close() }

func listenFreeTCPRoot(t *testing.T) *tcpPortHandle {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return &tcpPortHandle{ln: ln}
}

func TestReadyAndReadyz_Gates(t *testing.T) {
	// Nodes boot healthy by design (main.go buildReloadable stores
	// healthy=true, "assume healthy until proven otherwise"), so the
	// unhealthy gate is created by probing a dead upstream.
	deadPort := 0
	{
		h := listenFreeTCPRoot(t)
		deadPort = h.Port()
		_ = h.Close()
	}
	dead := newTestRouter(t, fmt.Sprintf("http://127.0.0.1:%d", deadPort), "stub-model")
	if ready, _ := dead.Ready(); !ready {
		t.Fatal("boot Ready() = false, want optimistic true before first probe")
	}
	dead.runHealthPass(context.Background())
	ready, reason := dead.Ready()
	if ready || !strings.Contains(reason, "no healthy upstream") {
		t.Fatalf("post-pass dead Ready() = (%v,%q), want unhealthy", ready, reason)
	}
	rec := httptest.NewRecorder()
	dead.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("dead /readyz = %d, want 503", rec.Code)
	}

	// Live upstream + health pass → ready.
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")
	r.runHealthPass(context.Background())
	ready, reason = r.Ready()
	if !ready || reason != "" {
		t.Fatalf("live Ready() = (%v,%q), want ready", ready, reason)
	}
	rec = httptest.NewRecorder()
	r.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("live /readyz = %d, want 200", rec.Code)
	}

	// Queue ceiling gate.
	r.queueDepth.Store(int64(r.snap().cfg.Defaults.MaxQueueDepth) + 1)
	ready, reason = r.Ready()
	if ready || !strings.Contains(reason, "queue depth") {
		t.Fatalf("overloaded Ready() = (%v,%q), want queue-depth gate", ready, reason)
	}
	r.queueDepth.Store(0)
}

func TestHandleHealth_CachedAndLiveProbes(t *testing.T) {
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")

	// Cached view reflects the stored flag: force it false first (the
	// boot default is optimistic true), then read the cached path.
	for _, node := range r.snap().nodes {
		node.healthy.Store(false)
	}
	rec := httptest.NewRecorder()
	r.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("healthz body not JSON: %v", err)
	}
	if body["ok"] != false {
		t.Fatalf("cached ok = %v, want false with stored unhealthy flag", body["ok"])
	}

	// live=1 forces an immediate probe of the live upstream.
	rec = httptest.NewRecorder()
	r.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz?live=1&timeout=900ms", nil))
	body = map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("live healthz body not JSON: %v", err)
	}
	if body["ok"] != true || body["live_probe"] != true {
		t.Fatalf("live healthz = %v, want ok+live_probe", body)
	}

	// Out-of-range timeout falls back to the 2s default.
	rec = httptest.NewRecorder()
	r.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz?live=1&timeout=99h", nil))
	body = map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["probe_timeout"] != "2s" {
		t.Fatalf("probe_timeout = %v, want clamped 2s", body["probe_timeout"])
	}
}

func TestHealthLoop_StopsOnCancelAndDefaultsInterval(t *testing.T) {
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")
	// Zero the interval via a fresh config so the <=0 branch runs.
	snap := r.snap()
	snap.cfg.HealthCheck.Interval = durationValue{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.healthLoop(ctx)
		close(done)
	}()
	// The loop's initial pass must mark the node healthy.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ready, _ := r.Ready(); ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ready, reason := r.Ready(); !ready {
		t.Fatalf("healthLoop initial pass never marked node healthy: %s", reason)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("healthLoop did not stop on ctx cancel")
	}
}

func TestFetchJSON_ErrorPaths(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>nope</html>")
	}))
	defer srv.Close()
	if _, err := fetchJSON(client, srv.URL); err == nil {
		t.Fatal("non-JSON body = nil error, want decode failure")
	}
	if _, err := fetchJSON(client, "http://127.0.0.1:1/"); err == nil {
		t.Fatal("unreachable target = nil error, want dial failure")
	}
}

func TestParsePrometheusGauge_Table(t *testing.T) {
	payload := strings.Join([]string{
		"# HELP llm_router_queue_depth depth",
		"llm_router_queue_depth_bucket 99 extra",
		"llm_router_queue_depth notanumber",
		"llm_router_queue_depth 7",
		"other_metric 3",
	}, "\n")
	if got := parsePrometheusGauge(payload, "llm_router_queue_depth"); got != 7 {
		t.Fatalf("gauge = %d, want 7 (skip malformed lines first)", got)
	}
	if got := parsePrometheusGauge(payload, "absent_metric"); got != 0 {
		t.Fatalf("absent gauge = %d, want 0", got)
	}
}

func TestHasDeltaToken_Table(t *testing.T) {
	mk := func(delta map[string]any) map[string]any {
		return map[string]any{"choices": []any{map[string]any{"delta": delta}}}
	}
	cases := []struct {
		name    string
		payload map[string]any
		want    bool
	}{
		{"no choices", map[string]any{}, false},
		{"empty choices", map[string]any{"choices": []any{}}, false},
		{"choice not object", map[string]any{"choices": []any{"x"}}, false},
		{"no delta", map[string]any{"choices": []any{map[string]any{}}}, false},
		{"role only", mk(map[string]any{"role": "assistant"}), false},
		{"blank content", mk(map[string]any{"content": "  "}), false},
		{"content", mk(map[string]any{"content": "hi"}), true},
		{"reasoning_content", mk(map[string]any{"reasoning_content": "think"}), true},
		{"reasoning", mk(map[string]any{"reasoning": "think"}), true},
	}
	for _, tc := range cases {
		if got := hasDeltaToken(tc.payload); got != tc.want {
			t.Fatalf("%s: hasDeltaToken = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReportMathHelpers(t *testing.T) {
	if numberValue(float64(2.5)) != 2.5 || numberValue(int(3)) != 3 || numberValue(int64(4)) != 4 || numberValue("x") != 0 {
		t.Fatal("numberValue table failed")
	}
	if durationMillis(1500*time.Millisecond) != 1500 {
		t.Fatal("durationMillis failed")
	}
	if safeRate(0, time.Second) != 0 || safeRate(10, 0) != 0 {
		t.Fatal("safeRate zero guards failed")
	}
	if got := safeRate(10, 2*time.Second); got != 5 {
		t.Fatalf("safeRate = %v, want 5", got)
	}
	if percentile(nil, 50) != 0 {
		t.Fatal("percentile empty failed")
	}
	if got := percentile([]float64{10}, 95); got != 10 {
		t.Fatalf("percentile single = %v, want 10", got)
	}
	if got := percentile([]float64{0, 10}, 50); got != 5 {
		t.Fatalf("percentile interpolation = %v, want 5", got)
	}
	if percent(1, 0) != 0 {
		t.Fatal("percent zero denominator failed")
	}
	if got := percent(3, 4); got != 75 {
		t.Fatalf("percent = %v, want 75", got)
	}
	if errorString(nil) != "" || errorString(fmt.Errorf("boom")) != "boom" {
		t.Fatal("errorString failed")
	}
}

func TestBuildReport_MixedResults(t *testing.T) {
	results := []requestResult{
		{OK: true, TTFTMillis: 100, LatencyMillis: 500, GenerationTokensSec: 40, PromptTokensSec: 900},
		{OK: true, TTFTMillis: 200, LatencyMillis: 700, GenerationTokensSec: 60, PromptTokensSec: 1100},
		{OK: false, Error: "upstream exploded"},
	}
	rep := buildReport("http://r", "m", results, cancelProbeResult{CancelledCleanly: true}, 9)
	if rep.SuccessfulRequests != 2 || rep.FailedRequests != 1 {
		t.Fatalf("counts = %+v", rep)
	}
	if rep.AvgGenerationTokensPerSec != 50 || rep.AvgPromptTokensPerSec != 1000 {
		t.Fatalf("averages = %v/%v, want 50/1000", rep.AvgGenerationTokensPerSec, rep.AvgPromptTokensPerSec)
	}
	if len(rep.Failures) != 1 || rep.Failures[0] != "upstream exploded" {
		t.Fatalf("failures = %v", rep.Failures)
	}
	if rep.ObservedMaxQueueDepth != 9 || !rep.CancelProbe.CancelledCleanly {
		t.Fatalf("passthrough fields lost: %+v", rep)
	}
}

func TestRunProbeGPU_StubbedSnapshots(t *testing.T) {
	old := collectGPUSnapshots
	defer func() { collectGPUSnapshots = old }()
	collectGPUSnapshots = func(ctx context.Context, run gpuprobe.CommandRunner) ([]gpuSnapshot, error) {
		return []gpuSnapshot{{}}, nil
	}

	out, err := captureStdoutV18760(t, func() error { return runProbeGPU(nil) })
	if err != nil {
		t.Fatalf("runProbeGPU stdout path = %v", err)
	}
	if !strings.Contains(out, "captured_at") {
		t.Fatalf("stdout %q missing report", out)
	}

	path := filepath.Join(t.TempDir(), "gpu.json")
	if _, err := captureStdoutV18760(t, func() error { return runProbeGPU([]string{"--output", path}) }); err != nil {
		t.Fatalf("runProbeGPU file path = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("gpu report not written: %v", err)
	}
	if err := runProbeGPU([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag = nil, want parse error")
	}
}

func TestRunCommand_Echo(t *testing.T) {
	out, err := runCommand(context.Background(), "echo", "v18760")
	if err != nil {
		t.Fatalf("runCommand echo = %v", err)
	}
	if !strings.Contains(string(out), "v18760") {
		t.Fatalf("output %q missing marker", out)
	}
}

func TestMainDispatch_ProbeGPUAndUsage(t *testing.T) {
	old := collectGPUSnapshots
	defer func() { collectGPUSnapshots = old }()
	collectGPUSnapshots = func(ctx context.Context, run gpuprobe.CommandRunner) ([]gpuSnapshot, error) {
		return nil, nil
	}
	oldArgs := os.Args
	os.Args = []string{"llm-cluster-router", "probe-gpu"}
	defer func() { os.Args = oldArgs }()
	if _, err := captureStdoutV18760(t, func() error { main(); return nil }); err != nil {
		t.Fatalf("main probe-gpu dispatch: %v", err)
	}

	// usage() is the shared exit-2 text; assert it renders.
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	usage()
	os.Stderr = oldStderr
	_ = w.Close()
	buf, _ := io.ReadAll(r)
	_ = r.Close()
	if !strings.Contains(string(buf), "serve|bench|probe-gpu") {
		t.Fatalf("usage output %q missing subcommand list", string(buf))
	}
}
