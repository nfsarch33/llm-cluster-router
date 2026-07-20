package main

// runx-public-repo-gate: allow-file personal_path_id
//
// This file intentionally references the `ai-gateway.zende.sk` host as
// part of the regression coverage for the upstream block-list
// (`forbiddenUpstreamHostSuffixes` in main.go). The literal anchors a
// security guardrail: the router refuses to forward prompts/secrets to
// corporate AI gateways the operator did not opt into. Sunset: after
// the 2026-05-28 ZD AI-gateway contract cleanup the literal can be
// removed entirely and this directive reverted. See
// `backlog/v321-public-repo-cleanup.md` (story v321-3) for context.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	cfg "github.com/nfsarch33/llm-cluster-router/internal/config"
)

func TestProbeNodeUsesConfiguredHealthPath(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	node := testNode(t, server.URL)
	hc := healthConfig{
		Path:    "/health",
		Timeout: durationValue{Duration: time.Second},
	}

	if !probeNode(context.Background(), hc, node) {
		t.Fatal("expected probeNode to succeed on configured health path")
	}
}

func TestProbeNodeFallsBackToModelsForOllamaStyleUpstream(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			http.NotFound(w, r)
		case "/v1/models":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	node := testNode(t, server.URL)
	hc := healthConfig{
		Path:    "/health",
		Timeout: durationValue{Duration: time.Second},
	}

	if !probeNode(context.Background(), hc, node) {
		t.Fatal("expected probeNode to fall back to /v1/models")
	}
}

func TestProbeNodeDoesNotMaskNon404HealthFailures(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	node := testNode(t, server.URL)
	hc := healthConfig{
		Path:    "/health",
		Timeout: durationValue{Duration: time.Second},
	}

	if probeNode(context.Background(), hc, node) {
		t.Fatal("expected probeNode to fail on non-404 health failure")
	}
}

func testNode(t *testing.T, rawURL string) *upstreamNode {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return &upstreamNode{
		cfg:     nodeConfig{Name: "test-node", Tier: "fast"},
		baseURL: parsed,
	}
}

func TestParseGPUCSV(t *testing.T) {
	t.Parallel()

	raw := "0, GPU-3090, 00000000:1B:00.0, NVIDIA GeForce RTX 3090, 24576 MiB, 37 MiB, 0 %, 21\n" +
		"1, GPU-4070, 00000000:68:00.0, NVIDIA GeForce RTX 4070 Ti SUPER, 16376 MiB, 3561 MiB, 22 %, 41\n"

	got, err := parseGPUCSV(raw)
	if err != nil {
		t.Fatalf("parseGPUCSV returned error: %v", err)
	}

	want := []gpuSnapshot{
		{
			Index:          0,
			UUID:           "GPU-3090",
			PCIBusID:       "00000000:1B:00.0",
			Name:           "NVIDIA GeForce RTX 3090",
			MemoryTotalMiB: 24576,
			MemoryUsedMiB:  37,
			UtilizationGPU: 0,
			TemperatureC:   21,
		},
		{
			Index:          1,
			UUID:           "GPU-4070",
			PCIBusID:       "00000000:68:00.0",
			Name:           "NVIDIA GeForce RTX 4070 Ti SUPER",
			MemoryTotalMiB: 16376,
			MemoryUsedMiB:  3561,
			UtilizationGPU: 22,
			TemperatureC:   41,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGPUCSV mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseComputeAppsCSV(t *testing.T) {
	t.Parallel()

	raw := "GPU-4070, 1234, python, 2048 MiB\nGPU-4070, 5678, ollama, 512 MiB\n"

	got, err := parseComputeAppsCSV(raw)
	if err != nil {
		t.Fatalf("parseComputeAppsCSV returned error: %v", err)
	}

	want := map[string][]gpuProcess{
		"GPU-4070": {
			{PID: 1234, ProcessName: "python", UsedMemoryMiB: 2048},
			{PID: 5678, ProcessName: "ollama", UsedMemoryMiB: 512},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseComputeAppsCSV mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseComputeAppsCSVAllowsUnavailableMemory(t *testing.T) {
	t.Parallel()

	raw := "GPU-3090, 4321, python, [N/A]\n"

	got, err := parseComputeAppsCSV(raw)
	if err != nil {
		t.Fatalf("parseComputeAppsCSV returned error: %v", err)
	}

	want := map[string][]gpuProcess{
		"GPU-3090": {
			{PID: 4321, ProcessName: "python", UsedMemoryMiB: 0},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseComputeAppsCSV mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestAttachGPUProcesses(t *testing.T) {
	t.Parallel()

	gpus := []gpuSnapshot{
		{UUID: "GPU-3090"},
		{UUID: "GPU-4070"},
	}
	processes := map[string][]gpuProcess{
		"GPU-4070": {
			{PID: 5678, ProcessName: "ollama", UsedMemoryMiB: 512},
		},
	}

	got := attachGPUProcesses(gpus, processes)

	if len(got[0].Processes) != 0 {
		t.Fatalf("expected no processes on first gpu, got %#v", got[0].Processes)
	}
	if !reflect.DeepEqual(got[1].Processes, processes["GPU-4070"]) {
		t.Fatalf("expected attached processes on second gpu, got %#v", got[1].Processes)
	}
}

func TestRunBenchRequestSetsMaxTokens(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if got := int(payload["max_tokens"].(float64)); got != 64 {
			t.Fatalf("max_tokens = %d, want 64", got)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(server.Close)

	result := runBenchRequest(server.Client(), server.URL, "qwen3.5-27b", "local", "hello", time.Second, 64)
	if !result.OK {
		t.Fatalf("runBenchRequest returned error: %#v", result)
	}
}

func TestIsRetryableConnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("timeout"), false},
		{fmt.Errorf("server closed idle connection"), true},
		{fmt.Errorf("read: connection reset by peer"), true},
		{fmt.Errorf("write: broken pipe"), true},
		{fmt.Errorf("wrapped: server closed idle connection"), true},
	}
	for _, tt := range tests {
		if got := isRetryableConnError(tt.err); got != tt.want {
			t.Errorf("isRetryableConnError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

type failOnceTransport struct {
	inner    http.RoundTripper
	failed   bool
	failErr  error
	attempts int
}

func (t *failOnceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.attempts++
	if !t.failed {
		t.failed = true
		return nil, t.failErr
	}
	return t.inner.RoundTrip(req)
}

func TestHandleProxyRetriesOnIdleConnectionClose(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	t.Cleanup(upstream.Close)

	parsed, _ := url.Parse(upstream.URL)
	node := &upstreamNode{
		cfg:     nodeConfig{Name: "retry-node", Tier: "fast", Models: []string{"test-model"}, Weight: 1},
		baseURL: parsed,
	}
	node.healthy.Store(true)

	transport := &failOnceTransport{
		inner:   http.DefaultTransport,
		failErr: fmt.Errorf("Post %q: server closed idle connection", upstream.URL),
	}

	r := &router{
		cfg: config{
			Defaults: defaults{
				MaxQueueDepth:  8,
				MaxConcurrency: 2,
				RequestTimeout: durationValue{Duration: 5 * time.Second},
				MaxBodySize:    1 << 20,
			},
		},
		client:    &http.Client{Timeout: 5 * time.Second, Transport: transport},
		semaphore: make(chan struct{}, 2),
		nodes:     []*upstreamNode{node},
	}

	body := `{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.handleProxy(w, req)

	if transport.attempts != 2 {
		t.Fatalf("expected 2 transport attempts (1 fail + 1 retry), got %d", transport.attempts)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after retry, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleProxyFallsBackToSecondUpstreamWhenPrimaryConnectionFails(t *testing.T) {
	t.Parallel()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"from-fallback"}}]}`))
	}))
	t.Cleanup(fallback.Close)

	fallbackParsed, err := url.Parse(fallback.URL)
	if err != nil {
		t.Fatalf("parse fallback url: %v", err)
	}

	deadParsed, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("parse dead url: %v", err)
	}

	const model = "shared-model"
	const tier = "fault"

	deadNode := &upstreamNode{
		cfg: nodeConfig{
			Name:     "primary-dead",
			Tier:     tier,
			Priority: 0,
			Weight:   1,
			Models:   []string{model},
		},
		baseURL: deadParsed,
	}
	deadNode.healthy.Store(true)

	fallbackNode := &upstreamNode{
		cfg: nodeConfig{
			Name:     "fallback-live",
			Tier:     tier,
			Priority: 1,
			Weight:   1,
			Models:   []string{model},
		},
		baseURL: fallbackParsed,
	}
	fallbackNode.healthy.Store(true)

	r := &router{
		cfg: config{
			Defaults: defaults{
				MaxQueueDepth:  8,
				MaxConcurrency: 4,
				RequestTimeout: durationValue{Duration: 5 * time.Second},
				MaxBodySize:    1 << 20,
			},
		},
		client:    &http.Client{Timeout: 2 * time.Second},
		semaphore: make(chan struct{}, 4),
		nodes:     []*upstreamNode{deadNode, fallbackNode},
	}

	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tier", tier)
	w := httptest.NewRecorder()

	r.handleProxy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from fallback upstream, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "from-fallback") {
		t.Fatalf("expected fallback body in response, got %q", w.Body.String())
	}
	if deadNode.healthy.Load() {
		t.Fatal("expected dead primary node to be marked unhealthy after failure")
	}
}

func TestHandleProxyConcurrentRequestsUseFallbackWhenPrimaryDead(t *testing.T) {
	t.Parallel()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"from-fallback"}}]}`))
	}))
	t.Cleanup(fallback.Close)

	fallbackParsed, err := url.Parse(fallback.URL)
	if err != nil {
		t.Fatalf("parse fallback url: %v", err)
	}
	deadParsed, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("parse dead url: %v", err)
	}

	const model = "shared-model"
	const tier = "fault-concurrent"

	deadNode := &upstreamNode{
		cfg:     nodeConfig{Name: "primary-dead-conc", Tier: tier, Priority: 0, Weight: 1, Models: []string{model}},
		baseURL: deadParsed,
	}
	deadNode.healthy.Store(true)

	fallbackNode := &upstreamNode{
		cfg:     nodeConfig{Name: "fallback-live-conc", Tier: tier, Priority: 1, Weight: 1, Models: []string{model}},
		baseURL: fallbackParsed,
	}
	fallbackNode.healthy.Store(true)

	const maxConc = 6
	r := &router{
		cfg: config{
			Defaults: defaults{
				MaxQueueDepth:  32,
				MaxConcurrency: maxConc,
				RequestTimeout: durationValue{Duration: 5 * time.Second},
				MaxBodySize:    1 << 20,
			},
		},
		client:    &http.Client{Timeout: 2 * time.Second},
		semaphore: make(chan struct{}, maxConc),
		nodes:     []*upstreamNode{deadNode, fallbackNode},
	}

	const nReq = 12
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
	errs := make(chan string, nReq)
	var wg sync.WaitGroup
	wg.Add(nReq)
	for i := 0; i < nReq; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Tier", tier)
			w := httptest.NewRecorder()
			r.handleProxy(w, req)
			if w.Code != http.StatusOK {
				errs <- fmt.Sprintf("status=%d body=%s", w.Code, w.Body.String())
				return
			}
			if !strings.Contains(w.Body.String(), "from-fallback") {
				errs <- fmt.Sprintf("missing fallback marker: %q", w.Body.String())
				return
			}
			errs <- ""
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		if msg != "" {
			t.Fatal(msg)
		}
	}
}

func TestRunCancelProbeSetsMaxTokens(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if got := int(payload["max_tokens"].(float64)); got != 64 {
			t.Fatalf("max_tokens = %d, want 64", got)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(server.Close)

	result := runCancelProbe(server.URL, "qwen3.5-27b", "local", "hello", 10*time.Millisecond, 64)
	if result.Error != "" {
		t.Fatalf("runCancelProbe returned error: %#v", result)
	}
}

func TestSelectNodePrefersLowerPriority(t *testing.T) {
	t.Parallel()

	localURL, _ := url.Parse("http://local:8001")
	cloudURL, _ := url.Parse("http://cloud:443")

	localNode := &upstreamNode{
		cfg:     nodeConfig{Name: "local-27b", Tier: "agent", Weight: 1, Priority: 0, Models: []string{"qwen3.5-27b"}},
		baseURL: localURL,
	}
	localNode.healthy.Store(true)

	cloudNode := &upstreamNode{
		cfg:     nodeConfig{Name: "cloud-deepseek", Tier: "reasoning", Weight: 1, Priority: 10, Models: []string{"qwen3.5-27b"}, APIKey: "sk-test"},
		baseURL: cloudURL,
	}
	cloudNode.healthy.Store(true)

	r := &router{nodes: []*upstreamNode{cloudNode, localNode}}

	for i := 0; i < 10; i++ {
		selected := r.selectNode("qwen3.5-27b", "")
		if selected == nil {
			t.Fatal("selectNode returned nil")
		}
		if selected.cfg.Name != "local-27b" {
			t.Fatalf("iteration %d: selected %q, want local-27b (lower priority)", i, selected.cfg.Name)
		}
	}
}

func TestSelectNodeFallsBackToCloudWhenLocalUnhealthy(t *testing.T) {
	t.Parallel()

	localURL, _ := url.Parse("http://local:8001")
	cloudURL, _ := url.Parse("http://cloud:443")

	localNode := &upstreamNode{
		cfg:     nodeConfig{Name: "local-27b", Tier: "agent", Weight: 1, Priority: 0, Models: []string{"qwen3.5-27b"}},
		baseURL: localURL,
	}
	localNode.healthy.Store(false)

	cloudNode := &upstreamNode{
		cfg:     nodeConfig{Name: "cloud-deepseek", Tier: "reasoning", Weight: 1, Priority: 10, Models: []string{"qwen3.5-27b"}, APIKey: "sk-test"},
		baseURL: cloudURL,
	}
	cloudNode.healthy.Store(true)

	r := &router{nodes: []*upstreamNode{localNode, cloudNode}}

	selected := r.selectNode("qwen3.5-27b", "")
	if selected == nil {
		t.Fatal("selectNode returned nil")
	}
	if selected.cfg.Name != "cloud-deepseek" {
		t.Fatalf("selected %q, want cloud-deepseek (local unhealthy)", selected.cfg.Name)
	}
}

func TestSelectNodeAPIKeySetOnNode(t *testing.T) {
	t.Parallel()

	cloudURL, _ := url.Parse("http://cloud:443")
	node := &upstreamNode{
		cfg:     nodeConfig{Name: "cloud-node", APIKey: "sk-secret", Weight: 1, Priority: 10, Models: []string{"model-x"}},
		baseURL: cloudURL,
	}
	node.healthy.Store(true)

	if node.cfg.APIKey != "sk-secret" {
		t.Fatalf("api_key = %q, want sk-secret", node.cfg.APIKey)
	}
}

func TestNextAPIKey_RoundRobin(t *testing.T) {
	t.Parallel()
	node := &upstreamNode{
		cfg: nodeConfig{
			Name:    "multi-key-node",
			APIKeys: []string{"key-a", "key-b", "key-c"},
		},
	}
	got := make([]string, 6)
	for i := range got {
		got[i] = node.nextAPIKey()
	}
	want := []string{"key-a", "key-b", "key-c", "key-a", "key-b", "key-c"}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("call %d: got %q, want %q", i, got[i], w)
		}
	}
}

func TestNextAPIKey_FallbackToSingle(t *testing.T) {
	t.Parallel()
	node := &upstreamNode{
		cfg: nodeConfig{Name: "single-key", APIKey: "sk-solo"},
	}
	if got := node.nextAPIKey(); got != "sk-solo" {
		t.Fatalf("nextAPIKey() = %q, want sk-solo", got)
	}
}

func TestNextAPIKey_Empty(t *testing.T) {
	t.Parallel()
	node := &upstreamNode{cfg: nodeConfig{Name: "no-key"}}
	if got := node.nextAPIKey(); got != "" {
		t.Fatalf("nextAPIKey() = %q, want empty", got)
	}
}

func TestLoadConfigExpandsAPIKeysEnvVars(t *testing.T) {
	t.Setenv("TEST_MK1", "sk-one") // gitleaks:allow
	t.Setenv("TEST_MK2", "sk-two") // gitleaks:allow

	yamlContent := `
listen: ":9999"
nodes:
  - name: multi-key
    url: http://localhost:8001
    tier: fast
    weight: 1
    api_keys:
      - ${TEST_MK1}
      - ${TEST_MK2}
    models: ["model-x"]
`
	dir := t.TempDir()
	path := dir + "/test-router.yml"
	if err := writeTestFile(t, path, yamlContent); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Nodes[0].APIKeys) != 2 {
		t.Fatalf("api_keys len = %d, want 2", len(cfg.Nodes[0].APIKeys))
	}
	if cfg.Nodes[0].APIKeys[0] != "sk-one" { // gitleaks:allow
		t.Fatalf("api_keys[0] = %q, want sk-one", cfg.Nodes[0].APIKeys[0]) // gitleaks:allow
	}
	if cfg.Nodes[0].APIKeys[1] != "sk-two" { // gitleaks:allow
		t.Fatalf("api_keys[1] = %q, want sk-two", cfg.Nodes[0].APIKeys[1]) // gitleaks:allow
	}
}

func TestExpandEnvValue(t *testing.T) {
	t.Setenv("TEST_EXPAND_KEY", "sk-from-env")

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"literal key", "sk-hardcoded", "sk-hardcoded"},
		{"empty string", "", ""},
		{"env var present", "${TEST_EXPAND_KEY}", "sk-from-env"},
		{"env var missing", "${MISSING_VAR_XYZ}", ""},
		{"partial syntax", "${INCOMPLETE", "${INCOMPLETE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandEnvValue(tt.input)
			if got != tt.want {
				t.Fatalf("expandEnvValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoadConfigExpandsAPIKeyEnvVar(t *testing.T) {
	// Test fixture: literal "sk-expanded-123" is a synthetic value
	// used to verify env-var expansion in node.api_key. It is not a
	// real API key. The trailing comments suppress gitleaks.
	t.Setenv("TEST_CLOUD_KEY", "sk-expanded-123") // gitleaks:allow

	yamlContent := `
listen: ":9999"
nodes:
  - name: test-local
    url: http://localhost:8001
    tier: fast
    weight: 1
    models: ["model-a"]
  - name: test-cloud
    url: https://api.example.com
    tier: reasoning
    priority: 10
    weight: 1
    api_key: ${TEST_CLOUD_KEY}
    models: ["model-b"]
`
	dir := t.TempDir()
	path := dir + "/test-router.yml"
	if err := writeTestFile(t, path, yamlContent); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(cfg.Nodes))
	}
	if cfg.Nodes[1].APIKey != "sk-expanded-123" { // gitleaks:allow
		t.Fatalf("api_key = %q, want sk-expanded-123", cfg.Nodes[1].APIKey) // gitleaks:allow
	}
}

func writeTestFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0o644)
}

// TestLoadConfigRejectsForbiddenUpstreamHosts asserts that loadConfig
// refuses to start the router when any node URL points at a corporate
// or managed AI gateway. Personal forks of llm-cluster-router are
// self-hosted-cluster-only by design (see router.sample.yml). Allowing
// a forbidden upstream would silently route every prompt — including
// any that contain personal data, secrets, or PII — into the wrong
// trust boundary.
func TestLoadConfigRejectsForbiddenUpstreamHosts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		url  string
	}{
		{"zende_sk_subdomain", "https://ai-gateway.zende.sk/v1"},
		{"zende_sk_apex", "https://zende.sk"},
		{"zendesk_corp_subdomain", "https://corp.zendesk.com/llm"},
		{"zendesk_internal_subdomain", "https://ai-gateway.internal.zendesk.com"},
		{"zendesk_uppercase", "https://AI-GATEWAY.ZENDE.SK/v1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			yamlContent := `
listen: ":9999"
nodes:
  - name: forbidden
    url: ` + tc.url + `
    tier: reasoning
    weight: 1
    models: ["forbidden-model"]
`
			dir := t.TempDir()
			path := dir + "/forbidden-router.yml"
			if err := writeTestFile(t, path, yamlContent); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfig(path)
			if err == nil {
				t.Fatalf("loadConfig(%q): expected error, got nil", tc.url)
			}
			if !strings.Contains(err.Error(), "forbidden upstream host") {
				t.Fatalf("loadConfig(%q): error %q does not mention 'forbidden upstream host'", tc.url, err)
			}
		})
	}
}

// TestLoadConfigAllowsLegitimateUpstreamHosts confirms the forbidden-host
// guard does NOT misfire on the documented happy paths: localhost
// clusters, a custom OpenAI-compatible cloud (deepseek), and an
// arbitrary self-hosted IP.
func TestLoadConfigAllowsLegitimateUpstreamHosts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		url  string
	}{
		{"loopback", "http://127.0.0.1:8001"},
		{"private_lan", "http://10.0.0.7:8001"},
		{"deepseek_cloud", "https://api.deepseek.com"},
		{"openrouter", "https://openrouter.ai"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			yamlContent := `
listen: ":9999"
nodes:
  - name: ok
    url: ` + tc.url + `
    tier: fast
    weight: 1
    models: ["ok-model"]
`
			dir := t.TempDir()
			path := dir + "/ok-router.yml"
			if err := writeTestFile(t, path, yamlContent); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err != nil {
				t.Fatalf("loadConfig(%q): unexpected error: %v", tc.url, err)
			}
		})
	}
}

func TestBearerAuthNoTokenConfigured(t *testing.T) {
	t.Parallel()
	handler := bearerAuth("")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when no auth configured, got %d", rec.Code)
	}
}

func TestBearerAuthValidToken(t *testing.T) {
	t.Parallel()
	handler := bearerAuth("secret-token")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d", rec.Code)
	}
}

func TestBearerAuthInvalidToken(t *testing.T) {
	t.Parallel()
	handler := bearerAuth("secret-token")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with invalid token, got %d", rec.Code)
	}
}

func TestBearerAuthMissingHeader(t *testing.T) {
	t.Parallel()
	handler := bearerAuth("secret-token")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with missing auth header, got %d", rec.Code)
	}
}

func TestHandleProxyRetriesAlternateUpstreamOnDialFailure(t *testing.T) {
	t.Parallel()

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(healthy.Close)

	r := &router{
		cfg: config{Defaults: defaults{
			MaxQueueDepth:  8,
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
			MaxBodySize:    1 << 20,
		}},
		client:    &http.Client{Timeout: time.Second},
		semaphore: make(chan struct{}, 1),
	}
	badURL, _ := url.Parse("http://127.0.0.1:1")
	goodURL, _ := url.Parse(healthy.URL)
	bad := &upstreamNode{
		cfg:     nodeConfig{Name: "dead-primary", Tier: "agent", Priority: 1, Weight: 1, Models: []string{"fault-model"}},
		baseURL: badURL,
	}
	good := &upstreamNode{
		cfg:     nodeConfig{Name: "healthy-fallback", Tier: "agent", Priority: 2, Weight: 1, Models: []string{"fault-model"}},
		baseURL: goodURL,
	}
	bad.healthy.Store(true)
	good.healthy.Store(true)
	r.nodes = []*upstreamNode{bad, good}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"fault-model","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected fallback 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if bad.healthy.Load() {
		t.Fatal("expected failed primary to be marked unhealthy")
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestNewRouterSkipsDisabledNodes(t *testing.T) {
	t.Parallel()

	cfg := config{
		Defaults: defaults{MaxConcurrency: 1, RequestTimeout: durationValue{Duration: time.Second}},
		Nodes: []nodeConfig{
			{Name: "primary", URL: "http://primary.example", Tier: "primary", Models: []string{"qwen35-27b-main"}},
			{Name: "coding-36", URL: "http://qwen36.example", Tier: "agent-ab", Enabled: "false", Models: []string{"qwen36-27b-int4"}},
		},
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	if len(r.nodes) != 1 {
		t.Fatalf("expected disabled coding-36 node to be skipped, got %d nodes", len(r.nodes))
	}
	if r.nodes[0].cfg.Name != "primary" {
		t.Fatalf("expected only primary node, got %q", r.nodes[0].cfg.Name)
	}
}

func TestSelectNodeHonorsXTierForOptInLane(t *testing.T) {
	t.Parallel()

	cfg := config{
		Defaults: defaults{MaxConcurrency: 1, RequestTimeout: durationValue{Duration: time.Second}},
		Nodes: []nodeConfig{
			{Name: "primary", URL: "http://primary.example", Tier: "primary", Priority: 1, Models: []string{"qwen35-27b-main"}},
			{Name: "coding-36", URL: "http://qwen36.example", Tier: "agent-ab", Priority: 9, Models: []string{"qwen36-27b-int4"}},
		},
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	if got := r.selectNode("", ""); got == nil || got.cfg.Name != "primary" {
		t.Fatalf("default selection = %#v, want primary", got)
	}
	if got := r.selectNode("", "agent-ab"); got == nil || got.cfg.Name != "coding-36" {
		t.Fatalf("X-Tier agent-ab selection = %#v, want coding-36", got)
	}
	if got := r.selectNode("qwen36-27b-int4", ""); got == nil || got.cfg.Name != "coding-36" {
		t.Fatalf("model opt-in selection = %#v, want coding-36", got)
	}
}

func TestLoadConfigExpandsAuthToken(t *testing.T) {
	t.Setenv("TEST_ROUTER_AUTH", "my-secret-auth")

	yamlContent := `
listen: ":9998"
auth_token: ${TEST_ROUTER_AUTH}
nodes:
  - name: test-node
    url: http://localhost:8001
    tier: fast
    weight: 1
    models: ["model-a"]
`
	dir := t.TempDir()
	path := dir + "/test-auth-router.yml"
	if err := writeTestFile(t, path, yamlContent); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.AuthToken != "my-secret-auth" {
		t.Fatalf("auth_token = %q, want my-secret-auth", cfg.AuthToken)
	}
}

// TestBuildReloadable_WiresTunnel validates that a NodeConfig with
// tunnel.enabled:true attaches a per-node *http.Client backed by
// tunnel.DialContext, and that a NodeConfig without the tunnel
// block leaves the per-node client nil. This proves the wiring is
// conditional and does not affect non-tunnelled nodes.
func TestBuildReloadable_WiresTunnel(t *testing.T) {
	t.Parallel()

	// Direct node: tunnelClient must be nil — the router-wide
	// client carries the request.
	directCfg := config{
		Defaults: defaults{
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
		},
		Nodes: []nodeConfig{
			{Name: "direct", URL: "http://api.example.invalid", Tier: "fast"},
		},
	}
	directNodes, directClient, _, err := buildReloadable(directCfg)
	if err != nil {
		t.Fatalf("buildReloadable(direct): %v", err)
	}
	if directClient == nil {
		t.Fatal("expected non-nil router-wide client for direct config")
	}
	if directNodes[0].tunnelClient != nil {
		t.Fatalf("direct node should not have tunnelClient; got %+v", directNodes[0])
	}

	// Tunnelled node: buildReloadable must succeed and attach a
	// non-nil tunnelClient. We do NOT dial ssh here — only that
	// the closure-bound DialContext is wired. A separate test in
	// the tunnel package verifies the actual ssh invocation.
	tunnelCfg := config{
		Defaults: defaults{
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
		},
		Nodes: []nodeConfig{
			{
				Name: "jump-only",
				URL:  "http://api.example.invalid",
				Tier: "fast",
				Tunnel: cfg.TunnelConfig{
					Enabled:      true,
					Host:         "jump.example",
					Port:         22,
					User:         "u",
					IdentityFile: "/k",
					LocalPort:    14443,
				},
			},
		},
	}
	tunnelNodes, tunnelClient, _, err := buildReloadable(tunnelCfg)
	if err != nil {
		t.Fatalf("buildReloadable(tunnelled): %v", err)
	}
	if tunnelClient == nil {
		t.Fatal("expected non-nil router-wide client for tunnelled config")
	}
	if len(tunnelNodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(tunnelNodes))
	}
	if tunnelNodes[0].tunnelClient == nil {
		t.Fatalf("expected non-nil tunnelClient on tunnelled node; got %+v", tunnelNodes[0])
	}

	// Bad tunnel config (missing identity file) must fail fast
	// at boot, not at first request.
	badCfg := config{
		Defaults: defaults{
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
		},
		Nodes: []nodeConfig{
			{
				Name: "broken",
				URL:  "http://api.example.invalid",
				Tier: "fast",
				Tunnel: cfg.TunnelConfig{
					Enabled:   true,
					Host:      "jump.example",
					Port:      22,
					User:      "u",
					LocalPort: 14443,
					// IdentityFile deliberately empty
				},
			},
		},
	}
	if _, _, _, err := buildReloadable(badCfg); err == nil {
		t.Fatal("expected buildReloadable to fail for invalid tunnel config")
	}
}
