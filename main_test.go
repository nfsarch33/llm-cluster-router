package main

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
	"testing"
	"time"
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
		selected := r.selectNode("qwen3.5-27b")
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

	selected := r.selectNode("qwen3.5-27b")
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
	t.Setenv("TEST_CLOUD_KEY", "sk-expanded-123")

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
	if cfg.Nodes[1].APIKey != "sk-expanded-123" {
		t.Fatalf("api_key = %q, want sk-expanded-123", cfg.Nodes[1].APIKey)
	}
}

func writeTestFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0o644)
}
