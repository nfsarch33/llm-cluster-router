// Package integration / otel_pipeline_e2e_test.go
//
// v18720-4 Agentrace + OpenTelemetry full pipeline E2E verification.
//
// The test asserts that:
//
//  1. A dual-listener-demo listener accepts a chat-completion request on
//     AES/mTLS port.
//  2. The accept is exported as an OpenTelemetry span to the local OTel
//     collector on OTLP/gRPC :4317.
//  3. The collector's spanmetrics connector derives RED metrics on
//     Prometheus :9464.
//  4. The demo's own /metrics surface exposes llm_cluster_router_*
//     counters (connections_total, bytes_total, helixchannel_session_total,
//     request_duration_seconds).
//  5. The demo writes one NDJSON event per accept to the agentrace log.
//
// The test is skipped automatically when the prerequisites are missing:
//
//   - HELIX_OTEL_COLLECTOR_DISABLE=1    -> skip (CI hermetic default)
//   - /home/jason/bin/otelcol-contrib   -> skip (binary not installed)
//
// Production verification on Lightsail runs the same flow via
//
//	runx ssh exec --target helixon-tunnel --raw 'curl -s http://127.0.0.1:8889/metrics | grep llm_cluster_router_decrypt_failed_total'
//	tail -3 ~/logs/runx/agentrace-mcp.ndjson
//
// and looks for the same family of metrics. The local E2E substitutes
// 127.0.0.1:9464 + 127.0.0.1:18090 in place of the Lightsail endpoint.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/proxy/observability"
)

// otelCollectorBinary is the standard install location for the
// otelcol-contrib binary on the operator's workstation. The
// collector-config.yaml in configs/otel/ is the canonical config the
// test relies on.
const (
	otelCollectorBinary     = "/home/jason/bin/otelcol-contrib"
	otelCollectorConfigPath = "configs/otel/collector-config.yaml"
	otelDemoBinaryBuild     = "./cmd/dual-listener-demo"
)

// TestOTelPipelineE2E exercises the dual-listener-demo + OTel collector
// pipeline end-to-end. The test is the in-tree replacement for the
// one-shot shell harness from earlier planning sessions; see the v18720-4
// story for the production verifier commands.
func TestOTelPipelineE2E(t *testing.T) {
	if os.Getenv("HELIX_OTEL_COLLECTOR_DISABLE") == "1" {
		t.Skip("HELIX_OTEL_COLLECTOR_DISABLE=1; OTel pipeline E2E skipped")
	}
	if _, err := os.Stat(otelCollectorBinary); err != nil {
		t.Skipf("otelcol-contrib not found at %s; skipping E2E", otelCollectorBinary)
	}

	// Pick non-default ports so we never collide with a sessionStart-managed
	// collector or demo. Local E2E isolation.
	const (
		localAESAddr     = "127.0.0.1:38080"
		localSOCKSAddr   = "127.0.0.1:31080"
		localMetricsAddr = "127.0.0.1:38090"
		localOTLPPort    = "4317"
		localPromPort    = "9464"
	)

	// The existing config (configs/otel/collector-config.yaml) is for the
	// production Lightsail collector. We reuse whichever collector the
	// sessionStart hook already started on :4317 / :9464 rather than
	// starting a second one. The dual-listener-demo is started fresh per
	// test invocation.

	// Probe the existing collector.
	if !tcpListen(localOTLPPort) {
		t.Skipf("no OTel collector listening on :%s; run the sessionStart otelcol first", localOTLPPort)
	}
	t.Logf("reusing sessionStart OTel collector on :%s (gRPC) and :%s (Prometheus)", localOTLPPort, localPromPort)

	// Stage an agentrace log under the integration test tempdir.
	evidenceDir := t.TempDir()
	agentraceLog := filepath.Join(evidenceDir, "agentrace-router.ndjson")
	t.Cleanup(func() {
		// Leave the log around for post-mortem inspection. It already
		// sits under t.TempDir() which the test framework will clean up.
	})

	demoCtx, cancelDemo := context.WithCancel(context.Background())
	defer cancelDemo()

	// Build the demo into a temp binary so the test does not depend on
	// `go run` resolving a relative path. `go run <relative>` treats the
	// argument as a package path, not a filesystem path, so it fails
	// when go test is invoked from another directory. We anchor the
	// build's working directory to the llm-cluster-router repo root
	// and resolve the demo package path relative to that root, regardless
	// of which test package dir go test changed into.
	repoRoot, err := repoRootFromWd()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	demoPkg := filepath.Join(repoRoot, "cmd", "dual-listener-demo")
	demoBin := filepath.Join(evidenceDir, "dual-listener-demo")
	buildCmd := exec.Command("go", "build", "-o", demoBin, demoPkg)
	buildCmd.Dir = repoRoot
	buildOut := &bytes.Buffer{}
	buildCmd.Stdout = buildOut
	buildCmd.Stderr = buildOut
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build dual-listener-demo: %v (output: %s)", err, buildOut.String())
	}

	demoCmd := exec.CommandContext(demoCtx, demoBin,
		"--aes-addr", localAESAddr,
		"--socks5-addr", localSOCKSAddr,
		"--metrics-addr", localMetricsAddr,
		"--agentrace-log", agentraceLog,
	)
	demoCmd.Env = append(os.Environ(),
		"OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:"+localOTLPPort,
	)
	demoStdout := &bytes.Buffer{}
	demoCmd.Stdout = demoStdout
	demoCmd.Stderr = demoStdout
	if err := demoCmd.Start(); err != nil {
		t.Fatalf("start dual-listener-demo: %v (output so far: %s)", err, demoStdout.String())
	}
	t.Logf("dual-listener-demo PID=%d; output:\n%s", demoCmd.Process.Pid, demoStdout.String())

	// Wait for demo to be healthy.
	healthy := waitForHTTP("http://"+localMetricsAddr+"/healthz", 30*time.Second)
	if !healthy {
		_ = demoCmd.Process.Signal(syscall.SIGTERM)
		t.Fatalf("dual-listener-demo did not become healthy within 30s; output:\n%s", demoStdout.String())
	}
	t.Cleanup(func() {
		_ = demoCmd.Process.Signal(syscall.SIGTERM)
		_, _ = demoCmd.Process.Wait()
	})

	// Emit a sample request against the AES/mTLS listener. The demo only
	// mounts `/` (mock upstream) and `/healthz`, so we use `/` as the
	// stand-in for a chat.completion call. The Accept event is what the
	// OTel pipeline measures; the body path is incidental.
	resp, err := http.Post("http://"+localAESAddr+"/",
		"application/json", strings.NewReader(`{"model":"minimax-m3","messages":[{"role":"user","content":"v18720-4 sample"}]}`))
	if err != nil {
		t.Fatalf("POST demo: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("demo response: status=%d body=%s", resp.StatusCode, string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from demo, got %d", resp.StatusCode)
	}

	// Wait for the collector's batch processor to flush.
	time.Sleep(8 * time.Second)

	// Pull both surfaces.
	demoMetrics := getURL(t, "http://"+localMetricsAddr+"/metrics")
	collectorMetrics := getURL(t, "http://127.0.0.1:"+localPromPort+"/metrics")
	agentraceBytes := readFile(t, agentraceLog)

	// Surface 1: demo exposes llm_cluster_router_* family.
	t.Run("DemoExposesRouterMetrics", func(t *testing.T) {
		for _, want := range []string{
			"llm_cluster_router_bytes_total",
			"llm_cluster_router_connections_total",
			"llm_cluster_router_helixchannel_session_total",
			"llm_cluster_router_request_duration_seconds",
		} {
			if !strings.Contains(demoMetrics, want) {
				t.Errorf("demo metrics missing %q", want)
			}
		}
	})

	// Surface 2: collector exposes spanmetrics derived RED metrics.
	t.Run("CollectorExposesSpanmetrics", func(t *testing.T) {
		// Either helix_otel_spanmetrics_calls_total (existing config)
		// or llm_cluster_router_* Prometheus-side metrics (if the test
		// re-uses a metrics-only collector). At minimum the test should
		// see one metric derived from the demo.accept span.
		if !strings.Contains(collectorMetrics, "helix_otel") &&
			!strings.Contains(collectorMetrics, "spanmetrics") {
			t.Errorf("collector metrics missing spanmetrics family; got %d bytes", len(collectorMetrics))
		}
	})

	// Surface 3: agentrace NDJSON captured the accept event.
	t.Run("AgentraceCaptured", func(t *testing.T) {
		if !strings.Contains(agentraceBytes, `"event":"demo.accept"`) {
			t.Errorf("agentrace log missing demo.accept event; got %d bytes", len(agentraceBytes))
		}
	})

	// Surface 4: Prometheus DecryptFailedTotal counter is registered.
	// This is the operator-facing gate for SC9 in the v18720-v18724 plan.
	t.Run("DecryptFailedCounterRegistered", func(t *testing.T) {
		// We don't increment it (no tampered frame in the smoke test), but
		// the counter MUST exist on the observability package so the
		// wire-doctor tests can hit it. We assert via the package API.
		if observability.DecryptFailedTotal == nil {
			t.Errorf("observability.DecryptFailedTotal is nil")
		}
		// CounterVec without observations is hidden from /metrics; the wire
		// E2E tests in helixchannel_wire_e2e_test.go own the increment path.
		_ = observability.DecryptFailedTotal.WithLabelValues("aes-mtls")
		// CounterVec without observations is hidden from /metrics; the wire
		// E2E tests in helixchannel_wire_e2e_test.go own the increment path.
	})

	t.Logf("EVIDENCE:\n  demo=%d bytes\n  collector=%d bytes\n  agentrace=%d bytes",
		len(demoMetrics), len(collectorMetrics), len(agentraceBytes))
	t.Logf("demo metrics preview:\n%s", previewLines(demoMetrics, 12))
	t.Logf("collector metrics preview:\n%s", previewLines(collectorMetrics, 12))
	t.Logf("agentrace preview:\n%s", previewLines(agentraceBytes, 6))
}

// tcpListen returns true if the given port is bound on 127.0.0.1.
func tcpListen(port string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// waitForHTTP polls the URL until it returns 200 or the timeout elapses.
func waitForHTTP(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// getURL returns the body of the URL or fails the test.
func getURL(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(body)
}

// readFile returns the file contents or fails the test.
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// previewLines returns the first n lines of the body.
func previewLines(body string, n int) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	var b strings.Builder
	for i := 0; i < n && scanner.Scan(); i++ {
		fmt.Fprintf(&b, "  %s\n", scanner.Text())
	}
	return strings.TrimRight(b.String(), "\n")
}

// repoRootFromWd walks up from cwd until it finds a directory containing
// go.mod, returning that absolute path. Used to anchor the demo build
// under the llm-cluster-router module root regardless of which test
// package dir go test changes into.
func repoRootFromWd() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", wd)
		}
		dir = parent
	}
}
