package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/channel"
)

// captureStderr mirrors captureStdout for the stream the warnings go to.
// Warnings are deliberately NOT on stdout: --print-routes writes a JSON
// envelope there that a fleet audit parses.
func captureStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	runErr := fn()
	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out, runErr
}

// writeTokenBudgetConfig writes a gateway config whose pooled route budgets by
// TOKENS — the shape no shipped example has any more, and the one an operator
// has to be told about.
func writeTokenBudgetConfig(t *testing.T, tokens, estimate int64) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/gateway.yml"
	cfg := fmt.Sprintf(`listen: "127.0.0.1:0"
routes:
  - name: minimax-pool
    prefix: /minimax-pool/
    upstream: "http://127.0.0.1:9"
    auth: inject
    key_envs: [V18770_BUDGET_K1, V18770_BUDGET_K2] # gitleaks:allow — env NAMES, not secrets
    rotation:
      budget:
        window: 1h
        tokens: %d
        estimate_tokens: %d
    enabled: true
`, tokens, estimate)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestRunGateway_SaysAtStartupThatATokenBudgetIsAdvisory is the wiring, not the
// arithmetic: warnAdvisoryTokenBudgets can be perfect and reach nobody.
//
// It is asserted through --print-routes because that is a terminating
// invocation, and because an operator inspecting a config is exactly who should
// be told what its budgets mean. The advisory is about the CONFIGURATION, so it
// is emitted before the server is built rather than alongside the runtime
// banner.
func TestRunGateway_SaysAtStartupThatATokenBudgetIsAdvisory(t *testing.T) {
	t.Setenv("V18770_BUDGET_K1", "sk-test-1")
	t.Setenv("V18770_BUDGET_K2", "sk-test-2")
	cfgPath := writeTokenBudgetConfig(t, 1000, 100)

	var stdout string
	stderr, err := captureStderr(t, func() error {
		var runErr error
		stdout, runErr = captureStdout(t, func() error {
			return runGateway([]string{"--config", cfgPath, "--print-routes"})
		})
		return runErr
	})
	if err != nil {
		t.Fatalf("runGateway --print-routes = %v, want nil", err)
	}
	for _, want := range []string{"WARNING", `"minimax-pool"`, "tokens/estimate_tokens = 10", "ADVISORY"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("startup stderr does not contain %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stdout, "WARNING") {
		t.Errorf("the warning leaked into the --print-routes JSON envelope on stdout:\n%s", stdout)
	}
}

// TestWarnAdvisoryTokenBudgets_WarnsForTokenBudgetsAndIsSilentForRequestBudgets
// is the startup half of requirement 5.
//
// The warning has to be emitted from the process, not merely be derivable from
// the config: an operator who configures a token cap discovers its magnitude on
// a bill unless something tells them at start, and a document nobody re-reads
// after the first deployment is not that something.
func TestWarnAdvisoryTokenBudgets_WarnsForTokenBudgetsAndIsSilentForRequestBudgets(t *testing.T) {
	cfg := &channel.Config{Listen: "127.0.0.1:0", Routes: []channel.Route{
		{
			Name: "minimax-pool", Prefix: "/minimax-pool/", Upstream: "https://api.example.invalid",
			Auth: channel.AuthInject, KeyEnvs: []string{"K1", "K2"}, Enabled: true,
			Rotation: &channel.RotationConfig{Budget: channel.Budget{
				Window: time.Hour, Tokens: 1000, EstimateTokens: 100, SoftRatio: 0.8,
			}},
		},
		{
			Name: "exa-pool", Prefix: "/exa/", Upstream: "https://api.example.invalid",
			Auth: channel.AuthInject, KeyEnvs: []string{"K3", "K4"}, Enabled: true,
			Rotation: &channel.RotationConfig{Budget: channel.Budget{
				Window: 24 * time.Hour, Requests: 1000, SoftRatio: 0.8,
			}},
		},
	}}

	var buf bytes.Buffer
	warnAdvisoryTokenBudgets(&buf, cfg)
	got := buf.String()

	for _, want := range []string{"WARNING", `"minimax-pool"`, "tokens/estimate_tokens = 10", "ADVISORY"} {
		if !strings.Contains(got, want) {
			t.Errorf("startup output does not contain %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "exa-pool") {
		t.Errorf("a route budgeting by requests must not be warned about:\n%s", got)
	}
	if lines := strings.Count(strings.TrimSpace(got), "\n"); lines != 0 {
		t.Errorf("got %d extra lines, want exactly one warning line per token-budgeted route:\n%s", lines, got)
	}
}

// TestWarnAdvisoryTokenBudgets_SaysNothingWhenNothingBudgetsByTokens keeps the
// banner quiet on the shape every shipped config now has. A warning that fires
// on the recommended configuration is a warning operators learn to scroll past.
func TestWarnAdvisoryTokenBudgets_SaysNothingWhenNothingBudgetsByTokens(t *testing.T) {
	cfg := &channel.Config{Listen: "127.0.0.1:0", Routes: []channel.Route{{
		Name: "qwen-pool", Prefix: "/qwen-pool/", Upstream: "https://api.example.invalid",
		Auth: channel.AuthInject, KeyEnvs: []string{"K1", "K2"}, Enabled: true,
		Rotation: &channel.RotationConfig{Budget: channel.Budget{Window: time.Hour, Requests: 5000}},
	}}}

	var buf bytes.Buffer
	warnAdvisoryTokenBudgets(&buf, cfg)
	if got := buf.String(); got != "" {
		t.Errorf("warnAdvisoryTokenBudgets wrote %q, want nothing", got)
	}
}
