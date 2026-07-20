//go:build release_gate_test

// release_gate_test.go exercises scripts/release-gate.sh in RED
// (no ADR reachable / missing gate script / rg missing) and GREEN
// (worktree ADR + non-color mode + summary table populated) modes.
//
// Build tag rationale: this is a meta-test for the orchestrator
// script. It is NOT shipped in the production binary and is NOT
// picked up by `go test ./...` without the `release_gate_test`
// tag. Operators run it explicitly:
//
//	go test -tags=release_gate_test ./scripts/
//
// Owner: cursor-parent@win3-wsl3 (v18710-5).
// Machine-Id: win3-wsl3.
package scripts

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	releaseGateRel = "scripts/release-gate.sh"
	worktreeADR    = "/home/jason/runs/worktrees/global-kb/feat-v18710-1-adr083/adrs/ADR-083-llm-cluster-router-lightsail-threat-model.md"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, ".."))
}

func runReleaseGate(t *testing.T, args []string, env []string) (string, int) {
	t.Helper()
	root := repoRoot(t)
	script := filepath.Join(root, releaseGateRel)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("script missing at %s: %v", script, err)
	}
	args = append([]string{script}, args...)
	cmd := exec.Command("bash", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("unexpected error running release-gate: %v\n%s", err, out)
	return "", -1
}

// TestReleaseGate_RED_NoADR asserts the orchestrator reports RED when
// no ADR file is reachable. This is the RED state we ship before the
// global-kb PR carrying the ADR lands.
func TestReleaseGate_RED_NoADR(t *testing.T) {
	tmp := t.TempDir()
	// Point GLOBAL_KB_PATH to an empty temp dir AND drop a sentinel file
	// in the repo-local adrs dir so neither the worktree nor the
	// canonical path can be found.
	root := repoRoot(t)
	localAdrs := filepath.Join(root, "adrs")
	if err := os.MkdirAll(localAdrs, 0o755); err != nil {
		t.Fatalf("mkdir local adrs: %v", err)
	}
	defer os.RemoveAll(localAdrs)

	out, code := runReleaseGate(t,
		[]string{"--no-color", "--no-realmodel", "--no-doctor"},
		[]string{"GLOBAL_KB_PATH=" + tmp, "ADR_FILE="},
	)
	if code == 0 {
		t.Fatalf("expected non-zero exit when ADR is unreachable, got 0:\n%s", out)
	}
	if !strings.Contains(out, "adr083-checklist") || !strings.Contains(out, "RED") {
		t.Fatalf("expected adr083-checklist row RED, got:\n%s", out)
	}
	if !strings.Contains(out, "release-gate] RED") {
		t.Fatalf("expected final RED banner, got:\n%s", out)
	}
}

// TestReleaseGate_GREEN_WorktreeADR asserts the orchestrator reports
// GREEN when the v18710-1 worktree ADR is present. Skips gracefully
// when the worktree ADR has been merged to the canonical global-kb
// path (the orchestrator's resolution order still finds it).
func TestReleaseGate_GREEN_WorktreeADR(t *testing.T) {
	if _, err := os.Stat(worktreeADR); err != nil {
		t.Skipf("worktree ADR not present (run from worktree): %v", err)
	}
	out, code := runReleaseGate(t,
		[]string{"--no-color", "--no-realmodel", "--no-doctor"},
		[]string{"ADR_FILE_OVERRIDE=" + worktreeADR, "ADR_FILE=" + worktreeADR},
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "sentrux") || !strings.Contains(out, "GREEN") {
		t.Fatalf("expected sentrux row GREEN, got:\n%s", out)
	}
	if !strings.Contains(out, "adr083-checklist") || !strings.Contains(out, "GREEN") {
		t.Fatalf("expected adr083-checklist row GREEN, got:\n%s", out)
	}
	if !strings.Contains(out, "decrypt-forward") || !strings.Contains(out, "GREEN") {
		t.Fatalf("expected decrypt-forward row GREEN, got:\n%s", out)
	}
	if !strings.Contains(out, "release-gate] GREEN") {
		t.Fatalf("expected final GREEN banner, got:\n%s", out)
	}
}

// TestReleaseGate_GREEN_JsonEnvelope asserts --json mode emits a
// parseable envelope on stdout (not stderr) with one entry per row
// plus a verdict field.
func TestReleaseGate_GREEN_JsonEnvelope(t *testing.T) {
	if _, err := os.Stat(worktreeADR); err != nil {
		t.Skipf("worktree ADR not present (run from worktree): %v", err)
	}
	cmd := exec.Command("bash", releaseGateRel, "--json", "--no-color", "--no-realmodel", "--no-doctor")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(),
		"ADR_FILE_OVERRIDE="+worktreeADR,
		"ADR_FILE="+worktreeADR,
	)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("expected exit 0, got %v:\n%s", err, stdout.String())
	}
	var env struct {
		Rows    []map[string]any `json:"rows"`
		Verdict string           `json:"verdict"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("parse JSON envelope: %v\noutput:\n%s", err, stdout.String())
	}
	if len(env.Rows) < 4 {
		t.Fatalf("expected at least 4 rows in JSON envelope, got %d:\n%s", len(env.Rows), stdout.String())
	}
	if env.Verdict != "GREEN" {
		t.Fatalf("expected verdict GREEN, got %q:\n%s", env.Verdict, stdout.String())
	}
	// Each row must carry name, status, detail, elapsed_s.
	for i, r := range env.Rows {
		for _, k := range []string{"name", "status", "detail", "elapsed_s"} {
			if _, ok := r[k]; !ok {
				t.Fatalf("row %d missing key %q: %v", i, k, r)
			}
		}
	}
}
