// ADR-083: C13 — release-gate superset (verifier-script TDD)
//go:build adr083_test

// adr083_checklist_test.go exercises scripts/adr083-checklist.sh in both
// RED (no ADR file) and GREEN (worktree ADR file) modes.
//
// Build tag rationale: this is a meta-test for the verifier script. It is
// NOT shipped in the production binary and is NOT picked up by `go test
// ./...` without the `adr083_test` tag. Operators run it explicitly:
//
//	go test -tags=adr083_test ./scripts/
//
// Owner: cursor-parent@win3-wsl3 (v18710-1).
// Machine-Id: win3-wsl3.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	scriptRel   = "scripts/adr083-checklist.sh"
	worktreeADR = "/home/jason/runs/worktrees/global-kb/feat-v18710-1-adr083/adrs/ADR-083-llm-cluster-router-lightsail-threat-model.md"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	// Locate the script relative to this test file.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// scripts/ is a sibling of the test file's directory.
	root := filepath.Clean(filepath.Join(wd, ".."))
	return root
}

func runChecklist(t *testing.T, env []string) (string, int) {
	t.Helper()
	root := repoRoot(t)
	script := filepath.Join(root, scriptRel)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("script missing at %s: %v", script, err)
	}
	cmd := exec.Command("bash", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	// We expect non-zero exits on RED; combine and surface both.
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("unexpected error running checklist: %v\n%s", err, out)
	return "", -1
}

// TestChecklist_RED_NoADR asserts that the verifier fails (exit 2) when
// no ADR file is reachable from the canonical GLOBAL_KB_PATH.
func TestChecklist_RED_NoADR(t *testing.T) {
	// Point GLOBAL_KB_PATH to a temp dir without the ADR.
	tmp := t.TempDir()
	out, code := runChecklist(t, []string{
		"GLOBAL_KB_PATH=" + tmp,
	})
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0; output:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "ADR_FILE_MISSING") {
		t.Fatalf("expected ADR_FILE_MISSING failure, got:\n%s", out)
	}
}

// TestChecklist_GREEN_WorktreeADR asserts the verifier passes when the
// worktree ADR is provided via ADR_FILE_OVERRIDE.
func TestChecklist_GREEN_WorktreeADR(t *testing.T) {
	if _, err := os.Stat(worktreeADR); err != nil {
		t.Skipf("worktree ADR not present (run from worktree): %v", err)
	}
	out, code := runChecklist(t, []string{
		"ADR_FILE_OVERRIDE=" + worktreeADR,
		"NO_COLOR_ENV=1",
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; output:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS [POSTCONDITION_COUNT]") {
		t.Fatalf("expected POSTCONDITION_COUNT PASS, got:\n%s", out)
	}
	if !strings.Contains(out, "GREEN — release-ready per ADR-083") {
		t.Fatalf("expected final GREEN banner, got:\n%s", out)
	}
}

// TestChecklist_GREEN_JsonOutput asserts --json mode emits a parseable
// JSON envelope with the expected keys.
func TestChecklist_GREEN_JsonOutput(t *testing.T) {
	if _, err := os.Stat(worktreeADR); err != nil {
		t.Skipf("worktree ADR not present (run from worktree): %v", err)
	}
	cmd := exec.Command("bash", "scripts/adr083-checklist.sh", "--json")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "ADR_FILE_OVERRIDE="+worktreeADR)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0, got %v; output:\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, `"pass":4`) {
		t.Fatalf("expected pass:4 in JSON, got:\n%s", s)
	}
	if !strings.Contains(s, `"fail":0`) {
		t.Fatalf("expected fail:0 in JSON, got:\n%s", s)
	}
}
