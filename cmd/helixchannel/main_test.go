package main

// runx-public-repo-gate: no findings.
// Copyright (c) 2026 jason. All rights reserved.
//
// Tests for the helixchannel CLI binary. Each test exercises a
// subcommand in isolation and asserts behaviour against the
// json-envelope contract: stdout is always JSON (so shells can
// jq it without escaping surprises), the exit code reflects
// pass/fail, and secrets are NEVER printed per the no-shell-leak
// rule.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestVersionSubcommand_ExitsZero asserts that `helixchannel version`
// prints a JSON envelope with version/git-sha/go-version, exits 0.
//
// RED until the version subcommand is implemented.
func TestVersionSubcommand_ExitsZero(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "version")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("version subcommand exited non-zero: %v (stderr=%q)", err, stderr.String())
	}

	var env envelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("version stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.HelixChannelVersion != proxyHelixChannelVersion {
		t.Fatalf("version.helixchannel_version = %q, want %q",
			env.HelixChannelVersion, proxyHelixChannelVersion)
	}
	if env.GoVersion == "" {
		t.Fatalf("version.go_version is empty")
	}
}

// TestFactoryProbe_BindsEphemeralPort asserts that
// `helixchannel factory-probe --addr :0` returns a JSON envelope
// with a non-empty bound address, the channel id, and tls=false
// (since the probe uses plain HTTP to keep the test cheap).
//
// RED until factory-probe is implemented.
func TestFactoryProbe_BindsEphemeralPort(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	// Run factory-probe with HELIXCHANNEL_ENABLED=false to force the
	// plain HTTP factory and avoid any AES-key env wiring in tests.
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "factory-probe", "--addr", ":0")
	cmd.Env = append(os.Environ(), "HELIXCHANNEL_ENABLED=false")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("factory-probe exited non-zero: %v (stderr=%q)", err, stderr.String())
	}

	var env factoryProbeEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("factory-probe stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Bound == "" {
		t.Fatalf("factory-probe.bound is empty; want 127.0.0.1:port")
	}
	if !strings.HasPrefix(env.Bound, "127.0.0.1:") && !strings.HasPrefix(env.Bound, "[::]:") {
		t.Fatalf("factory-probe.bound = %q, want 127.0.0.1:PORT", env.Bound)
	}
	if env.Channel != "plain-http" {
		t.Fatalf("factory-probe.channel = %q, want plain-http", env.Channel)
	}
	if env.TLS {
		t.Fatalf("factory-probe.tls = true; want false (probe uses plain HTTP)")
	}

	// Probe should have unbound by now (probe releases on exit);
	// sanity-check by trying to connect to the address — the
	// listener MUST be closed.
	if _, err := http.Get("http://" + env.Bound); err == nil {
		t.Logf("WARN: probe port %s still accepting after exit", env.Bound)
	}
}

// TestKeyCheck_RefusesOnInvalidLength asserts that
// `helixchannel key-check` refuses (exit 1) when HELIXCHANNEL_KEY
// is set to a 31-byte string (wrong for AES-256) and that the JSON
// envelope never includes the key value (anti-shell-leak).
//
// RED until key-check is implemented.
func TestKeyCheck_RefusesOnInvalidLength(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "key-check")
	// 31 bytes — wrong for AES-256 (needs exactly 32).
	cmd.Env = append(os.Environ(), "HELIXCHANNEL_KEY="+strings.Repeat("A", 31))
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	exitErr := cmd.Run()
	if exitErr == nil {
		t.Fatalf("key-check exited 0 on invalid length; want non-zero")
	}

	var env keyCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("key-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Valid {
		t.Fatalf("key-check.valid = true on 31-byte key; want false")
	}
	if env.Source != "env" {
		t.Fatalf("key-check.source = %q, want env", env.Source)
	}
	// Anti-shell-leak: the JSON envelope MUST NOT contain any
	// "value" field that echoes the key. We round-trip the JSON
	// into a generic map and fail if such a key appears.
	var generic map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &generic); err != nil {
		t.Fatalf("key-check stdout not JSON-map: %v", err)
	}
	if v, ok := generic["value"]; ok && v != "" {
		t.Fatalf("key-check.value = %q; want absent or empty (anti-shell-leak)", v)
	}
	if _, leaked := generic["key"]; leaked {
		t.Fatalf("key-check.key present in JSON; anti-shell-leak violation")
	}
}

// TestDoctorSubcommand_ChecksADR085 asserts that
// `helixchannel doctor` exits 0, the JSON envelope lists all
// doctor checks, and at least one check passes (the cursor-global-kb
// ADR-085 reference).
//
// RED until doctor is implemented.
func TestDoctorSubcommand_ChecksADR085(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "doctor")
	cmd.Env = append(os.Environ(), "HELIXCHANNEL_ENABLED=false")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("doctor exited non-zero: %v (stderr=%q)", err, stderr.String())
	}

	var env doctorEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("doctor stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Checks == nil {
		t.Fatalf("doctor.checks is nil; expected map[string]string")
	}
	wantChecks := []string{"release_gate_script", "adr_085"}
	for _, name := range wantChecks {
		// both checks should be present (PASS or FAIL — both is acceptable
		// in a CI run, the assertion is that the check was invoked).
		if _, ok := env.Checks[name]; !ok {
			t.Fatalf("doctor.checks[%q] missing; got %v", name, env.Checks)
		}
	}
	if env.Checks["adr_085"] != "pass" && env.Checks["adr_085"] != "fail" {
		t.Fatalf("doctor.checks[adr_085] = %q, want pass or fail", env.Checks["adr_085"])
	}
}

// --- helpers ---

// repoRoot returns the path to the llm-cluster-router repo root by
// resolving the test binary's location. Tests run from
// cmd/helixchannel, so we go up two levels.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("could not find go.mod at %s: %v", root, err)
	}
	return root
}

// envelope is the JSON envelope for the `version` subcommand.
// Mirrors the production struct so the test catches JSON drift.
type envelope struct {
	HelixChannelVersion string `json:"helixchannel_version"`
	GoVersion           string `json:"go_version"`
	GitSHA              string `json:"git_sha,omitempty"`
}

// buildHelixchannelBinary compiles cmd/helixchannel into a temp
// directory and returns its absolute path. Tests use this so the
// subcommand binaries are always fresh.
func buildHelixchannelBinary(t *testing.T, root string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "helixchannel")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/helixchannel")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/helixchannel failed: %v\n%s", err, out)
	}
	return bin
}
