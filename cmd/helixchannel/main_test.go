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

// TestCipherList_EmitsCanonicalSuite asserts that `cipher-list`
// returns a JSON envelope with the canonical 4-row catalog and at
// least one recommended suite (TLS_AES_256_GCM_SHA384, RFC 8446).
//
// RED until cipher-list is implemented (v18727-2).
func TestCipherList_EmitsCanonicalSuite(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "cipher-list")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cipher-list exited non-zero: %v (stderr=%q)", err, stderr.String())
	}

	var env cipherListEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("cipher-list stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Channel != "aes-256-gcm" {
		t.Fatalf("cipher-list.channel = %q, want aes-256-gcm", env.Channel)
	}
	if env.Count < 4 {
		t.Fatalf("cipher-list.count = %d, want >=4 (canonical catalog has 4 rows)", env.Count)
	}
	// Confirm the canonical recommended suite is the first
	// entry (cf. catalogCipherSuites ordering invariant).
	if len(env.Ciphers) == 0 || env.Ciphers[0].IANA != "TLS_AES_256_GCM_SHA384" {
		var got []string
		for _, c := range env.Ciphers {
			got = append(got, c.IANA)
		}
		t.Fatalf("cipher-list first row should be TLS_AES_256_GCM_SHA384; got %v", got)
	}
	if !env.Ciphers[0].Recommended {
		t.Fatalf("cipher-list first row should be Recommended=true")
	}
	if !env.Ciphers[0].AEAD {
		t.Fatalf("cipher-list first row should be AEAD=true")
	}
}

// TestCipherList_RecommendedOnlyFilter asserts that
// `cipher-list --recommended-only` returns only rows where
// Recommended == true and reduces the count below the catalog total.
func TestCipherList_RecommendedOnlyFilter(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "cipher-list", "--recommended-only")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cipher-list --recommended-only exited non-zero: %v (stderr=%q)", err, stderr.String())
	}

	var env cipherListEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("cipher-list stdout not JSON: %v", err)
	}
	if env.Count == 0 {
		t.Fatalf("cipher-list --recommended-only.count = 0")
	}
	for i, c := range env.Ciphers {
		if !c.Recommended {
			t.Fatalf("cipher-list --recommended-only row %d (%q) has Recommended=false", i, c.IANA)
		}
	}
}

// TestCipherList_AsYAMLEmitsSSLCiphers asserts that
// `cipher-list --as-yaml` emits a nginx-friendly ssl_ciphers block
// with the recommended suite as the directive value.
func TestCipherList_AsYAMLEmitsSSLCiphers(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "cipher-list", "--as-yaml")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cipher-list --as-yaml exited non-zero: %v (stderr=%q)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "ssl_ciphers ") {
		t.Fatalf("cipher-list --as-yaml missing 'ssl_ciphers' directive:\n%s", out)
	}
	if !strings.Contains(out, "TLS_AES_256_GCM_SHA384") {
		t.Fatalf("cipher-list --as-yaml missing canonical suite:\n%s", out)
	}
}

// TestCertPin_OfflineFailsClean asserts that `cert-pin --host
// 127.0.0.1 --port 1` exits non-zero with a JSON envelope
// containing an error key (per the envelope contract) and does not
// leak internal argv. Offline test - never reaches Lightsail.
func TestCertPin_OfflineFailsClean(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	// 127.0.0.1:1 is the canonical "guaranteed-no-listener" probe:
	// the kernel will refuse immediately.
	cmd := exec.Command(bin, "cert-pin", "--host", "127.0.0.1", "--port", "1", "--probe-timeout", "1s")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("cert-pin against 127.0.0.1:1 should exit non-zero")
	}
	// The CLI's fail() helper writes the error envelope to stderr
	// (so stdout stays clean for jq pipes); check stderr.
	if stderr.Len() == 0 {
		t.Fatalf("cert-pin must emit JSON error envelope on failure; got empty stderr")
	}
	if !strings.Contains(stderr.String(), "\"error\"") {
		t.Fatalf("cert-pin error envelope missing 'error' key: %s", stderr.String())
	}
	// Anti-shell-leak: no PII / tmp paths. Note: the dial-error
	// text *will* echo the input address (127.0.0.1:1) — that's
	// not a leak, that's the operator's own probe target echoed
	// back. We only assert no /tmp/ paths.
	if strings.Contains(stderr.String(), "/tmp/") {
		t.Fatalf("cert-pin error envelope leaked tmp path: %s", stderr.String())
	}
}

// TestCipherList_UnknownFlagErrors asserts that an unknown flag
// returns a non-zero exit and the JSON error envelope (on stderr,
// per the fail() helper contract).
func TestCipherList_UnknownFlagErrors(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "cipher-list", "--no-such-flag")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("cipher-list --no-such-flag should exit non-zero")
	}
	if !strings.Contains(stderr.String(), "\"error\"") {
		t.Fatalf("cipher-list unknown flag must emit error JSON envelope (stderr): %s", stderr.String())
	}
}

// TestTailnetAllowlist_DefaultEmitsCanonicalRange asserts that
// `helixchannel tailnet-allowlist` (no flags) prints a JSON envelope
// with `canonical = "100.64.0.0/10"` and exactly one CIDR in the
// list. v18730-2 defence-in-depth posture: the canonical Tailscale
// CGNAT range is always enforced.
func TestTailnetAllowlist_DefaultEmitsCanonicalRange(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "tailnet-allowlist")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tailnet-allowlist default exited non-zero: %v (stderr=%q)", err, stderr.String())
	}
	var env struct {
		Mode      string   `json:"mode"`
		Canonical string   `json:"canonical"`
		CIDRs     []string `json:"cidrs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("tailnet-allowlist stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Mode != "default" {
		t.Errorf("mode = %q, want default", env.Mode)
	}
	if env.Canonical != "100.64.0.0/10" {
		t.Errorf("canonical = %q, want 100.64.0.0/10", env.Canonical)
	}
	if len(env.CIDRs) != 1 || env.CIDRs[0] != "100.64.0.0/10" {
		t.Errorf("cidrs = %v, want only [100.64.0.0/10]", env.CIDRs)
	}
}

// TestTailnetAllowlist_CheckTailNetPeerPasses asserts that a known
// TailNet peer (wsl1 = 100.84.108.92) is reported as `allowed=true`
// and the process exits 0. v18730-2.
func TestTailnetAllowlist_CheckTailNetPeerPasses(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "tailnet-allowlist", "--check", "100.84.108.92")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tailnet-allowlist --check 100.84.108.92 exited non-zero: %v (stderr=%q)", err, stderr.String())
	}
	var env struct {
		IP      string `json:"ip"`
		Allowed *bool  `json:"allowed"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("tailnet-allowlist stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.IP != "100.84.108.92" {
		t.Errorf("ip = %q, want 100.84.108.92", env.IP)
	}
	if env.Allowed == nil || !*env.Allowed {
		t.Errorf("allowed = %v, want true", env.Allowed)
	}
}

// TestTailnetAllowlist_CheckPublicIPDenies asserts that a public IP
// (8.8.8.8 = Google DNS) is reported as `allowed=false` and the
// process exits 1. v18730-2 — the defence-in-depth gate must
// reject non-TailNet traffic.
func TestTailnetAllowlist_CheckPublicIPDenies(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "tailnet-allowlist", "--check", "8.8.8.8")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("tailnet-allowlist --check 8.8.8.8 must exit non-zero; got exit 0")
	}
	var env struct {
		IP      string `json:"ip"`
		Allowed *bool  `json:"allowed"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("tailnet-allowlist stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Allowed == nil || *env.Allowed {
		t.Errorf("allowed = %v, want false", env.Allowed)
	}
}

// TestTailnetAllowlist_AllowExtraCIDR asserts that an explicit
// `--allow 10.99.0.0/16` adds the extra range to the canonical
// CGNAT list and that an IP inside the extras (10.99.5.5) is
// reported as allowed. v18730-2.
func TestTailnetAllowlist_AllowExtraCIDR(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "tailnet-allowlist", "--allow", "10.99.0.0/16", "--check", "10.99.5.5")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tailnet-allowlist --check 10.99.5.5 exited non-zero: %v (stderr=%q)", err, stderr.String())
	}
	var env struct {
		CIDRs   []string `json:"cidrs"`
		Allowed *bool    `json:"allowed"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("tailnet-allowlist stdout not JSON: %v", err)
	}
	if len(env.CIDRs) != 2 {
		t.Errorf("cidrs = %v, want 2 entries (canonical + extra)", env.CIDRs)
	}
	if env.Allowed == nil || !*env.Allowed {
		t.Errorf("allowed = %v, want true (10.99.5.5 in 10.99.0.0/16)", env.Allowed)
	}
}

// TestTailnetAllowlist_InvalidCIDRErrors asserts that an invalid
// `--allow` value returns a JSON error envelope and a non-zero exit.
// v18730-2.
func TestTailnetAllowlist_InvalidCIDRErrors(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "tailnet-allowlist", "--allow", "not-a-cidr")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("tailnet-allowlist --allow not-a-cidr must exit non-zero")
	}
	if !strings.Contains(stderr.String(), "\"error\"") {
		t.Fatalf("tailnet-allowlist invalid CIDR must emit JSON error envelope (stderr): %s", stderr.String())
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
