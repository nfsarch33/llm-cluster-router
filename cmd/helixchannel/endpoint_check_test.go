// Package main contains the helixchannel CLI binary. Tests live in
// files suffixed _test.go so they get picked up by `go test ./...`.
//
// endpoint_check_test.go validates the v18714-3 endpoint-check subcommand:
// probes a single host endpoint over BOTH TCP/22 (legacy SSH SOCKS5
// tunneld path) and TCP/443 (ADR-086 path A2 production wire) and
// returns a JSON envelope recommending the better path per session.
//
// RED assertions for v18714-3:
//
//   - `helixchannel endpoint-check --host 127.0.0.1 --tcp22-port N --tcp443-port M`
//     exits 0 when at least one path is reachable, 1 when neither is.
//   - When TCP/22 is reachable and TCP/443 is not, recommendation =
//     "tcp22" (legacy fallback).
//   - When BOTH are reachable, recommendation = "tcp443" (production
//     wire preferred — TCP/443 is the canonical ingress per ADR-086
//     path A2; lower fingerprinting surface than TCP/22 SSH banners).
//   - When BOTH are unreachable, recommendation = "none" and the
//     process exits 1.
//   - The subcommand never prints HELIXCHANNEL_KEY (anti-shell-leak
//     invariant even when probing).
package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// endpointCheckEnvelope is the canonical JSON schema produced by
// `helixchannel endpoint-check`. Defined in main.go (production
// code); tests unmarshal stdout into the same type.

// TestEndpointCheck_BothUnreachable_Exit1 exercises the path where
// neither TCP/22 nor TCP/443 responds. The subcommand must exit 1
// (operator actionable) and emit recommendation="none".
func TestEndpointCheck_BothUnreachable_Exit1(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	// Port 1 is reserved and unbound on any sane host; connections
	// must complete within the probeTimeout so the test stays fast.
	// The failure should be ECONNREFUSED on Linux/WSL.
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--host", "127.0.0.1",
		"--tcp22-port", "1",
		"--tcp443-port", "1",
		"--probe-timeout", "500ms")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("endpoint-check must exit 1 when both tcp:22 and tcp:443 unreachable; stderr=%q stdout=%q",
			stderr.String(), stdout.String())
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError; got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.ExitCode())
	}

	var env endpointCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("endpoint-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.TCP22Reachable {
		t.Fatalf("expected tcp22_reachable=false when port 1 unbound, got true")
	}
	if env.TCP443Reachable {
		t.Fatalf("expected tcp443_reachable=false when port 1 unbound, got true")
	}
	if env.Recommendation != "none" {
		t.Fatalf("recommendation = %q, want \"none\" when both unreachable", env.Recommendation)
	}
	if env.ProbedAt == "" {
		t.Fatalf("probed_at must be a non-empty ISO-8601 timestamp")
	}
	if strings.Contains(stdout.String(), "HELIXCHANNEL_KEY") {
		t.Fatalf("endpoint-check stdout references HELIXCHANNEL_KEY (anti-shell-leak violated)")
	}
}

// TestEndpointCheck_TCP22Only_RecommendsTCP22 asserts the legacy
// fallback path: TCP/22 is reachable (a stub TCP listener on
// 127.0.0.1), TCP/443 is not. The recommendation must be "tcp22".
func TestEndpointCheck_TCP22Only_RecommendsTCP22(t *testing.T) {
	t.Parallel()

	port22 := listenFreeTCP(t)
	defer port22.Close()
	port443 := nothingListening(t)

	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--host", "127.0.0.1",
		"--tcp22-port", strconv.Itoa(port22.Port()),
		"--tcp443-port", strconv.Itoa(port443),
		"--probe-timeout", "500ms")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("endpoint-check (tcp22-only) exited non-zero: %v (stderr=%q stdout=%q)",
			err, stderr.String(), stdout.String())
	}

	var env endpointCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("endpoint-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if !env.TCP22Reachable {
		t.Fatalf("expected tcp22_reachable=true (port %d bound for test)", port22.Port())
	}
	if env.TCP443Reachable {
		t.Fatalf("expected tcp443_reachable=false (port %d unbound for test)", port443)
	}
	if env.TCP22LatencyMs < 0 {
		t.Fatalf("tcp22_latency_ms must be >= 0 when reachable; got %d", env.TCP22LatencyMs)
	}
	if env.Recommendation != "tcp22" {
		t.Fatalf("recommendation = %q, want \"tcp22\" when only tcp22 reachable", env.Recommendation)
	}
}

// TestEndpointCheck_TCP443Only_RecommendsTCP443 asserts the
// production-wire path: only TCP/443 reachable.
func TestEndpointCheck_TCP443Only_RecommendsTCP443(t *testing.T) {
	t.Parallel()

	port22 := nothingListening(t)
	port443 := listenFreeTCP(t)
	defer port443.Close()

	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--host", "127.0.0.1",
		"--tcp22-port", strconv.Itoa(port22),
		"--tcp443-port", strconv.Itoa(port443.Port()),
		"--probe-timeout", "500ms")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("endpoint-check (tcp443-only) exited non-zero: %v (stderr=%q stdout=%q)",
			err, stderr.String(), stdout.String())
	}

	var env endpointCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("endpoint-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.TCP22Reachable {
		t.Fatalf("expected tcp22_reachable=false (port %d unbound)", port22)
	}
	if !env.TCP443Reachable {
		t.Fatalf("expected tcp443_reachable=true (port %d bound)", port443.Port())
	}
	if env.Recommendation != "tcp443" {
		t.Fatalf("recommendation = %q, want \"tcp443\" when only tcp443 reachable", env.Recommendation)
	}
}

// TestEndpointCheck_BothReachable_RecommendsTCP443 asserts the
// "both reachable" decision: TCP/443 wins, not because it's always
// faster (latency parity is operator-environment-dependent), but
// because TCP/443 is the canonical ingress for the HelixChannel
// production wire (ADR-086 path A2) — lower fingerprinting surface
// than TCP/22 SSH banners.
func TestEndpointCheck_BothReachable_RecommendsTCP443(t *testing.T) {
	t.Parallel()

	port22 := listenFreeTCP(t)
	defer port22.Close()
	port443 := listenFreeTCP(t)
	defer port443.Close()

	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--host", "127.0.0.1",
		"--tcp22-port", strconv.Itoa(port22.Port()),
		"--tcp443-port", strconv.Itoa(port443.Port()),
		"--probe-timeout", "500ms")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("endpoint-check (both reachable) exited non-zero: %v (stderr=%q stdout=%q)",
			err, stderr.String(), stdout.String())
	}

	var env endpointCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("endpoint-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if !env.TCP22Reachable || !env.TCP443Reachable {
		t.Fatalf("expected both reachable; got tcp22=%v tcp443=%v",
			env.TCP22Reachable, env.TCP443Reachable)
	}
	if env.Recommendation != "tcp443" {
		t.Fatalf("recommendation = %q, want \"tcp443\" when both reachable (ADR-086 path A2 canonical ingress)",
			env.Recommendation)
	}
}

// TestEndpointCheck_AESKeyEnvLeakGuard asserts that even with
// HELIXCHANNEL_KEY set, the endpoint-check subcommand never includes
// the key value in its stdout envelope (anti-shell-leak).
func TestEndpointCheck_AESKeyEnvLeakGuard(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	const sentinel = "AES-KEY-SENTINEL-012345678901234" // exactly 33 bytes
	if len(sentinel) != 32 {
		t.Fatalf("sentinel must be exactly 32 bytes for AES-256; got %d (text=%q)", len(sentinel), sentinel)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--host", "127.0.0.1",
		"--tcp22-port", "1",
		"--tcp443-port", "1",
		"--probe-timeout", "200ms")
	cmd.Env = append(os.Environ(),
		"HELIXCHANNEL_KEY="+sentinel,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Don't care about exit code (likely 1 since port 1 unbound);
	// we only care that stdout doesn't leak the key.
	_ = cmd.Run()

	if strings.Contains(stdout.String(), sentinel) {
		t.Fatalf("endpoint-check stdout leaks HELIXCHANNEL_KEY (anti-shell-leak violated)")
	}
}

// TestEndpointCheck_ProbeTimeoutHonoured asserts that a 300ms
// probe-timeout flag is honoured: the call must complete within ~2s
// wall-clock even though both target ports are unbound.
func TestEndpointCheck_ProbeTimeoutHonoured(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--host", "127.0.0.1",
		"--tcp22-port", "1",
		"--tcp443-port", "1",
		"--probe-timeout", "300ms")
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	_ = cmd.Run()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("endpoint-check took %v with probe-timeout=300ms; want <2s wall-clock", elapsed)
	}
}

// TestEndpointCheck_BaseURLFlagDerivesHost asserts the v18714-11
// precedence: when --host is omitted, the host is extracted from
// --base-url. The probe runs against 127.0.0.1 (the loopback we
// control); port 1 is unbound so both legs fail and the envelope's
// `host` field reflects what the binary derived from --base-url.
func TestEndpointCheck_BaseURLFlagDerivesHost(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--base-url", "https://127.0.0.1:9999",
		"--tcp22-port", "1",
		"--tcp443-port", "1",
		"--probe-timeout", "200ms")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	_ = cmd.Run() // exit code 1 expected (port unbound); we assert envelope shape only.

	var env endpointCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("endpoint-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Host != "127.0.0.1:9999" {
		t.Fatalf("env.host = %q, want %q (derived from --base-url)", env.Host, "127.0.0.1:9999")
	}
}

// TestEndpointCheck_HostFlagOverridesBaseURL asserts the explicit
// --host flag wins over --base-url. This is the operator escape
// hatch when the canonical hostname is temporarily broken (DNS
// outage, cert rollover, etc.) and they need to probe the raw IP.
func TestEndpointCheck_HostFlagOverridesBaseURL(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--host", "127.0.0.1",
		"--base-url", "https://helixchannel.example.com",
		"--tcp22-port", "1",
		"--tcp443-port", "1",
		"--probe-timeout", "200ms")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	_ = cmd.Run()

	var env endpointCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("endpoint-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Host != "127.0.0.1" {
		t.Fatalf("env.host = %q, want %q (--host should win over --base-url)", env.Host, "127.0.0.1")
	}
}

// TestEndpointCheck_EnvBaseURLDerivesHostDefault asserts the
// v18714-11 default-fallback path: when neither --host nor
// --base-url is given, the binary uses HELIXCHANNEL_BASE_URL env.
// Setting HELIXCHANNEL_BASE_URL to a sentinel host lets the test
// observe the derivation without depending on the canonical
// helixchannel.example.com being resolvable from CI.
func TestEndpointCheck_EnvBaseURLDerivesHostDefault(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	bin := buildHelixchannelBinary(t, root)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := exec.Command(bin, "endpoint-check",
		"--tcp22-port", "1",
		"--tcp443-port", "1",
		"--probe-timeout", "200ms")
	cmd.Env = append(os.Environ(),
		"HELIXCHANNEL_BASE_URL=https://127.0.0.1:8888",
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	_ = cmd.Run()

	var env endpointCheckEnvelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("endpoint-check stdout not JSON: %v\nstdout=%q", err, stdout.String())
	}
	if env.Host != "127.0.0.1:8888" {
		t.Fatalf("env.host = %q, want %q (HELIXCHANNEL_BASE_URL fallback)", env.Host, "127.0.0.1:8888")
	}
}

// listenFreeTCP binds an ephemeral TCP listener on 127.0.0.1 and
// returns a small handle that exposes .Port() and .Close(). The
// caller must Close the listener.
func listenFreeTCP(t *testing.T) *tcpListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free tcp: %v", err)
	}
	return &tcpListener{ln: ln}
}

// tcpListener wraps an embedded net.Listener and exposes the bound
// port directly via .Port(). This is simpler than type-asserting on
// every test site.
type tcpListener struct {
	ln net.Listener
}

// Port returns the bound TCP port.
func (l *tcpListener) Port() int {
	if l.ln == nil {
		return 0
	}
	return l.ln.Addr().(*net.TCPAddr).Port
}

// Close delegates to the embedded listener.
func (l *tcpListener) Close() error {
	if l.ln == nil {
		return nil
	}
	return l.ln.Close()
}

// nothingListening finds a free TCP port by binding+closing on
// 127.0.0.1:0, returns that port number for the test to use as the
// "unbound" probe target. Yields briefly to avoid the same port
// being re-resolved by the binding cache on Linux.
func nothingListening(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open then close: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	return port
}
