// Copyright (c) 2026 jason. All rights reserved.
//
// cli_inprocess_test.go (v18760) drives the top-level dispatcher and the
// small subcommands in-process: version envelopes, key-check, header
// stamping, factory probe, doctor, and the pure helpers behind
// kilo-verify. Complements the compiled-binary suite (which validates
// exit codes) with coverage-visible assertions on the same contracts.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// runMainWithArgs swaps os.Args, runs main(), and captures stdout. Only
// safe for argv forms whose path returns without os.Exit.
func runMainWithArgs(t *testing.T, args ...string) string {
	t.Helper()
	oldArgs := os.Args
	os.Args = append([]string{"helixchannel"}, args...)
	defer func() { os.Args = oldArgs }()
	out, _ := captureStdout(t, func() error {
		main()
		return nil
	})
	return out
}

func TestMainDispatch_TopLevelVersionFlags(t *testing.T) {
	for _, form := range []string{"--version", "-version"} {
		out := runMainWithArgs(t, form)
		if !strings.Contains(out, "helixchannel_version="+proxyHelixChannelVersion) {
			t.Fatalf("%s output %q missing canonical version line", form, out)
		}
	}
}

func TestMainDispatch_HelpPrintsUsage(t *testing.T) {
	// usage() writes to stderr; main() must return without exiting.
	runMainWithArgs(t, "--help")
	runMainWithArgs(t, "-h")
}

func TestMainDispatch_VersionSubcommandJSON(t *testing.T) {
	out := runMainWithArgs(t, "version")
	var env versionEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("version output not JSON: %v (%q)", err, out)
	}
	if env.HelixChannelVersion != proxyHelixChannelVersion {
		t.Fatalf("helixchannel_version = %q, want %q", env.HelixChannelVersion, proxyHelixChannelVersion)
	}
}

func TestMainDispatch_HeaderStamp(t *testing.T) {
	out := runMainWithArgs(t, "header-stamp")
	var env headerStampEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("header-stamp output not JSON: %v (%q)", err, out)
	}
	if env.Channel != "HelixChannel" || len(env.Headers) != 1 {
		t.Fatalf("envelope = %+v, want one HelixChannel header line", env)
	}
	if !strings.Contains(env.Headers[0], proxyHelixChannelVersion) {
		t.Fatalf("header %q missing version stamp", env.Headers[0])
	}
}

func TestMainDispatch_KeyCheckValidKey(t *testing.T) {
	t.Setenv("HELIXCHANNEL_KEY", strings.Repeat("K", 32))
	out := runMainWithArgs(t, "key-check")
	var env keyCheckEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("key-check output not JSON: %v (%q)", err, out)
	}
	if !env.Valid || env.Length != 32 {
		t.Fatalf("envelope = %+v, want valid 32-byte", env)
	}
	if strings.Contains(out, strings.Repeat("K", 32)) {
		t.Fatal("key value leaked into stdout (anti-shell-leak violation)")
	}
}

func TestRunKeyCheck_UnsetKeyWarnsButPasses(t *testing.T) {
	t.Setenv("HELIXCHANNEL_KEY", "")
	out, err := captureStdout(t, runKeyCheck)
	if err != nil {
		t.Fatalf("runKeyCheck unset = %v, want nil (legacy plain-HTTP mode)", err)
	}
	var env keyCheckEnvelope
	if jErr := json.Unmarshal([]byte(out), &env); jErr != nil {
		t.Fatalf("output not JSON: %v", jErr)
	}
	if env.Valid || env.Length != 0 {
		t.Fatalf("envelope = %+v, want invalid length 0", env)
	}
}

func TestMainDispatch_FactoryProbePlainHTTP(t *testing.T) {
	t.Setenv("HELIXCHANNEL_ENABLED", "false")
	out := runMainWithArgs(t, "factory-probe", "--addr", "127.0.0.1:0")
	var env factoryProbeEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("factory-probe output not JSON: %v (%q)", err, out)
	}
	if env.Bound == "" || env.TLS {
		t.Fatalf("envelope = %+v, want bound plain listener", env)
	}
}

func TestRunFactoryProbe_FlagErrors(t *testing.T) {
	if err := runFactoryProbe([]string{"--addr"}); err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("dangling --addr: err = %v", err)
	}
	if err := runFactoryProbe([]string{"--bogus"}); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("unknown flag: err = %v", err)
	}
}

func TestRunFactoryProbe_ListenFailureSurfaced(t *testing.T) {
	t.Setenv("HELIXCHANNEL_ENABLED", "false")
	// Occupy a port, then probe the same explicit port → bind conflict.
	lf := listenFreeTCP(t)
	defer func() { _ = lf.Close() }()
	addr := fmt.Sprintf("127.0.0.1:%d", lf.Port())
	_, err := captureStdout(t, func() error { return runFactoryProbe([]string{"--addr", addr}) })
	if err == nil || !strings.Contains(err.Error(), "factory.Listen") {
		t.Fatalf("err = %v, want factory.Listen failure", err)
	}
}

func TestMainDispatch_DoctorEnvelope(t *testing.T) {
	t.Setenv("HELIXCHANNEL_CDP_SKIP", "1")
	t.Setenv("LIGHTSAIL_API_BASE", "")
	t.Setenv("LLM_CLUSTER_ROUTER_REPO", repoRoot(t))
	t.Setenv("HELIXCHANNEL_KEY", "")
	out := runMainWithArgs(t, "doctor")
	var env doctorEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("doctor output not JSON: %v (%q)", err, out)
	}
	if env.Checks["release_gate_script"] != "pass" {
		t.Fatalf("release_gate_script = %q, want pass (repo root %s)", env.Checks["release_gate_script"], repoRoot(t))
	}
	if env.Checks["cdp_reachable"] != "skipped" {
		t.Fatalf("cdp_reachable = %q, want skipped (opt-out set)", env.Checks["cdp_reachable"])
	}
	if env.Checks["lightsail_tcp443"] != "skipped" {
		t.Fatalf("lightsail_tcp443 = %q, want skipped (offline)", env.Checks["lightsail_tcp443"])
	}
	if env.Checks["aes_key"] != "pass" {
		t.Fatalf("aes_key = %q, want pass for unset key", env.Checks["aes_key"])
	}
}

func TestUsage_WritesToStderr(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	usage()
	os.Stderr = oldStderr
	_ = w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	_ = r.Close()
	if !strings.Contains(string(buf[:n]), "usage:") {
		t.Fatalf("usage() wrote %q, want a usage line", string(buf[:n]))
	}
}

func TestHelixChannelEnabledFromEnv_Table(t *testing.T) {
	cases := map[string]bool{
		"":      true,
		"1":     true,
		"true":  true,
		"TRUE":  true,
		"True":  true,
		"0":     false,
		"false": false,
		"FALSE": false,
		"False": false,
		"no":    false,
		"off":   false,
		"junk":  false,
	}
	for v, want := range cases {
		t.Setenv("HELIXCHANNEL_ENABLED", v)
		if got := helixChannelEnabledFromEnv(); got != want {
			t.Fatalf("HELIXCHANNEL_ENABLED=%q → %v, want %v", v, got, want)
		}
	}
}

func TestParseKiloVerifyBaseURL_Table(t *testing.T) {
	cases := []struct {
		raw                string
		scheme, host, port string
		wantErr            bool
	}{
		{raw: "https://edge.example/minimax/v1", scheme: "https", host: "edge.example", port: "443"},
		{raw: "http://edge.example/v1", scheme: "http", host: "edge.example", port: "80"},
		{raw: "https://edge.example:8443/minimax/v1", scheme: "https", host: "edge.example", port: "8443"},
		{raw: "http://127.0.0.1:8787", scheme: "http", host: "127.0.0.1", port: "8787"},
		{raw: "  https://pad.example  ", scheme: "https", host: "pad.example", port: "443"},
		{raw: "", wantErr: true},
		{raw: "ftp://nope.example", wantErr: true},
		{raw: "edge.example/v1", wantErr: true},
	}
	for _, tc := range cases {
		scheme, host, port, err := parseKiloVerifyBaseURL(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parse(%q) = (%s,%s,%s), want error", tc.raw, scheme, host, port)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parse(%q) unexpected error: %v", tc.raw, err)
		}
		if scheme != tc.scheme || host != tc.host || port != tc.port {
			t.Fatalf("parse(%q) = (%s,%s,%s), want (%s,%s,%s)", tc.raw, scheme, host, port, tc.scheme, tc.host, tc.port)
		}
	}
}

func TestClassifyNetErr_Table(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{fmt.Errorf("context deadline exceeded"), "timeout"},
		{fmt.Errorf("i/o timeout"), "timeout"},
		{fmt.Errorf("dial tcp: connection refused"), "refused"},
		{fmt.Errorf("lookup x: no such host"), "no_route"},
		{fmt.Errorf("tls: handshake failure"), "tls"},
		{fmt.Errorf("status 401"), "upstream_401"},
		{fmt.Errorf("status 403"), "upstream_403"},
		{fmt.Errorf("status 429"), "upstream_429"},
		{fmt.Errorf("weird transport wobble"), "net"},
	}
	for _, tc := range cases {
		if got := classifyNetErr(tc.err); got != tc.want {
			t.Fatalf("classifyNetErr(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestTruncateKiloVerify(t *testing.T) {
	if got := truncateKiloVerify("short", 10); got != "short" {
		t.Fatalf("got %q", got)
	}
	if got := truncateKiloVerify("0123456789ABC", 10); got != "0123456789..." {
		t.Fatalf("got %q", got)
	}
}

func TestKiloVerifyVerdictError_ErrorString(t *testing.T) {
	if kiloVerifySkipErr.Error() != "verdict=skip" {
		t.Fatalf("skip sentinel = %q", kiloVerifySkipErr.Error())
	}
	if kiloVerifyFailErr.Error() != "verdict=fail" {
		t.Fatalf("fail sentinel = %q", kiloVerifyFailErr.Error())
	}
}

func TestRunVersion_BadFlagRejected(t *testing.T) {
	if err := runVersion([]string{"--nope"}); err == nil {
		t.Fatal("runVersion with unknown flag = nil, want parse error")
	}
}
