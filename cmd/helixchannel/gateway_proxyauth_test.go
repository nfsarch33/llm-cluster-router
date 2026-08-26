package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nfsarch33/llm-cluster-router/internal/channel"
)

// TestRunGateway_PrintRoutesCarriesTheProxyAuthPosture keeps the machine-readable
// envelope honest. An operator auditing a fleet needs to be able to ask each node
// whether its reverse-proxy leg authenticates anybody without shelling in to read
// its config, and "the config said so" is not the same answer as "the process
// says so".
func TestRunGateway_PrintRoutesCarriesTheProxyAuthPosture(t *testing.T) {
	t.Setenv("V18760_GW_TEST_KEY", "sk-test")
	cfgPath := writeGatewayConfig(t, "127.0.0.1:0", "http://127.0.0.1:9")

	out, err := captureStdout(t, func() error {
		return runGateway([]string{"--config", cfgPath, "--print-routes"})
	})
	if err != nil {
		t.Fatalf("runGateway --print-routes = %v, want nil", err)
	}
	var env struct {
		ProxyAuth string `json:"proxy_auth"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("print-routes output not JSON: %v (%q)", err, out)
	}
	if env.ProxyAuth != string(channel.ProxyAuthLoopbackOnly) {
		t.Errorf("proxy_auth = %q, want %q: this config names no gateway token", env.ProxyAuth, channel.ProxyAuthLoopbackOnly)
	}
}

// TestRunGateway_ListenOverrideCannotSmuggleAWideBindPastTheCheck closes the
// hole the flag would otherwise open. The bind rule is enforced by
// Config.Validate, which runs at load; --listen replaces the one field that rule
// reads, so without re-validating, a config that legitimately bound loopback with
// no token could be moved onto a wildcard address from the command line and
// become an unauthenticated funded relay with no error anywhere.
func TestRunGateway_ListenOverrideCannotSmuggleAWideBindPastTheCheck(t *testing.T) {
	t.Setenv("V18760_GW_TEST_KEY", "sk-test")
	cfgPath := writeGatewayConfig(t, "127.0.0.1:0", "http://127.0.0.1:9")

	_, err := captureStdout(t, func() error {
		return runGateway([]string{"--config", cfgPath, "--listen", "0.0.0.0:0", "--print-routes"})
	})
	if err == nil {
		t.Fatal("runGateway --listen 0.0.0.0:0 = nil error; a wildcard bind with no gateway token must be refused")
	}
	if !strings.Contains(err.Error(), "gateway_auth") {
		t.Errorf("error = %v, want it to name gateway_auth", err)
	}

	// The control: a loopback override is still accepted, so the check is the
	// bind rule and not a blanket refusal of the flag.
	if _, err := captureStdout(t, func() error {
		return runGateway([]string{"--config", cfgPath, "--listen", "127.0.0.1:2", "--print-routes"})
	}); err != nil {
		t.Errorf("loopback override = %v, want nil", err)
	}
}

// TestWarnUnauthenticatedProxyLeg_SaysSoLoudlyAndOnlyWhenTrue pins the startup
// warning. Both unauthenticated postures are legitimate deployments and both are
// indistinguishable, from inside this process, from having forgotten to configure
// a token — so the sentence a human reads has to be printed, and it has to stop
// being printed the moment a token exists, or it becomes noise nobody reads.
func TestWarnUnauthenticatedProxyLeg_SaysSoLoudlyAndOnlyWhenTrue(t *testing.T) {
	cases := []struct {
		mode     channel.ProxyAuthMode
		wantWarn bool
		wantSays string
	}{
		{channel.ProxyAuthLoopbackOnly, true, "the bind address is the only boundary"},
		{channel.ProxyAuthOpen, true, "allow_unauthenticated"},
		{channel.ProxyAuthToken, false, ""},
		{channel.ProxyAuthTokenLoopbackExempt, false, ""},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			var buf bytes.Buffer
			warnUnauthenticatedProxyLeg(&buf, tc.mode, "0.0.0.0:14443")
			got := buf.String()
			if !tc.wantWarn {
				if got != "" {
					t.Fatalf("warned on %q: %q", tc.mode, got)
				}
				return
			}
			if !strings.Contains(got, "WARNING") {
				t.Errorf("warning for %q is not labelled: %q", tc.mode, got)
			}
			if !strings.Contains(got, "authenticates NOBODY") {
				t.Errorf("warning for %q does not say what is wrong: %q", tc.mode, got)
			}
			if !strings.Contains(got, "0.0.0.0:14443") {
				t.Errorf("warning for %q does not name the listen address: %q", tc.mode, got)
			}
			if !strings.Contains(got, tc.wantSays) {
				t.Errorf("warning for %q does not contain %q: %q", tc.mode, tc.wantSays, got)
			}
		})
	}
}
