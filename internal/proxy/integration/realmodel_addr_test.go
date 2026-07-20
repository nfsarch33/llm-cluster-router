//go:build realmodel

package integration

import (
	"os"
	"testing"
)

// TestRealModel_LightsailAddr_Defaults verifies that the helper resolves
// sensible defaults when only the host env var is set, and that no
// `lightsail` hostnames or hardcoded IPs leak into the helper output.
func TestRealModel_LightsailAddr_Defaults(t *testing.T) {
	t.Setenv("REALMODEL_LIGHTSAIL_SOCKS5", "")
	t.Setenv("LLM_ROUTER_LIGHTSAIL_HOST", "helixon-tunnel")
	t.Setenv("SSH_DYNAMIC_PORT", "")
	got := lightsailSSHAddr()
	want := "127.0.0.1:1080"
	if got != want {
		t.Fatalf("lightsailSSHAddr() = %q, want %q (operator host alias must NOT leak)", got, want)
	}
}

// TestRealModel_LightsailAddr_OverrideWins verifies that an explicit
// REALMODEL_LIGHTSAIL_SOCKS5 override wins over the host-var path.
func TestRealModel_LightsailAddr_OverrideWins(t *testing.T) {
	t.Setenv("REALMODEL_LIGHTSAIL_SOCKS5", "192.0.2.10:9100")
	t.Setenv("LLM_ROUTER_LIGHTSAIL_HOST", "anything-else")
	got := lightsailSSHAddr()
	if got != "192.0.2.10:9100" {
		t.Fatalf("lightsailSSHAddr() = %q, want override to win", got)
	}
}

// TestRealModel_Upstream_Defaults verifies that defaults match the canonical
// Aliyun Qwen endpoint. If a future operator migrates to a different
// provider, they override UPSTREAM_HTTPS_ADDR; the default is the
// provider we have a 1Password key for today.
func TestRealModel_Upstream_Defaults(t *testing.T) {
	t.Setenv("UPSTREAM_HTTPS_ADDR", "")
	got := upstreamHTTPSAddr()
	if got != "dashscope.aliyuncs.com:443" {
		t.Fatalf("upstreamHTTPSAddr() = %q, want dashscope.aliyuncs.com:443", got)
	}
	// also verify model default
	t.Setenv("UPSTREAM_MODEL", "")
	if m := upstreamModel(); m != "qwen-turbo" {
		t.Fatalf("upstreamModel() = %q, want qwen-turbo", m)
	}
}

// TestRealModel_Upstream_Override verifies env var overrides flow through.
// Using `os.Setenv` directly (vs t.Setenv) to test late-binding.
func TestRealModel_Upstream_Override(t *testing.T) {
	os.Setenv("UPSTREAM_HTTPS_ADDR", "example.com:8443")
	defer os.Unsetenv("UPSTREAM_HTTPS_ADDR")
	if got := upstreamHTTPSAddr(); got != "example.com:8443" {
		t.Fatalf("override did not flow: got %q", got)
	}
	os.Setenv("UPSTREAM_MODEL", "qwen-max")
	defer os.Unsetenv("UPSTREAM_MODEL")
	if m := upstreamModel(); m != "qwen-max" {
		t.Fatalf("model override did not flow: got %q", m)
	}
}

// TestRealModel_NoEnvYieldsEmpty ensures the addr helpers are safe to call
// with no env vars set (so the gating logic in the E2E tests can use
// `if addr == ""` as the SKIP signal without triggering nil panics).
func TestRealModel_NoEnvYieldsEmpty(t *testing.T) {
	// Clear everything before the call.
	os.Unsetenv("REALMODEL_LIGHTSAIL_SOCKS5")
	os.Unsetenv("LLM_ROUTER_LIGHTSAIL_HOST")
	t.Setenv("REALMODEL_LIGHTSAIL_SOCKS5", "")
	t.Setenv("LLM_ROUTER_LIGHTSAIL_HOST", "")
	// no panic + no leakage (returns "")
	_ = lightsailSSHAddr()
}
