// Package config -- v18750-B1 vendor-field admission tests.
//
// These tests pin the YAML schema additions made for the v18750-B1
// multi-vendor router extension. They are deliberately idempotent:
// running them twice produces the same outcome. They do not touch
// network, secrets, or the host filesystem.
package config

import (
	"testing"
)

// TestVendorFieldDefaultsAreEmpty asserts the new fields default to
// the zero value, so adding them does not change behaviour for any
// existing YAML that omits them.
func TestVendorFieldDefaultsAreEmpty(t *testing.T) {
	n := NodeConfig{Name: "noop"}
	if n.Vendor != "" {
		t.Fatalf("Vendor: want empty, got %q", n.Vendor)
	}
	if n.EnabledVendor != "" {
		t.Fatalf("EnabledVendor: want empty, got %q", n.EnabledVendor)
	}
	if n.QuotaDetectRegex != "" {
		t.Fatalf("QuotaDetectRegex: want empty, got %q", n.QuotaDetectRegex)
	}
}

// TestVendorFieldRoundTrip pins the YAML key spelling because the
// runtime yaml package keys by string, not by Go struct tag.
func TestVendorFieldRoundTrip(t *testing.T) {
	in := `
listen: ":8787"
nodes:
  - name: minimax-m3
    url: "https://api.minimaxi.com/v1"
    tier: "3"
    enabled: "true"
    enabled_vendor: "true"
    vendor: "minimax"
    quota_detect_regex: "(?i)insufficient_quota|quota_exceeded"
    models:
      - "MiniMax-M3"
`
	path := writeTempConfig(t, in)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(cfg.Nodes))
	}
	n := cfg.Nodes[0]
	if n.Vendor != "minimax" {
		t.Fatalf("Vendor: want minimax, got %q", n.Vendor)
	}
	if n.EnabledVendor != "true" {
		t.Fatalf("EnabledVendor: want true, got %q", n.EnabledVendor)
	}
	if n.QuotaDetectRegex == "" {
		t.Fatalf("QuotaDetectRegex: want non-empty")
	}
}

// TestVendorBackCompatNoFields asserts an existing v14934/v14585
// YAML without the new fields still loads.
func TestVendorBackCompatNoFields(t *testing.T) {
	in := `
listen: ":8787"
nodes:
  - name: c5-wsl4
    url: "http://<tailscale-ip>:8001"
    tier: "1"
    enabled: "true"
    weight: 50
    models:
      - "Qwen3.6-27B-Q4_K_M"
`
	path := writeTempConfig(t, in)
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig back-compat: %v", err)
	}
}
