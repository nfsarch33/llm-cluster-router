package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDefaultConfig_PopulatesCanonicalFields asserts the default
// config matches the v18716.1 kilo-verify defaults so operators
// see the same wire whether they pass --config or rely on the
// built-in defaults.
func TestDefaultConfig_PopulatesCanonicalFields(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Target != "https://helixchannel.example.com/minimax/v1" {
		t.Errorf("Target mismatch: got %q want canonical", cfg.Target)
	}
	if cfg.Model != "MiniMax-M3" {
		t.Errorf("Model mismatch: got %q want canonical", cfg.Model)
	}
	if cfg.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds mismatch: got %d want 30", cfg.TimeoutSeconds)
	}
	if cfg.TLSInsecure {
		t.Errorf("TLSInsecure mismatch: got true want false (default)")
	}
}

// TestLoadConfig_EmptyPathReturnsDefaults asserts that calling
// LoadConfig("") is identical to DefaultConfig (no surprises for
// operators who don't use --config).
func TestLoadConfig_EmptyPathReturnsDefaults(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\"): unexpected error %v", err)
	}
	def := DefaultConfig()
	if cfg.Target != def.Target || cfg.Model != def.Model ||
		cfg.TimeoutSeconds != def.TimeoutSeconds || cfg.TLSInsecure != def.TLSInsecure {
		t.Errorf("LoadConfig(\"\") returned non-default config: %+v vs %+v", cfg, def)
	}
}

// TestLoadConfig_MissingFileReturnsError asserts that a missing
// path produces a clear error (not silent fallback to defaults).
// This catches typos in operator-supplied paths.
func TestLoadConfig_MissingFileReturnsError(t *testing.T) {
	_, err := LoadConfig("/tmp/this-file-does-not-exist-9f7c.yaml")
	if err == nil {
		t.Fatalf("LoadConfig(missing): expected error, got nil")
	}
}

// TestLoadConfig_ParsesCanonicalYAML asserts the YAML parser
// reads a hand-edited config file and propagates values into the
// struct. The test mirrors the schema documented in docs/kilo-code-setup.md.
func TestLoadConfig_ParsesCanonicalYAML(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "helix.yaml")
	content := `target: https://example.test/minimax/v1
model: MiniMax-M3
tls_insecure: true
timeout_seconds: 12
keys:
  - name: minimax
    vault: <vault-name>
    item: <item-uuid>
    field: tagc4supdfgjj3rujdpb67ygm
  - name: grafana
    vault: <vault-name>
    item: deadbeefcafebabe1234567890
    field: 1234567890abcdef1234567890
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%q): %v", path, err)
	}
	if cfg.Target != "https://example.test/minimax/v1" {
		t.Errorf("Target: got %q want https://example.test/minimax/v1", cfg.Target)
	}
	if cfg.Model != "MiniMax-M3" {
		t.Errorf("Model: got %q want MiniMax-M3", cfg.Model)
	}
	if !cfg.TLSInsecure {
		t.Errorf("TLSInsecure: got false want true")
	}
	if cfg.TimeoutSeconds != 12 {
		t.Errorf("TimeoutSeconds: got %d want 12", cfg.TimeoutSeconds)
	}
	if len(cfg.Keys) != 2 {
		t.Fatalf("len(Keys): got %d want 2", len(cfg.Keys))
	}
	if cfg.Keys[0].Name != "minimax" || cfg.Keys[0].Vault != "<vault-name>" ||
		cfg.Keys[0].Item != "<item-uuid>" ||
		cfg.Keys[0].Field != "tagc4supdfgjj3rujdpb67ygm" {
		t.Errorf("Keys[0]: %+v", cfg.Keys[0])
	}
}

// TestLoadConfig_PartialFieldsStillWork asserts that a config
// file with only `target` set still produces a working config
// (other fields fall back to defaults).
func TestLoadConfig_PartialFieldsStillWork(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "partial.yaml")
	if err := os.WriteFile(path, []byte("target: https://only.test/v1\n"), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Target != "https://only.test/v1" {
		t.Errorf("Target: got %q want https://only.test/v1", cfg.Target)
	}
	if cfg.Model != "MiniMax-M3" {
		t.Errorf("Model should fall back to default; got %q", cfg.Model)
	}
	if cfg.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds should fall back to default; got %d", cfg.TimeoutSeconds)
	}
}

// TestLoadConfig_MalformedYAMLReturnsError asserts that a YAML
// file with broken syntax surfaces a parse error (not silent
// fallback).
func TestLoadConfig_MalformedYAMLReturnsError(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "broken.yaml")
	if err := os.WriteFile(path, []byte("target: : :\n  bad"), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("expected parse error from broken YAML, got nil")
	}
}

// TestMergeEnv_OverridesConfigFields asserts env vars win over
// config-file values (precedence: subcommand flag > env > config
// > default). This is required for ad-hoc operator overrides
// during incidents without touching the YAML file.
func TestMergeEnv_OverridesConfigFields(t *testing.T) {
	t.Setenv("HELIXCHANNEL_TARGET", "https://override.test/v1")
	t.Setenv("HELIXCHANNEL_MODEL", "qwen3.5-plus")
	t.Setenv("HELIXCHANNEL_TIMEOUT", "7")
	t.Setenv("HELIXCHANNEL_TLS_INSECURE", "true")

	cfg := DefaultConfig()
	cfg.Target = "https://from-file.test/v1"
	cfg.Model = "MiniMax-M3"
	cfg = mergeEnv(cfg)

	if cfg.Target != "https://override.test/v1" {
		t.Errorf("env did not override Target; got %q", cfg.Target)
	}
	if cfg.Model != "qwen3.5-plus" {
		t.Errorf("env did not override Model; got %q", cfg.Model)
	}
	if cfg.TimeoutSeconds != 7 {
		t.Errorf("env did not override TimeoutSeconds; got %d", cfg.TimeoutSeconds)
	}
	if !cfg.TLSInsecure {
		t.Errorf("env did not flip TLSInsecure to true")
	}
}

// TestMergeEnv_MalformedEnvIgnored asserts a malformed env var
// is ignored rather than invalidating other overrides.
func TestMergeEnv_MalformedEnvIgnored(t *testing.T) {
	t.Setenv("HELIXCHANNEL_TIMEOUT", "not-a-number")
	cfg := DefaultConfig()
	cfg = mergeEnv(cfg)
	if cfg.TimeoutSeconds != DefaultConfig().TimeoutSeconds {
		t.Errorf("malformed env should be ignored; TimeoutSeconds=%d", cfg.TimeoutSeconds)
	}
}

// TestConfig_TimeoutAccessor checks the Duration conversion
// edge cases (zero, negative).
func TestConfig_TimeoutAccessor(t *testing.T) {
	cfg := HelixChannelConfig{}
	if cfg.Timeout() != 30*time.Second {
		t.Errorf("zero TimeoutSeconds should fall back to 30s; got %v", cfg.Timeout())
	}
	cfg.TimeoutSeconds = -5
	if cfg.Timeout() != 30*time.Second {
		t.Errorf("negative TimeoutSeconds should fall back to 30s; got %v", cfg.Timeout())
	}
	cfg.TimeoutSeconds = 5
	if cfg.Timeout() != 5*time.Second {
		t.Errorf("5s expected; got %v", cfg.Timeout())
	}
}
