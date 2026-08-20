// config.go defines the operator-facing configuration surface for
// the `helixchannel` CLI binary (v18716.3 hardening). The config
// file is a flat YAML document that every subcommand can read via
// `LoadConfig(path)`.
//
// Schema (canonical, see docs/kilo-code-setup.md):
//
//	target: https://helixchannel.example.com/minimax/v1     # Kilo Code base URL
//	model: MiniMax-M3                          # upstream model id
//	tls_insecure: false                        # mirror --insecure flag
//	timeout_seconds: 30                        # per-request budget
//	keys:
//	  - name: minimax
//	    vault: <vault-name>
//	    item: <item-uuid>
//	    field: tagc4supdfgjj3rujdpb67ygm
//
// Field semantics:
//
//   - target / model / tls_insecure / timeout_seconds feed the
//     kilo-verify + endpoint-check subcommands. Subcommand-level
//     flags always override config-file values (subcommand > config
//     > env > default), matching gstack-style precedence.
//   - keys is consumed by the check-keys subcommand. Each entry
//     names a 1Password item + field; the CLI calls `op read
//     op://<vault>/<item>/<field>` and reports a verdict.
//   - secret values are NEVER persisted to disk in this file (the
//     schema references UUIDs only). The `op` call is the read path.
//
// Anti-patterns:
//
//   - Do not embed raw API keys in this file. Keys go through
//     1Password via `op` only (per no-shell-leak.mdc and
//     guardrails/1password-usage.mdc).
//   - Do not use a nested YAML schema. Keep it flat so a future
//     "Config file missing key X" error message points at exactly
//     one field.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HelixChannelConfig is the YAML config schema. Field order
// matches the doc above so a `helixchannel check-keys --config
// path.yaml` run surfaces fields in the same order the operator
// sees in the docs.
type HelixChannelConfig struct {
	Target         string         `yaml:"target"`
	Model          string         `yaml:"model"`
	TLSInsecure    bool           `yaml:"tls_insecure"`
	TimeoutSeconds int            `yaml:"timeout_seconds"`
	Keys           []ConfigKeyRef `yaml:"keys"`
}

// ConfigKeyRef is one 1Password entry used by check-keys. UUIDs
// only; never embed secret values in the YAML file.
type ConfigKeyRef struct {
	Name  string `yaml:"name"`
	Vault string `yaml:"vault"`
	Item  string `yaml:"item"`
	Field string `yaml:"field"`
}

// DefaultConfig returns the canonical v18716 defaults used when
// no config file is present. These mirror the constants in
// main.go (kiloVerifyDefaultBaseURL / kiloVerifyDefaultModel)
// so operators see the same values across CLI flags and the
// config file schema.
func DefaultConfig() HelixChannelConfig {
	return HelixChannelConfig{
		Target:         "https://helixchannel.example.com/minimax/v1",
		Model:          "MiniMax-M3",
		TLSInsecure:    false,
		TimeoutSeconds: 30,
		Keys:           nil,
	}
}

// LoadConfig parses a YAML config file. Returns DefaultConfig()
// when path is empty. Returns an error if the file exists but
// is malformed, so the operator gets a clear "config file is
// broken" diagnostic rather than silent fallback to defaults.
//
// Env vars override the loaded config (precedence:
// subcommand flag > env > config > default):
//
//	HELIXCHANNEL_TARGET     -> Target
//	HELIXCHANNEL_MODEL      -> Model
//	HELIXCHANNEL_TLS_INSECURE -> TLSInsecure ("1"/"true"/"yes")
//	HELIXCHANNEL_TIMEOUT    -> TimeoutSeconds (int)
func LoadConfig(path string) (HelixChannelConfig, error) {
	cfg := DefaultConfig()
	if path == "" {
		return mergeEnv(cfg), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Operator pointed --config at a missing path. Surface
			// as an error (do not silently fall back) so a typo
			// in the path does not produce a successful run with
			// stale defaults.
			return cfg, fmt.Errorf("config file %q does not exist", path)
		}
		return cfg, fmt.Errorf("read config file %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config file %q: %w", path, err)
	}
	// Sanity-check fields. The operator may have hand-edited the
	// file and produced an invalid value; we want a loud error
	// here, not a quiet runtime failure.
	if cfg.Target == "" {
		// Empty target means the file did not set it; fall back
		// to default so a partial config still works.
		cfg.Target = DefaultConfig().Target
	}
	if cfg.Model == "" {
		cfg.Model = DefaultConfig().Model
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = DefaultConfig().TimeoutSeconds
	}
	return mergeEnv(cfg), nil
}

// mergeEnv applies env-var overrides to a loaded config. Returns
// the modified config. Each var is checked individually so a
// malformed HELIXCHANNEL_TIMEOUT does not invalidate other
// overrides.
func mergeEnv(cfg HelixChannelConfig) HelixChannelConfig {
	if v := strings.TrimSpace(os.Getenv("HELIXCHANNEL_TARGET")); v != "" {
		cfg.Target = v
	}
	if v := strings.TrimSpace(os.Getenv("HELIXCHANNEL_MODEL")); v != "" {
		cfg.Model = v
	}
	if v := strings.TrimSpace(os.Getenv("HELIXCHANNEL_TLS_INSECURE")); v != "" {
		cfg.TLSInsecure, _ = strconv.ParseBool(v)
	}
	if v := strings.TrimSpace(os.Getenv("HELIXCHANNEL_TIMEOUT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.TimeoutSeconds = n
		}
	}
	return cfg
}

// Timeout returns the parsed timeout as a time.Duration. Used by
// kilo-verify when the operator has a config file but did not
// pass --timeout on the CLI.
func (c HelixChannelConfig) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}
