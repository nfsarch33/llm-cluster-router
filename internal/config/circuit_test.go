package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "router.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

const minimalNode = `
nodes:
  - name: n1
    url: http://127.0.0.1:9001
    models: ["minimax-m3"]
`

func TestLoadConfig_CircuitDefaultsWhenOmitted(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, minimalNode))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Defaults.Circuit.Threshold != DefaultCircuitThreshold {
		t.Errorf("threshold = %d, want default %d", cfg.Defaults.Circuit.Threshold, DefaultCircuitThreshold)
	}
	if cfg.Defaults.Circuit.Cooldown.Duration != DefaultCircuitCooldown {
		t.Errorf("cooldown = %v, want default %v", cfg.Defaults.Circuit.Cooldown.Duration, DefaultCircuitCooldown)
	}
}

func TestLoadConfig_CircuitGlobalOverride(t *testing.T) {
	body := `
defaults:
  circuit:
    threshold: 10
    cooldown: 90s
nodes:
  - name: n1
    url: http://127.0.0.1:9001
`
	cfg, err := LoadConfig(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Defaults.Circuit.Threshold != 10 {
		t.Errorf("threshold = %d, want 10", cfg.Defaults.Circuit.Threshold)
	}
	if cfg.Defaults.Circuit.Cooldown.Duration != 90*time.Second {
		t.Errorf("cooldown = %v, want 90s", cfg.Defaults.Circuit.Cooldown.Duration)
	}
}

func TestResolvedCircuit_NodeOverridesGlobal(t *testing.T) {
	def := Defaults{Circuit: CircuitConfig{Threshold: 8, Cooldown: DurationValue{60 * time.Second}}}
	node := NodeConfig{Circuit: CircuitConfig{Threshold: 3, Cooldown: DurationValue{10 * time.Second}}}
	th, cd := node.ResolvedCircuit(def)
	if th != 3 || cd != 10*time.Second {
		t.Errorf("ResolvedCircuit = (%d, %v), want (3, 10s)", th, cd)
	}
}

func TestResolvedCircuit_InheritsGlobalWhenNodeUnset(t *testing.T) {
	def := Defaults{Circuit: CircuitConfig{Threshold: 8, Cooldown: DurationValue{60 * time.Second}}}
	th, cd := NodeConfig{}.ResolvedCircuit(def)
	if th != 8 || cd != 60*time.Second {
		t.Errorf("ResolvedCircuit = (%d, %v), want (8, 60s)", th, cd)
	}
}

func TestResolvedCircuit_PartialNodeOverride(t *testing.T) {
	def := Defaults{Circuit: CircuitConfig{Threshold: 8, Cooldown: DurationValue{60 * time.Second}}}
	// Only threshold overridden; cooldown inherits the global default.
	node := NodeConfig{Circuit: CircuitConfig{Threshold: 2}}
	th, cd := node.ResolvedCircuit(def)
	if th != 2 || cd != 60*time.Second {
		t.Errorf("ResolvedCircuit = (%d, %v), want (2, 60s)", th, cd)
	}
}

func TestResolvedCircuit_FallsBackToHardDefaults(t *testing.T) {
	// Neither global nor node set: must never return non-positive values.
	th, cd := NodeConfig{}.ResolvedCircuit(Defaults{})
	if th != DefaultCircuitThreshold || cd != DefaultCircuitCooldown {
		t.Errorf("ResolvedCircuit = (%d, %v), want (%d, %v)", th, cd, DefaultCircuitThreshold, DefaultCircuitCooldown)
	}
}
