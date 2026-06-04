package config

import "testing"

func TestLoadConfig_HealthCheckDisabledDefaultsFalse(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, minimalNode))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Nodes[0].HealthCheckDisabled {
		t.Errorf("health_check_disabled should default to false (probe enabled) so a tripped node can self-recover")
	}
}

func TestLoadConfig_HealthCheckDisabledParsed(t *testing.T) {
	body := `
nodes:
  - name: m3-key1
    url: http://127.0.0.1:8500
    models: ["minimax-m3"]
    health_check_disabled: false
  - name: legacy-no-probe
    url: http://127.0.0.1:8600
    models: ["minimax-m3"]
    health_check_disabled: true
`
	cfg, err := LoadConfig(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Nodes[0].HealthCheckDisabled {
		t.Errorf("node[0] health_check_disabled = true, want false")
	}
	if !cfg.Nodes[1].HealthCheckDisabled {
		t.Errorf("node[1] health_check_disabled = false, want true")
	}
}
