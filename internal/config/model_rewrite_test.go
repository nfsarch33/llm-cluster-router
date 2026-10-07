package config

import "testing"

func TestLoadConfigModelRewrite(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, `
nodes:
  - name: strict
    url: "http://127.0.0.1:1"
    tier: "0"
    models: ["qwen3.8-27b", "qwen3.8-27b-local"]
    model_rewrite:
      qwen3.8-27b-local: qwen3.8-27b
  - name: plain
    url: "http://127.0.0.1:2"
    tier: "0"
    models: ["m"]
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.Nodes[0].ModelRewrite["qwen3.8-27b-local"]; got != "qwen3.8-27b" {
		t.Fatalf("model_rewrite must parse per node, got %q", got)
	}
	if cfg.Nodes[1].ModelRewrite != nil {
		t.Fatalf("a node without model_rewrite must parse a nil map, got %v", cfg.Nodes[1].ModelRewrite)
	}
}

// The per-node request defaults must load from YAML — yaml.v3 cannot
// decode a scalar into a json.RawMessage byte slice, so the field carries
// a custom unmarshaler converting each value to its JSON literal once.
func TestLoadConfigRequestDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, `
nodes:
  - name: split-engine
    url: "http://127.0.0.1:1"
    tier: "1"
    models: ["reasoning-model"]
    request_defaults:
      reasoning_split: true
      temperature: 0.2
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Nodes) != 1 {
		t.Fatalf("nodes: %d", len(cfg.Nodes))
	}
	rd := cfg.Nodes[0].RequestDefaults
	if got := string(rd["reasoning_split"]); got != "true" {
		t.Fatalf("reasoning_split = %s, want JSON true", got)
	}
	if got := string(rd["temperature"]); got != "0.2" {
		t.Fatalf("temperature = %s, want JSON 0.2", got)
	}
}
