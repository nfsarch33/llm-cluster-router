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
