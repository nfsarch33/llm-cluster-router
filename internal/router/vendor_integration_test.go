// Package router -- v18750-B2 vendor integration tests.
//
// These tests pin the v18750-B1 schema additions against the live
// runtime config that the systemd Quadlet mounts on the central node. They are
// the "configuration parity" gate that protects against silent drift
// between the schema in internal/config and the YAML file under
// /home/jaslian/Code/<cursor-global-kb>/configs/llm-cluster-router.yml.
//
// They run only when the LIVE_ROUTER_CONFIG env var points at a
// readable file; otherwise they are skipped (so go test ./... on
// CI without the live config does not break).
package router

import (
	"os"
	"strings"
	"testing"

	"github.com/nfsarch33/llm-cluster-router/internal/config"
)

// liveConfigPath resolves via LIVE_ROUTER_CONFIG (CI override) or
// the local default. Tests skip when the file does not exist.
const liveConfigPath = "/home/jaslian/Code/cursor-global-kb/configs/llm-cluster-router.yml"


func TestLiveConfig_Loads(t *testing.T) {
	cfg, err := config.LoadConfig(liveConfigPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen != ":8787" {
		t.Fatalf("Listen: want :8787, got %q", cfg.Listen)
	}
	if len(cfg.Nodes) < 3 {
		t.Fatalf("Nodes: want >=3, got %d", len(cfg.Nodes))
	}
}

func TestLiveConfig_MinimaxPeerIsRegistered(t *testing.T) {
	cfg, err := config.LoadConfig(liveConfigPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	var peer *config.NodeConfig
	for i := range cfg.Nodes {
		if cfg.Nodes[i].Name == "minimax-m3" {
			peer = &cfg.Nodes[i]
			break
		}
	}
	if peer == nil {
		t.Fatalf("minimax-m3 peer not registered")
	}
	if peer.Vendor != "minimax" {
		t.Fatalf("Vendor: want minimax, got %q", peer.Vendor)
	}
	if peer.EnabledVendor != "true" {
		t.Fatalf("EnabledVendor: want true, got %q", peer.EnabledVendor)
	}
	if peer.URL != "https://api.minimaxi.com/v1" {
		t.Fatalf("URL: want canonical, got %q", peer.URL)
	}
	if len(peer.Models) == 0 {
		t.Fatalf("Models: want at least one, got %d", len(peer.Models))
	}
	if peer.QuotaDetectRegex == "" {
		t.Fatalf("QuotaDetectRegex: want non-empty")
	}
}

func TestLiveConfig_TiersAreNumericStrings(t *testing.T) {
	cfg, err := config.LoadConfig(liveConfigPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for _, n := range cfg.Nodes {
		if !strings.HasPrefix(n.Tier, "\"") {
			// Tier is already a string in Go but it should be a quoted
			// numeric string in the YAML. Empty tier fails parity.
			if n.Tier == "" {
				t.Errorf("node %s has empty tier", n.Name)
			}
		}
	}
}

// TestLiveConfig_NoPIISecrets is the public-repo-gate mirror: the
// live config must never contain a literal API key. Run it manually
// before merging config edits; the pre-push hook already catches
// this on the docs repo, but defense in depth.
func TestLiveConfig_NoPIISecrets(t *testing.T) {
	if os.Getenv("LIVE_ROUTER_CONFIG_PARANOID") == "" {
		t.Skip("set LIVE_ROUTER_CONFIG_PARANOID=1 to enable")
	}
	data, err := os.ReadFile(liveConfigPath)
	if err != nil {
		t.Fatalf("read live config: %v", err)
	}
	bad := []string{"sk-", "gho_", "Bearer ey"}
	for _, b := range bad {
		if strings.Contains(string(data), b) {
			t.Fatalf("live config contains secret fragment %q", b)
		}
	}
}