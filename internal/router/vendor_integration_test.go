// Package router -- v18750-B2 vendor integration tests.
//
// These tests pin the v18750-B1 schema additions against the live
// runtime config that the systemd Quadlet mounts on the central node. They are
// the "configuration parity" gate that protects against silent drift
// between the schema in internal/config and the YAML file under
// /home/jaslian/Code/<cursor-global-kb>/configs/llm-cluster-router.yml.
//
// They run only when the config file is readable; otherwise they skip,
// because a parity test with nothing to compare against has nothing to say.
package router

import (
	"os"
	"strings"
	"testing"

	"github.com/nfsarch33/llm-cluster-router/internal/config"
)

// defaultLiveConfigPath is the checkout-relative location on the central node.
// LIVE_ROUTER_CONFIG overrides it.
const defaultLiveConfigPath = "/home/jaslian/Code/cursor-global-kb/configs/llm-cluster-router.yml"

// liveConfigPath honours the LIVE_ROUTER_CONFIG override the package header has
// always documented. Until v18778 the constant was used directly and the
// override did nothing, so the documented contract and the code disagreed.
func liveConfigPath() string {
	if p := os.Getenv("LIVE_ROUTER_CONFIG"); p != "" {
		return p
	}
	return defaultLiveConfigPath
}

// loadLiveConfig resolves the path, skips when the file is absent, and supplies
// placeholder values for the credentials the live config expands.
//
// The placeholders are the point. These tests assert config SHAPE -- that the
// minimax peer is registered, that tiers are non-empty -- and shape does not
// depend on a real credential. But LoadConfig validates after env expansion,
// and an auth_header node whose key expands empty is rejected outright (by
// design: the header would never be sent and every request would silently
// reach the upstream unauthenticated). With no value in the environment, all
// three tests failed on the credential rather than on anything they assert.
//
// That is why llm-cluster-router's CI has been red on main since v18774: the
// config gained an auth_header node, and the self-hosted runner has no
// gateway token in its environment. Supplying an obvious non-credential here
// fixes the tests without weakening the validation they tripped over.
func loadLiveConfig(t *testing.T) config.Config {
	t.Helper()
	path := liveConfigPath()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("live config not readable at %s (%v); set LIVE_ROUTER_CONFIG to point at one", path, err)
	}
	t.Setenv("HELIXCHANNEL_GATEWAY_TOKEN", "placeholder-not-a-real-credential")
	t.Setenv("LLM_ROUTER_TOKEN", "placeholder-not-a-real-credential")
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", path, err)
	}
	return cfg
}

func TestLiveConfig_Loads(t *testing.T) {
	cfg := loadLiveConfig(t)
	if cfg.Listen != ":8787" {
		t.Fatalf("Listen: want :8787, got %q", cfg.Listen)
	}
	if len(cfg.Nodes) < 3 {
		t.Fatalf("Nodes: want >=3, got %d", len(cfg.Nodes))
	}
}

func TestLiveConfig_MinimaxPeerIsRegistered(t *testing.T) {
	cfg := loadLiveConfig(t)
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
	// Until v18778 this asserted peer.URL == "https://api.minimaxi.com/v1",
	// which is exactly the configuration v18774 removed: a direct,
	// unmetered path to the provider whose spend no budget, key rotation or
	// audit log could see. The assertion was pinning the defect.
	//
	// What matters is the guarantee, not the address: paid traffic must not
	// go straight to the vendor, and it must authenticate with a named
	// header rather than a bearer (the caller's own Authorization is
	// scrubbed before dispatch). Asserting the guarantee also keeps the
	// gateway hostname out of this public repository -- it lives only in
	// the private config-as-code that this test reads.
	if strings.Contains(peer.URL, "api.minimaxi.com") {
		t.Errorf("URL %q goes straight to the provider; paid traffic must route through the metered gateway", peer.URL)
	}
	if peer.AuthHeader == "" {
		t.Errorf("AuthHeader is empty; the gateway authenticates on a named header, and an empty one means requests arrive unauthenticated")
	}
	// The proxy joins node.URL with the full request path, so a URL that
	// already ends in /v1 double-joins into /v1/v1/... and 404s. This cost a
	// live restart to discover once.
	if strings.HasSuffix(strings.TrimRight(peer.URL, "/"), "/v1") {
		t.Errorf("URL %q ends in /v1; node URLs are pathless route prefixes and this double-joins at dispatch", peer.URL)
	}
	if len(peer.Models) == 0 {
		t.Fatalf("Models: want at least one, got %d", len(peer.Models))
	}
	if peer.QuotaDetectRegex == "" {
		t.Fatalf("QuotaDetectRegex: want non-empty")
	}
}

func TestLiveConfig_TiersAreNumericStrings(t *testing.T) {
	cfg := loadLiveConfig(t)
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
	data, err := os.ReadFile(liveConfigPath()) //nolint:gosec // G304: operator-provided config path, read-only
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
