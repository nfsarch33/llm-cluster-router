package main

import (
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/piiroute"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
)

// The PII-local rule at the SELECTION level (the detector and the
// selection predicate have their own rows in internal/piiroute): a
// payload classified personal may only be served by a pii_local node,
// and when none exists the router returns nil — the handler then fails
// closed with 503 pii_no_local_node; a cloud node is never selected.
// MUTANT: drop the PersonalBlocks filter in selectNodeFromSnapExcluding
// and the cloud row goes red (the personal payload lands on cloud-m3).
func TestSelectNodePersonalNeverClouds(t *testing.T) {
	t.Parallel()

	cfg := config{
		Defaults: defaults{
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
		},
		Nodes: []nodeConfig{
			{Name: "cloud-m3", URL: "http://cloud.example", Tier: "fast", Models: []string{"alpha"}, Weight: 1, Enabled: "true", Priority: 1},
			{Name: "cloud-alt", URL: "http://cloud2.example", Tier: "fast", Models: []string{"alpha"}, Weight: 1, Enabled: "true", Priority: 2},
		},
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	snap := r.snap()

	// Cloud-only pool: a personal payload selects NOTHING (nil is the
	// handler's cue to refuse), while ordinary traffic still routes.
	if got := r.selectNodeFromSnap(snap, "alpha", "", "", proxy.ClassInternal, true); got != nil {
		t.Fatalf("a personal payload must never select a cloud node, got %q", got.cfg.Name)
	}
	if got := r.selectNodeFromSnap(snap, "alpha", "", "", proxy.ClassInternal, false); got == nil {
		t.Fatal("ordinary traffic must still route on the cloud pool")
	}

	// With a pii_local node present, personal selects it — and ONLY it,
	// even at a worse priority than every cloud node.
	cfg.Nodes = append(cfg.Nodes, nodeConfig{
		Name: "local-qwen", URL: "http://local.example", Tier: "fast",
		Models: []string{"alpha"}, Weight: 1, Enabled: "true", Priority: 9, PIILocal: true,
	})
	r2, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter(2): %v", err)
	}
	snap2 := r2.snap()
	for i := 0; i < 8; i++ { // weighted round-robin: every pick must be local
		got := r2.selectNodeFromSnap(snap2, "alpha", "", "", proxy.ClassInternal, true)
		if got == nil || got.cfg.Name != "local-qwen" {
			t.Fatalf("pick %d: personal payload must always land on local-qwen, got %+v", i, got)
		}
	}

	// The detector drives it end to end: a body with an email is personal.
	if !piiroute.DetectPersonal([]byte(`Reply to sam.wong@example.com`)) {
		t.Fatal("detector regression: email payload must classify personal")
	}
}
