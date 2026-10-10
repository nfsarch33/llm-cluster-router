package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfgpkg "github.com/nfsarch33/llm-cluster-router/internal/config"
	"github.com/nfsarch33/llm-cluster-router/internal/fairshare"
)

// TestRunHealthPass_MarksNodeUnhealthyAfterThreshold covers the previously
// untested else-branch: consecutive health-probe failures must flip the node
// unhealthy exactly at UnhealthyThreshold, not before.
func TestRunHealthPass_MarksNodeUnhealthyAfterThreshold(t *testing.T) {
	var failing atomic.Bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)

	c := config{
		Defaults: cfgpkg.Defaults{
			MaxConcurrency: 2, MaxQueueDepth: 4,
			RequestTimeout: cfgpkg.DurationValue{Duration: 2 * time.Second},
		},
		HealthCheck: cfgpkg.HealthConfig{
			Interval:           cfgpkg.DurationValue{Duration: time.Hour}, // loop never fires; we drive passes manually
			Timeout:            cfgpkg.DurationValue{Duration: time.Second},
			UnhealthyThreshold: 3,
			HealthyThreshold:   1,
		},
		Nodes: []cfgpkg.NodeConfig{{
			Name: "probed", URL: up.URL, Tier: "0", Enabled: "true", Weight: 1, Models: []string{"m1"},
		}},
	}
	r, err := newRouter(c)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	node := r.nodes[0]
	node.healthy.Store(true)

	failing.Store(true)
	for pass := 1; pass <= 3; pass++ {
		r.runHealthPass(context.Background())
		if pass < 3 && !node.healthy.Load() {
			t.Fatalf("node flipped unhealthy on pass %d, want only at threshold 3", pass)
		}
	}
	if node.healthy.Load() {
		t.Fatal("node still healthy after UnhealthyThreshold consecutive failures")
	}

	// And the documented recovery path still works after the flip.
	failing.Store(false)
	r.runHealthPass(context.Background())
	if !node.healthy.Load() {
		t.Error("node did not recover after HealthyThreshold passing probes")
	}
}

// TestHandleProxy_FairshareRejectsOverLimitUser covers the fairshare block in
// handleProxy: a user over their window budget gets 429 before any upstream
// call; a different user is unaffected.
func TestHandleProxy_FairshareRejectsOverLimitUser(t *testing.T) {
	var upstreamHits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(up.Close)

	c := config{
		Defaults: cfgpkg.Defaults{
			MaxConcurrency: 4, MaxQueueDepth: 8,
			RequestTimeout: cfgpkg.DurationValue{Duration: 5 * time.Second},
		},
		FairShare: cfgpkg.FairShareConfig{
			Enabled:            true,
			MaxRequestsPerUser: 2,
			Window:             cfgpkg.DurationValue{Duration: time.Minute},
			Burst:              2,
		},
		Nodes: []cfgpkg.NodeConfig{{
			Name: "up", URL: up.URL, Tier: "0", Enabled: "true", Weight: 1, Models: []string{"m1"},
		}},
	}
	r, err := newRouter(c)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	if r.fairScheduler == nil {
		t.Fatal("fairScheduler not constructed despite FairShare.Enabled")
	}
	for _, n := range r.nodes {
		n.healthy.Store(true)
	}

	do := func(user string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"m1","messages":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+user)
		w := httptest.NewRecorder()
		r.handleProxy(w, req)
		return w.Code
	}

	codes := []int{do("user-one"), do("user-one"), do("user-one")}
	rejected := 0
	for _, code := range codes {
		if code == http.StatusTooManyRequests {
			rejected++
		}
	}
	if rejected == 0 {
		t.Errorf("user over budget was never rejected: codes %v", codes)
	}
	if got := do("user-two"); got != http.StatusOK {
		t.Errorf("a different user must be unaffected by user-one's budget, got %d", got)
	}
	_ = fairshare.Config{} // keep the import honest if assertions change
}
