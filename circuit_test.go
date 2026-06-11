package main

import (
	"errors"
	"testing"
	"time"
)

// TestCircuitBreaker_OpensOnConsecutiveFailures asserts that after
// the configured failure threshold, the breaker opens and short-
// circuits subsequent calls until the cooldown elapses.
func TestCircuitBreaker_OpensOnConsecutiveFailures(t *testing.T) {
	t.Parallel()

	cb := newCircuitBreaker(3, 50*time.Millisecond)
	if !cb.Allow() {
		t.Fatal("breaker should start closed and allow calls")
	}
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("breaker should still allow after 2 of 3 failures")
	}
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker should be open after the 3rd consecutive failure")
	}

	// Half-open after cooldown.
	time.Sleep(70 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("breaker should half-open after cooldown")
	}

	// A success while half-open closes the breaker.
	cb.RecordSuccess()
	if !cb.Allow() {
		t.Fatal("breaker should be closed after a success")
	}
}

// TestCircuitBreaker_HalfOpenFailureReopens asserts that a failure
// during the half-open probe re-opens the breaker for another
// cooldown window.
func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	t.Parallel()

	cb := newCircuitBreaker(2, 30*time.Millisecond)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker should be open after 2 failures")
	}
	time.Sleep(40 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("breaker should half-open after cooldown")
	}
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker should be open again after half-open failure")
	}
}

// TestCircuitBreaker_SuccessResetsFailureCount asserts that a
// success while closed resets the consecutive-failure counter so a
// flapping upstream doesn't trip the breaker on noise.
func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	t.Parallel()

	cb := newCircuitBreaker(3, time.Second)
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("breaker should still be closed after success reset")
	}
}

// TestUpstreamNode_ExposesCircuitBreaker asserts every upstreamNode
// that newRouter constructs has a non-nil circuit breaker, so
// handleProxy can guard each upstream independently.
func TestUpstreamNode_ExposesCircuitBreaker(t *testing.T) {
	t.Parallel()

	cfg := config{
		Defaults: defaults{
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
		},
		Nodes: []nodeConfig{{
			Name: "n1", URL: "http://upstream.example", Tier: "fast",
			Models: []string{"alpha"}, Weight: 1, Enabled: "true",
		}},
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	if len(r.nodes) != 1 {
		t.Fatalf("nodes: got %d, want 1", len(r.nodes))
	}
	if r.nodes[0].breaker == nil {
		t.Fatal("upstreamNode.breaker must be non-nil for circuit-breaker integration")
	}
	if !r.nodes[0].breaker.Allow() {
		t.Fatal("breaker should start closed")
	}
}

// TestSelectNode_SkipsBrokenCircuit asserts that selectNodeFromSnap
// will not return a node whose breaker is open even if the node is
// still marked healthy. This is the direct routing-time consumer
// of the circuit breaker.
func TestSelectNode_SkipsBrokenCircuit(t *testing.T) {
	t.Parallel()

	cfg := config{
		Defaults: defaults{
			MaxConcurrency: 1,
			RequestTimeout: durationValue{Duration: time.Second},
		},
		Nodes: []nodeConfig{
			{Name: "broken", URL: "http://broken.example", Tier: "fast", Models: []string{"alpha"}, Weight: 1, Enabled: "true"},
			{Name: "healthy", URL: "http://healthy.example", Tier: "fast", Models: []string{"alpha"}, Weight: 1, Enabled: "true"},
		},
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	// Force the first node's breaker open.
	for i := 0; i < 10; i++ {
		r.nodes[0].breaker.RecordFailure()
	}
	if r.nodes[0].breaker.Allow() {
		t.Fatal("expected first node's breaker to be open")
	}

	snap := r.snap()
	picked := r.selectNodeFromSnap(snap, "alpha", "", "")
	if picked == nil {
		t.Fatal("selectNodeFromSnap returned nil even though one node is healthy")
	}
	if picked.cfg.Name != "healthy" {
		t.Fatalf("selectNodeFromSnap returned %q, expected the healthy node", picked.cfg.Name)
	}
}

// helpers
//

// errFlaky is the canonical failure newCircuitBreaker callers can
// use to drive recordFailure. Defined here so test files can grow
// without redeclaring it.
var errFlaky = errors.New("flaky upstream")

var _ = errFlaky
