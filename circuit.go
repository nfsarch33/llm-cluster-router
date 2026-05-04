package main

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// circuitState is the discrete state of a per-upstream circuit
// breaker. Strings are stable for use as Prometheus label values
// so the operator can chart breaker state over time.
type circuitState string

const (
	circuitClosed   circuitState = "closed"
	circuitOpen     circuitState = "open"
	circuitHalfOpen circuitState = "half_open"
)

// circuitBreaker is a small, dependency-free implementation of the
// classic three-state breaker pattern. It is per-upstream-node and
// is consulted by selectNodeFromSnap so a flapping node is dropped
// from rotation faster than the slower health-check loop notices.
//
// Threshold semantics:
//   - threshold consecutive failures while closed -> open
//   - cooldown elapsed while open                  -> half-open
//   - any failure while half-open                  -> open
//   - any success while half-open                  -> closed
//   - success while closed resets the failure run
//
// All transitions are recorded into the llm_router_circuit_state
// gauge so Grafana can show breaker history alongside node health.
type circuitBreaker struct {
	mu        sync.Mutex
	state     circuitState
	failures  int
	threshold int
	cooldown  time.Duration
	openedAt  time.Time

	// nodeName is captured for metric labelling. Empty when the
	// breaker is constructed standalone (tests), which is fine --
	// the gauge update degrades to a no-op.
	nodeName string
}

// newCircuitBreaker builds a closed breaker. threshold is the count
// of consecutive failures that opens the breaker; cooldown is the
// minimum duration the breaker stays open before a single probe is
// allowed (the half-open state).
func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &circuitBreaker{
		state:     circuitClosed,
		threshold: threshold,
		cooldown:  cooldown,
	}
}

// withName returns the receiver after attaching a node name for
// metric labelling. Provided as a fluent helper so newRouter can
// wire up labels in one line per node.
func (cb *circuitBreaker) withName(name string) *circuitBreaker {
	cb.mu.Lock()
	cb.nodeName = name
	cb.mu.Unlock()
	cb.recordState(cb.state)
	return cb
}

// allow is the routing-time check. Returns true if the breaker
// permits a call. A side effect of allow() is the open->half_open
// transition when the cooldown has elapsed.
func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case circuitClosed:
		return true
	case circuitOpen:
		if time.Since(cb.openedAt) >= cb.cooldown {
			cb.transition(circuitHalfOpen)
			return true
		}
		return false
	case circuitHalfOpen:
		return true
	default:
		return true
	}
}

// recordSuccess marks a successful upstream call. Resets the
// failure counter and closes the breaker if it was half-open.
func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	if cb.state != circuitClosed {
		cb.transition(circuitClosed)
	}
}

// recordFailure marks a failed upstream call. Opens the breaker
// when consecutive failures hit the threshold (closed) or
// immediately (half-open).
func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case circuitHalfOpen:
		cb.openedAt = time.Now()
		cb.transition(circuitOpen)
	case circuitClosed:
		cb.failures++
		if cb.failures >= cb.threshold {
			cb.openedAt = time.Now()
			cb.transition(circuitOpen)
		}
	case circuitOpen:
		// Already open; nothing to do.
	}
}

// State returns the current breaker state. Provided for tests and
// future operator tooling (e.g., a debug endpoint).
func (cb *circuitBreaker) State() circuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// transition is mu-locked-callers only. Updates state and metric.
func (cb *circuitBreaker) transition(next circuitState) {
	cb.state = next
	cb.recordState(next)
}

// recordState publishes the breaker state to Prometheus. Encoded
// as 0/1 across three label values so the operator can write
//
//	max by (node) (llm_router_circuit_state{state="open"})
//
// to alert on any open breaker without bumping label cardinality
// (3 values per node, fixed).
func (cb *circuitBreaker) recordState(state circuitState) {
	if cb.nodeName == "" {
		return
	}
	for _, s := range []circuitState{circuitClosed, circuitOpen, circuitHalfOpen} {
		v := 0.0
		if s == state {
			v = 1
		}
		circuitStateGauge.WithLabelValues(cb.nodeName, string(s)).Set(v)
	}
}

var circuitStateGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "llm_router_circuit_state",
	Help: "Per-upstream circuit-breaker state. 1 in exactly one of state in {closed, open, half_open}.",
}, []string{"node", "state"})
