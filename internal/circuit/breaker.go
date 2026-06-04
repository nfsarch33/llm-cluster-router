// Package circuit implements a per-upstream circuit breaker for the
// llm-cluster-router. It follows the classic three-state pattern
// (closed, open, half-open) and integrates with Prometheus metrics.
package circuit

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// State is the discrete state of a per-upstream circuit breaker.
// Strings are stable for use as Prometheus label values.
type State string

const (
	Closed   State = "closed"
	Open     State = "open"
	HalfOpen State = "half_open"
)

// Breaker is a small, dependency-free implementation of the classic
// three-state breaker pattern. It is per-upstream-node and is
// consulted by the router so a flapping node is dropped from rotation
// faster than the slower health-check loop notices.
type Breaker struct {
	mu        sync.Mutex
	state     State
	failures  int
	threshold int
	cooldown  time.Duration
	openedAt  time.Time
	nodeName  string
	// now is the time source. It defaults to time.Now but can be
	// replaced via WithClock so chaos/recovery tests can advance a fake
	// clock and assert open -> half-open -> closed transitions
	// deterministically without real sleeps (keeping tests race-clean).
	now func() time.Time
}

// NewBreaker builds a closed breaker. threshold is the count of
// consecutive failures that opens the breaker; cooldown is the
// minimum duration the breaker stays open before allowing a probe.
func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Breaker{
		state:     Closed,
		threshold: threshold,
		cooldown:  cooldown,
		now:       time.Now,
	}
}

// WithClock replaces the breaker's time source. Pass nil to reset to the
// real clock. Intended for tests; returns the breaker for chaining.
func (cb *Breaker) WithClock(now func() time.Time) *Breaker {
	cb.mu.Lock()
	if now == nil {
		now = time.Now
	}
	cb.now = now
	cb.mu.Unlock()
	return cb
}

// nowFn returns the configured clock, defaulting to time.Now for breakers
// constructed without NewBreaker (e.g. zero-value structs in tests).
func (cb *Breaker) nowFn() time.Time {
	if cb.now == nil {
		return time.Now()
	}
	return cb.now()
}

// WithName attaches a node name for metric labelling.
func (cb *Breaker) WithName(name string) *Breaker {
	cb.mu.Lock()
	cb.nodeName = name
	cb.mu.Unlock()
	cb.recordState(cb.state)
	return cb
}

// Allow is the routing-time check. Returns true if the breaker
// permits a call.
func (cb *Breaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case Closed:
		return true
	case Open:
		if cb.nowFn().Sub(cb.openedAt) >= cb.cooldown {
			cb.transition(HalfOpen)
			return true
		}
		return false
	case HalfOpen:
		return true
	default:
		return true
	}
}

// RecordSuccess marks a successful upstream call.
func (cb *Breaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	if cb.state != Closed {
		cb.transition(Closed)
	}
}

// RecordFailure marks a failed upstream call.
func (cb *Breaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case HalfOpen:
		cb.openedAt = cb.nowFn()
		cb.transition(Open)
	case Closed:
		cb.failures++
		if cb.failures >= cb.threshold {
			cb.openedAt = cb.nowFn()
			cb.transition(Open)
		}
	case Open:
		// Already open; nothing to do.
	}
}

// GetState returns the current breaker state.
func (cb *Breaker) GetState() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *Breaker) transition(next State) {
	cb.state = next
	cb.recordState(next)
}

func (cb *Breaker) recordState(state State) {
	if cb.nodeName == "" {
		return
	}
	for _, s := range []State{Closed, Open, HalfOpen} {
		v := 0.0
		if s == state {
			v = 1
		}
		StateGauge.WithLabelValues(cb.nodeName, string(s)).Set(v)
	}
}

// StateGauge is the Prometheus gauge for circuit breaker state.
var StateGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "llm_router_circuit_state",
	Help: "Per-upstream circuit-breaker state. 1 in exactly one of state in {closed, open, half_open}.",
}, []string{"node", "state"})
