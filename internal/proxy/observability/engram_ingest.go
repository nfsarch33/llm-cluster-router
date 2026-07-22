// Copyright (c) 2026 nfsarch33
// SPDX-License-Identifier: Apache-2.0
//
// EngramIngester (v18716.5) periodically probes an upstream
// Engram service and emits an `engram.doctor` event into the
// Agentrace log so the DRL feature pipeline can see queue
// depth + health without pulling a sidecar.

package observability

import (
	"context"
	"sync"
	"time"
)

// EngramProbe is the snapshot an upstream probe (or test stub)
// returns from a single doctor call.
type EngramProbe struct {
	Status             string // "ok" | "warn" | "error"
	EmbedderQueueDepth int64
	EmbedderBackend    string // model name or "engram.local"
	LatencyMs          int64
}

// EngramIngester wires a static EngramProbe snapshot to the
// AgentraceBridge and emits a single Agentrace event per
// RunOnce tick. The probe is fed by the caller (typically the
// dual-listener-demo init path that already has an Engram HTTP
// client); tests inject a value directly. A future enhancement
// may promote EngramProbeFn for live probing; the v18716.5
// scope keeps the surface minimal.
type EngramIngester struct {
	bridge   *AgentraceBridge
	probe    EngramProbe
	interval time.Duration

	mu      sync.Mutex
	cancel  context.CancelFunc
	doneCh  chan struct{}
	stopped bool
}

// NewEngramIngester builds an ingester with the supplied bridge
// and probe snapshot. If bridge is nil, RunOnce is a no-op
// (graceful degradation per the v18716.5 plan); the caller can
// still wire Start/Stop without panicking.
func NewEngramIngester(bridge *AgentraceBridge, probe EngramProbe) *EngramIngester {
	return &EngramIngester{
		bridge:   bridge,
		probe:    probe,
		interval: 30 * time.Second,
	}
}

// SetInterval overrides the periodic interval. Used by tests to
// compress the wait window.
func (e *EngramIngester) SetInterval(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d > 0 {
		e.interval = d
	}
}

// RunOnce emits a single engram.doctor event from the stored
// probe snapshot. Safe to call with a nil bridge (returns nil)
// so the dual-listener-demo can wire it before the Agentrace
// path is fully configured.
func (e *EngramIngester) RunOnce() error {
	if e == nil {
		return nil
	}
	if e.bridge == nil {
		return nil
	}
	return e.bridge.AppendEngramDoctorEvent(e.probe.Status, int(e.probe.EmbedderQueueDepth))
}

// Start launches the periodic loop in a goroutine that ticks
// every `interval`. Returns a stop function that cancels the
// loop and waits for the goroutine to drain. The `interval`
// argument is interpreted as a time.Duration (nanoseconds), so
// callers may pass `1<<20` for an effectively-never-tick
// configuration in tests. Idempotent: a second Start while
// the loop is already running returns a stop function bound to
// the existing loop.
func (e *EngramIngester) Start(interval time.Duration) (stop func()) {
	if e == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = e.interval
	}
	e.mu.Lock()
	if e.cancel != nil {
		existingCancel := e.cancel
		existingDone := e.doneCh
		e.mu.Unlock()
		return func() {
			if existingCancel != nil {
				existingCancel()
			}
			if existingDone != nil {
				<-existingDone
			}
		}
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	e.cancel = cancel
	e.doneCh = doneCh
	e.interval = interval
	finalInterval := interval
	e.mu.Unlock()

	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(finalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				_ = e.RunOnce()
			}
		}
	}()
	return e.Stop
}

// Stop signals the periodic loop to exit and waits for the
// goroutine to drain. Safe to call when Start was never called.
// We capture the cancel/doneCh references and clear them under
// the lock, but we do NOT close doneCh ourselves — the goroutine
// owns the close via defer, so clearing the receiver's pointer
// does not race with the defer.
func (e *EngramIngester) Stop() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	cancel := e.cancel
	doneCh := e.doneCh
	e.cancel = nil
	e.doneCh = nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if doneCh != nil {
		<-doneCh
	}
}
