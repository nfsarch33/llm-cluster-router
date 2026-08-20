// Package keypool rotates a node's API keys with per-key exhaustion
// cooldowns.
//
// Why this exists: a node backed by several paid token plans (e.g. three
// MiniMax keys) previously rotated keys blind round-robin. When one plan's
// quota ran out, every len(keys)-th request kept using the dead key and
// failed, and the resulting errors were scored against the whole NODE —
// tripping its circuit breaker even though the other plans were healthy.
// The pool keeps failure isolation at the key level: an exhausted key sits
// out its cooldown while the survivors carry the traffic, and only when ALL
// keys are cooling should callers treat the node itself as quota-limited.
package keypool

import (
	"sync/atomic"
	"time"
)

// Pool is a concurrency-safe round-robin over API keys that skips keys
// marked exhausted until their cooldown expires.
type Pool struct {
	keys      []string
	cooldown  time.Duration
	idx       atomic.Uint64
	coolUntil []atomic.Int64 // unix nanos; 0 = healthy

	// now is injectable for tests; defaults to time.Now.
	now func() time.Time
}

// New builds a Pool. A nil/empty key list yields a pool whose Next returns
// ("", -1) — callers fall back to their single-key path. Cooldown <= 0
// disables cooling (pure round-robin, the previous behaviour).
func New(keys []string, cooldown time.Duration) *Pool {
	return &Pool{
		keys:      keys,
		cooldown:  cooldown,
		coolUntil: make([]atomic.Int64, len(keys)),
		now:       time.Now,
	}
}

// Next returns the next healthy key and its index. Keys whose cooldown has
// not expired are skipped. If every key is cooling, the plain round-robin
// key is returned anyway: a last-resort upstream attempt beats a synthetic
// local failure, and node-level failover still applies above this layer.
func (p *Pool) Next() (string, int) {
	n := len(p.keys)
	if n == 0 {
		return "", -1
	}
	nowNano := p.now().UnixNano()
	start := p.idx.Add(1) - 1
	for off := 0; off < n; off++ {
		i := int((start + uint64(off)) % uint64(n))
		if p.coolUntil[i].Load() <= nowNano {
			return p.keys[i], i
		}
	}
	i := int(start % uint64(n))
	return p.keys[i], i
}

// MarkExhausted puts the key at idx on cooldown (no-op for out-of-range
// indices or a non-positive cooldown).
func (p *Pool) MarkExhausted(idx int) {
	if idx < 0 || idx >= len(p.keys) || p.cooldown <= 0 {
		return
	}
	p.coolUntil[idx].Store(p.now().Add(p.cooldown).UnixNano())
}

// Cooling reports how many keys are currently on cooldown.
func (p *Pool) Cooling() int {
	nowNano := p.now().UnixNano()
	c := 0
	for i := range p.coolUntil {
		if p.coolUntil[i].Load() > nowNano {
			c++
		}
	}
	return c
}

// AllCooling reports whether every key is on cooldown — the signal that the
// node as a whole is quota-limited rather than one plan.
func (p *Pool) AllCooling() bool {
	return len(p.keys) > 0 && p.Cooling() == len(p.keys)
}

// Size returns the number of keys in the pool.
func (p *Pool) Size() int { return len(p.keys) }
