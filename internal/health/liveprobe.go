package health

import (
	"sync"
	"time"
)

// Defaults for the /healthz?live=1 forced-probe bound.
//
// The background health loop already sweeps every upstream once per
// health_check.interval (15s by default). DefaultLiveProbeInterval is set
// just under that so a caller hammering the forced variant can at worst
// roughly double the probe load the fleet already carries, rather than
// multiply it by the request rate. DefaultLiveProbeBurst leaves room for
// the way the endpoint is actually used by a human or a status page --
// a couple of sweeps back to back while looking at something -- without
// leaving a sustained amplification lever open.
const (
	DefaultLiveProbeInterval = 10 * time.Second
	DefaultLiveProbeBurst    = 3
)

// ProbeLimiter is the token bucket that bounds forced upstream probes.
//
// It is GLOBAL, not per-caller, and deliberately so: the resource being
// protected is the upstream fleet, which is shared by every caller, and a
// per-IP bucket is bypassed by anyone who can reach the router from more
// than one address -- which, on a tailnet, is everyone. A global bucket
// bounds the total probe load the endpoint can generate no matter how the
// requests are spread.
//
// The bucket refills continuously at one token per Interval and saturates
// at Burst tokens, so an idle router answers a small burst of forced
// probes immediately and a busy one degrades smoothly instead of stepping
// between "all allowed" and "all denied".
//
// The zero value is not usable; construct with NewProbeLimiter.
type ProbeLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	burst    int
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// NewProbeLimiter returns a limiter admitting one forced probe per
// interval with the given burst.
//
// A non-positive interval or burst selects the package default rather
// than meaning "unbounded". There is deliberately no spelling for
// unbounded: an unbounded forced-probe path is the exact condition this
// type exists to make unreachable, and a config that reaches the router
// without passing through validation (a hand-built Config in a test, an
// embedded caller) must still be bounded. Zero means the default here and
// in config.LoadConfig, or it does not mean the default at all.
func NewProbeLimiter(interval time.Duration, burst int) *ProbeLimiter {
	return NewProbeLimiterWithClock(interval, burst, time.Now)
}

// NewProbeLimiterWithClock is NewProbeLimiter with an injectable clock so
// callers (and tests) can advance time without sleeping. A nil clock
// selects time.Now.
func NewProbeLimiterWithClock(interval time.Duration, burst int, now func() time.Time) *ProbeLimiter {
	if interval <= 0 {
		interval = DefaultLiveProbeInterval
	}
	if burst <= 0 {
		burst = DefaultLiveProbeBurst
	}
	if now == nil {
		now = time.Now
	}
	return &ProbeLimiter{
		interval: interval,
		burst:    burst,
		tokens:   float64(burst),
		last:     now(),
		now:      now,
	}
}

// Interval reports the effective refill interval (post-defaulting).
func (l *ProbeLimiter) Interval() time.Duration {
	if l == nil {
		return 0
	}
	return l.interval
}

// Burst reports the effective bucket capacity (post-defaulting).
func (l *ProbeLimiter) Burst() int {
	if l == nil {
		return 0
	}
	return l.burst
}

// Allow consumes a token and reports whether a forced probe may run now.
//
// A nil limiter answers false, not true. Denying is the safe direction
// here because the caller's fallback is the cached health view -- it
// still answers 200 with the same shape -- whereas a nil limiter reading
// as "allowed" would turn a wiring mistake into the unbounded path this
// type was added to close, silently.
func (l *ProbeLimiter) Allow() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens += elapsed.Seconds() / l.interval.Seconds()
		if ceiling := float64(l.burst); l.tokens > ceiling {
			l.tokens = ceiling
		}
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
