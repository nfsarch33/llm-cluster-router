// Package fairshare implements per-user rate limiting for the
// llm-cluster-router. It uses a sliding-window token bucket per user
// to prevent any single user from monopolising the shared GPU cluster.
//
// The scheduler layers AFTER the global concurrency semaphore:
// global cap provides backpressure; per-user limits prevent starvation.
package fairshare

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// Config holds the fair-share scheduler parameters.
type Config struct {
	MaxRequestsPerUser int           `yaml:"max_requests_per_user"`
	Window             time.Duration `yaml:"window"`
	Burst              int           `yaml:"burst"`
	CleanupInterval    time.Duration `yaml:"cleanup_interval"`
}

// Scheduler tracks per-user request budgets.
type Scheduler struct {
	cfg     Config
	mu      sync.RWMutex
	buckets map[string]*bucket
	stopCh  chan struct{}
}

// New creates a fair-share scheduler with the given config and starts
// a background goroutine to garbage-collect expired buckets.
func New(cfg Config) *Scheduler {
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	s := &Scheduler{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
		stopCh:  make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Acquire attempts to consume one token for the given user. Returns
// true if the request is allowed, false if the user has exceeded
// their per-window budget.
func (s *Scheduler) Acquire(user string) bool {
	s.mu.Lock()
	b, ok := s.buckets[user]
	if !ok {
		b = newBucket(s.cfg.MaxRequestsPerUser, s.cfg.Window, s.cfg.Burst)
		s.buckets[user] = b
	}
	s.mu.Unlock()
	return b.Allow()
}

// Release is called when a request completes. Currently a no-op
// (the token bucket is consume-only), but the interface is provided
// so callers wire it symmetrically and we can add concurrency-per-user
// tracking in the future.
func (s *Scheduler) Release(_ string) {}

// Stop terminates the background cleanup goroutine.
func (s *Scheduler) Stop() {
	close(s.stopCh)
}

func (s *Scheduler) cleanupLoop() {
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.gc()
		}
	}
}

func (s *Scheduler) gc() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for user, b := range s.buckets {
		b.mu.Lock()
		idle := now.Sub(b.lastAccess)
		b.mu.Unlock()
		if idle > s.cfg.Window*2 {
			delete(s.buckets, user)
		}
	}
}

// UserFromToken derives a stable, non-reversible user identifier from
// a bearer token. Used as the fallback when no X-User header is present.
func UserFromToken(token string) string {
	if token == "" {
		return ""
	}
	h := sha256.Sum256([]byte(token))
	return "token:" + fmt.Sprintf("%x", h)[:16]
}

// bucket is a sliding-window token bucket that refills proportionally
// over time rather than resetting all at once.
type bucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  int
	window     time.Duration
	lastRefill time.Time
	lastAccess time.Time
}

func newBucket(maxRequests int, window time.Duration, burst int) *bucket {
	initial := burst
	if initial > maxRequests {
		initial = maxRequests
	}
	now := time.Now()
	return &bucket{
		tokens:     float64(initial),
		maxTokens:  maxRequests,
		window:     window,
		lastRefill: now,
		lastAccess: now,
	}
}

// Allow consumes one token if available. Refills proportionally based
// on elapsed time since the last refill.
func (b *bucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.lastAccess = now

	elapsed := now.Sub(b.lastRefill)
	if elapsed > 0 && b.window > 0 {
		refill := float64(b.maxTokens) * (float64(elapsed) / float64(b.window))
		b.tokens += refill
		if b.tokens > float64(b.maxTokens) {
			b.tokens = float64(b.maxTokens)
		}
		b.lastRefill = now
	}

	if b.tokens < 1.0 {
		return false
	}
	b.tokens--
	return true
}
