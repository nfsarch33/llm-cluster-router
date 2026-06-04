package circuit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a monotonic, mutex-guarded clock for deterministic,
// race-clean breaker tests. Advance() moves time forward without any real
// sleeping, so cooldown/half-open transitions are exercised instantly.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(0, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestBreaker_OpensAfterThresholdConsecutiveFailures(t *testing.T) {
	t.Parallel()
	cb := NewBreaker(3, 30*time.Second)

	for i := 0; i < 2; i++ {
		cb.RecordFailure()
		if got := cb.GetState(); got != Closed {
			t.Fatalf("after %d failures state=%s, want closed", i+1, got)
		}
		if !cb.Allow() {
			t.Fatalf("breaker should still allow after %d/<3 failures", i+1)
		}
	}
	cb.RecordFailure() // 3rd consecutive -> open
	if got := cb.GetState(); got != Open {
		t.Fatalf("state=%s after threshold, want open", got)
	}
	if cb.Allow() {
		t.Fatalf("open breaker must not allow before cooldown")
	}
}

func TestBreaker_SuccessResetsFailureCount(t *testing.T) {
	t.Parallel()
	cb := NewBreaker(3, 30*time.Second)
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // resets counter
	cb.RecordFailure()
	cb.RecordFailure() // only 2 consecutive again
	if got := cb.GetState(); got != Closed {
		t.Fatalf("state=%s, want closed (success should have reset the count)", got)
	}
}

// TestBreaker_HalfOpenRecoveryWithFakeClock is the core self-recovery chaos
// case: the breaker trips, refuses traffic during cooldown, half-opens once
// the (fake) clock advances past the cooldown, and closes on the next
// success — all without real sleeps.
func TestBreaker_HalfOpenRecoveryWithFakeClock(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	cb := NewBreaker(2, 30*time.Second).WithClock(clk.Now)

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.GetState() != Open {
		t.Fatalf("breaker should be open after 2 failures")
	}

	// Still within cooldown: no probe allowed.
	clk.Advance(29 * time.Second)
	if cb.Allow() {
		t.Fatalf("breaker must stay open before cooldown elapses")
	}
	if cb.GetState() != Open {
		t.Fatalf("state should remain open mid-cooldown, got %s", cb.GetState())
	}

	// Cooldown elapsed: first Allow half-opens and admits a probe.
	clk.Advance(2 * time.Second)
	if !cb.Allow() {
		t.Fatalf("breaker should allow a probe after cooldown")
	}
	if cb.GetState() != HalfOpen {
		t.Fatalf("state=%s after cooldown probe, want half_open", cb.GetState())
	}

	// Successful probe closes the breaker (upstream recovered).
	cb.RecordSuccess()
	if cb.GetState() != Closed {
		t.Fatalf("state=%s after successful probe, want closed", cb.GetState())
	}
	if !cb.Allow() {
		t.Fatalf("closed breaker should allow traffic")
	}
}

// TestBreaker_HalfOpenFailureReopens asserts that a failed half-open probe
// re-opens the breaker and restarts the cooldown window (no premature flap).
func TestBreaker_HalfOpenFailureReopens(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	cb := NewBreaker(1, 10*time.Second).WithClock(clk.Now)

	cb.RecordFailure() // threshold 1 -> immediately open
	if cb.GetState() != Open {
		t.Fatalf("want open")
	}
	clk.Advance(10 * time.Second)
	if !cb.Allow() || cb.GetState() != HalfOpen {
		t.Fatalf("want half_open probe admitted after cooldown")
	}
	cb.RecordFailure() // probe failed -> reopen, cooldown restarts
	if cb.GetState() != Open {
		t.Fatalf("failed half-open probe should reopen breaker, got %s", cb.GetState())
	}
	// Cooldown window restarted at the reopen instant.
	clk.Advance(9 * time.Second)
	if cb.Allow() {
		t.Fatalf("breaker must not allow before the restarted cooldown elapses")
	}
	clk.Advance(2 * time.Second)
	if !cb.Allow() {
		t.Fatalf("breaker should re-probe once the restarted cooldown elapses")
	}
}

// TestBreaker_ConcurrentRecordRace hammers the breaker from many goroutines
// to prove it is race-clean (run under -race). It does not assert a specific
// final state, only that no data race or panic occurs and the state stays
// within the valid set.
func TestBreaker_ConcurrentRecordRace(t *testing.T) {
	t.Parallel()
	cb := NewBreaker(5, time.Millisecond)
	var wg sync.WaitGroup
	var allows atomic.Int64
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if cb.Allow() {
					allows.Add(1)
				}
				if (i+j)%3 == 0 {
					cb.RecordFailure()
				} else {
					cb.RecordSuccess()
				}
			}
		}(i)
	}
	wg.Wait()
	switch cb.GetState() {
	case Closed, Open, HalfOpen:
	default:
		t.Fatalf("breaker ended in invalid state %q", cb.GetState())
	}
}
