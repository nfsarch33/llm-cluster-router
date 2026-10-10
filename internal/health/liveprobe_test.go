package health

import (
	"sync"
	"testing"
	"time"
)

func TestNewProbeLimiter_DefaultsNonPositive(t *testing.T) {
	tests := []struct {
		name         string
		interval     time.Duration
		burst        int
		wantInterval time.Duration
		wantBurst    int
	}{
		{"both zero take defaults", 0, 0, DefaultLiveProbeInterval, DefaultLiveProbeBurst},
		{"negative interval takes default", -time.Hour, 5, DefaultLiveProbeInterval, 5},
		{"negative burst takes default", 3 * time.Second, -9, 3 * time.Second, DefaultLiveProbeBurst},
		{"explicit values win", 250 * time.Millisecond, 1, 250 * time.Millisecond, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := NewProbeLimiter(tc.interval, tc.burst)
			if got := l.Interval(); got != tc.wantInterval {
				t.Fatalf("Interval() = %v, want %v", got, tc.wantInterval)
			}
			if got := l.Burst(); got != tc.wantBurst {
				t.Fatalf("Burst() = %d, want %d", got, tc.wantBurst)
			}
		})
	}
}

// A non-positive interval or burst must NOT read as "unbounded". This is
// the assertion that keeps the type honest: the whole point is that a
// config which never passed validation is still bounded.
func TestProbeLimiter_NonPositiveIsNotUnbounded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		burst    int
	}{
		{"zero/zero", 0, 0},
		{"negative/negative", -time.Second, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(0, 0)
			l := NewProbeLimiterWithClock(tc.interval, tc.burst, func() time.Time { return now })
			allowed := 0
			for i := 0; i < 100; i++ {
				if l.Allow() {
					allowed++
				}
			}
			if allowed != DefaultLiveProbeBurst {
				t.Fatalf("allowed %d of 100 at a frozen clock, want exactly the default burst %d",
					allowed, DefaultLiveProbeBurst)
			}
		})
	}
}

func TestProbeLimiter_BurstThenRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	l := NewProbeLimiterWithClock(10*time.Second, 3, clock)

	// The burst is spent first, at a frozen clock.
	for i := 1; i <= 3; i++ {
		if !l.Allow() {
			t.Fatalf("burst call %d denied; want allowed", i)
		}
	}
	if l.Allow() {
		t.Fatal("call 4 allowed at a frozen clock; the burst must be exhausted")
	}

	// Half an interval is not a token.
	now = now.Add(5 * time.Second)
	if l.Allow() {
		t.Fatal("allowed after half an interval; refill must be one token per interval")
	}

	// A full interval (the 5s above plus 5s more) is exactly one token.
	now = now.Add(5 * time.Second)
	if !l.Allow() {
		t.Fatal("denied after a full interval elapsed; want one refilled token")
	}
	if l.Allow() {
		t.Fatal("allowed twice off one interval of refill")
	}
}

func TestProbeLimiter_RefillSaturatesAtBurst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewProbeLimiterWithClock(time.Second, 2, func() time.Time { return now })

	// Idle for a very long time: the bucket must cap at Burst, not
	// accumulate a thousand tokens an attacker can spend at once.
	now = now.Add(1000 * time.Second)
	allowed := 0
	for i := 0; i < 50; i++ {
		if l.Allow() {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("allowed %d after a long idle, want the burst cap 2", allowed)
	}
}

// A nil limiter denies. Fail-closed: the caller's fallback is the cached
// health view, which still answers, whereas fail-open would silently
// restore the unbounded path.
func TestProbeLimiter_NilDeniesAndReportsZero(t *testing.T) {
	var l *ProbeLimiter
	if l.Allow() {
		t.Fatal("nil limiter allowed a forced probe; want fail-closed")
	}
	if l.Interval() != 0 || l.Burst() != 0 {
		t.Fatalf("nil limiter reported interval=%v burst=%d, want zeroes", l.Interval(), l.Burst())
	}
}

func TestProbeLimiter_ConcurrentAllowRespectsBurst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewProbeLimiterWithClock(time.Hour, 5, func() time.Time { return now })

	const goroutines = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if l.Allow() {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 5 {
		t.Fatalf("concurrent Allow admitted %d, want exactly the burst 5", allowed)
	}
}
