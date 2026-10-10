package channel

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeClock serialises its own state. A bare captured time.Time mutated by
// the test body would be read from every store goroutine and is a genuine
// data race that -race will, correctly, fail on.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// countingObserver replaces the Prometheus sink so a unit test can assert
// retirement reasons without touching a global registry.
type countingObserver struct {
	mu     sync.Mutex
	counts map[RetireReason]int
}

func newCountingObserver() *countingObserver {
	return &countingObserver{counts: map[RetireReason]int{}}
}

func (o *countingObserver) KeyRetired(_ string, reason RetireReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.counts[reason]++
}

func (o *countingObserver) count(r RetireReason) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.counts[r]
}

func (o *countingObserver) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, v := range o.counts {
		n += v
	}
	return n
}

// stubPolicy always answers the same position, including deliberately
// impossible ones, so the store's containment can be exercised.
type stubPolicy struct{ ret int }

func (p stubPolicy) Select([]KeyState) int { return p.ret }

func snapshotOf(t *testing.T, s *Store, route string, idx int) KeyState {
	t.Helper()
	snap := s.Snapshot(route)
	if idx < 0 || idx >= len(snap) {
		t.Fatalf("Snapshot(%q) returned %d keys, want index %d to exist", route, len(snap), idx)
	}
	return snap[idx]
}

// ---------------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------------

// TestStore_SoftCapRetiresKeyBeforeItErrors is the planned-rotation property:
// a key must leave rotation while it still has headroom, rather than being
// discovered dead by an upstream error.
func TestStore_SoftCapRetiresKeyBeforeItErrors(t *testing.T) {
	t.Parallel()
	clk, obs := newFakeClock(), newCountingObserver()
	st := NewStore(map[string]int{"r": 3},
		WithClock(clk.Now), WithRetireObserver(obs),
		WithBudget(Budget{Window: 5 * time.Minute, Requests: 10, SoftRatio: 0.8}))

	for i := 0; i < 8; i++ {
		st.RecordUsage("r", 0, 0)
	}

	k0 := snapshotOf(t, st, "r", 0)
	if k0.Selectable {
		t.Errorf("key 0 selectable after 8/10 requests, want retired at the 80%% soft cap")
	}
	if k0.Reason != ReasonCap {
		t.Errorf("key 0 reason = %q, want %q", k0.Reason, ReasonCap)
	}
	if k0.Drained {
		t.Errorf("key 0 drained at 8/10, want soft-retired only")
	}
	if got := obs.count(ReasonCap); got != 1 {
		t.Errorf("retired{reason=cap} = %d, want exactly 1", got)
	}
	for i := 0; i < 30; i++ {
		if got := st.Next("r"); got == 0 {
			t.Fatalf("Next returned the soft-retired key 0 on call %d", i)
		}
	}
}

// TestStore_SoftCapFiresOncePerKeyPerWindow: late settlements of in-flight
// leases must not re-emit the retirement they already caused.
func TestStore_SoftCapFiresOncePerKeyPerWindow(t *testing.T) {
	t.Parallel()
	clk, obs := newFakeClock(), newCountingObserver()
	st := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(obs),
		WithBudget(Budget{Window: 5 * time.Minute, Requests: 10, SoftRatio: 0.8}))

	for i := 0; i < 8; i++ {
		st.RecordUsage("r", 0, 0)
	}
	if got := obs.count(ReasonCap); got != 1 {
		t.Fatalf("retired{cap} after soft trip = %d, want 1", got)
	}
	st.RecordUsage("r", 0, 0)
	st.RecordUsage("r", 0, 0)
	if got := obs.count(ReasonCap); got != 1 {
		t.Errorf("retired{cap} after two late settlements = %d, want it to stay 1", got)
	}
}

// TestStore_HardCapMarksDrainedDistinguishably: "spent its whole plan" and
// "parked early on purpose" are different operational facts even though both
// are unselectable.
func TestStore_HardCapMarksDrainedDistinguishably(t *testing.T) {
	t.Parallel()
	clk, obs := newFakeClock(), newCountingObserver()
	st := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(obs),
		WithBudget(Budget{Window: 5 * time.Minute, Tokens: 1000, EstimateTokens: 100}))

	st.RecordUsage("r", 0, 1000)
	st.RecordUsage("r", 1, 800)

	drained := snapshotOf(t, st, "r", 0)
	soft := snapshotOf(t, st, "r", 1)
	if !drained.Drained {
		t.Errorf("key 0 Drained = false after charging the full 1000-token cap")
	}
	if drained.Selectable {
		t.Errorf("key 0 selectable after being drained")
	}
	if soft.Drained {
		t.Errorf("key 1 Drained = true at 800/1000, want soft-retired and NOT drained")
	}
	if !soft.SoftRetired || soft.Selectable {
		t.Errorf("key 1 SoftRetired=%v Selectable=%v, want soft-retired and unselectable", soft.SoftRetired, soft.Selectable)
	}
	if got := st.Next("r"); got != -1 {
		t.Errorf("Next = %d with every key spent, want -1", got)
	}
}

// ---------------------------------------------------------------------------
// Retry-After
// ---------------------------------------------------------------------------

func TestStore_RetryAfterIsTrueMinimumAcrossKeys(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: 5 * time.Minute, Tokens: 1000, EstimateTokens: 100}))

	clk.Advance(4*time.Minute + 15*time.Second) // 45s left in the window
	st.Retire("r", 0, clk.Now().Add(300*time.Second))
	st.RecordUsage("r", 1, 1000) // drained until the window ends

	d, ok := st.RetryAfter("r")
	if !ok {
		t.Fatalf("RetryAfter ok = false, want true with every key spent")
	}
	if d != 45*time.Second {
		t.Errorf("RetryAfter = %v, want 45s (the window end beats key 0's 300s cooldown)", d)
	}
}

func TestStore_RetryAfterIsClampedAndNeverZero(t *testing.T) {
	t.Parallel()
	t.Run("clamped to max", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		st := NewStore(map[string]int{"r": 2}, WithClock(clk.Now),
			WithRetireObserver(newCountingObserver()), WithMaxRetryAfter(time.Hour))
		for i := 0; i < 2; i++ {
			st.Retire("r", i, clk.Now().Add(6*time.Hour))
		}
		d, ok := st.RetryAfter("r")
		if !ok || d != time.Hour {
			t.Fatalf("RetryAfter = (%v, %v), want (1h, true): an hours-long value is fatal to several agents", d, ok)
		}
	})
	t.Run("floored to min", func(t *testing.T) {
		t.Parallel()
		clk := newFakeClock()
		st := NewStore(map[string]int{"r": 1}, WithClock(clk.Now),
			WithRetireObserver(newCountingObserver()), WithMaxRetryAfter(time.Hour))
		st.Retire("r", 0, clk.Now().Add(200*time.Millisecond))
		d, ok := st.RetryAfter("r")
		if !ok || d != MinRetryAfter {
			t.Fatalf("RetryAfter = (%v, %v), want (%v, true): Retry-After: 0 tells a client nothing", d, ok, MinRetryAfter)
		}
	})
	t.Run("not reported while a key is live", func(t *testing.T) {
		t.Parallel()
		st := NewStore(map[string]int{"r": 2}, WithRetireObserver(newCountingObserver()))
		if d, ok := st.RetryAfter("r"); ok {
			t.Fatalf("RetryAfter = (%v, true) with live keys, want ok=false", d)
		}
	})
}

// ---------------------------------------------------------------------------
// Window rollover
// ---------------------------------------------------------------------------

func TestStore_WindowRolloverRestoresEveryKey(t *testing.T) {
	t.Parallel()
	clk, obs := newFakeClock(), newCountingObserver()
	st := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(obs),
		WithBudget(Budget{Window: 5 * time.Minute, Requests: 10, SoftRatio: 0.8}))

	for i := 0; i < 10; i++ {
		st.RecordUsage("r", 0, 5)
	}
	for i := 0; i < 8; i++ {
		st.RecordUsage("r", 1, 5)
	}
	if got := st.Next("r"); got != -1 {
		t.Fatalf("Next = %d before rollover, want -1 (one drained, one soft-retired)", got)
	}

	clk.Advance(5*time.Minute + time.Second)

	if got := st.Next("r"); got < 0 {
		t.Fatalf("Next = %d after the window rolled, want a live key", got)
	}
	for i, k := range st.Snapshot("r") {
		if !k.Selectable || k.Drained || k.SoftRetired {
			t.Errorf("key %d after rollover: selectable=%v drained=%v soft=%v, want a clean key",
				i, k.Selectable, k.Drained, k.SoftRetired)
		}
		if k.Requests != 0 || k.Tokens != 0 {
			t.Errorf("key %d after rollover: requests=%d tokens=%d, want the counters zeroed", i, k.Requests, k.Tokens)
		}
	}
}

// TestStore_RolloverKeepsAnExplicitRetirement: a one-hour upstream quota
// cooldown must survive a five-minute accounting boundary.
func TestStore_RolloverKeepsAnExplicitRetirement(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: 5 * time.Minute, Requests: 10}))

	st.Retire("r", 0, clk.Now().Add(time.Hour))
	clk.Advance(6 * time.Minute)

	k0 := snapshotOf(t, st, "r", 0)
	if k0.Selectable {
		t.Fatalf("key 0 selectable after rollover, want the 1h quota cooldown to outlive the 5m window")
	}
	if k0.Reason != ReasonQuota {
		t.Errorf("key 0 reason = %q, want %q", k0.Reason, ReasonQuota)
	}
	for i := 0; i < 10; i++ {
		if got := st.Next("r"); got != 1 {
			t.Fatalf("Next = %d, want 1 (key 0 is still cooling down)", got)
		}
	}
}

// TestStore_RolloverAccountsSettlementsToTheRightWindow proves both halves of
// the boundary contract without sleeping.
func TestStore_RolloverAccountsSettlementsToTheRightWindow(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 4},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: time.Minute}))

	leases := make([]*KeyLease, 0, 100)
	for i := 0; i < 100; i++ {
		l, ok := st.Acquire("r")
		if !ok {
			t.Fatalf("Acquire failed on lease %d", i)
		}
		leases = append(leases, l)
	}
	for _, l := range leases[:40] {
		l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 1})
	}
	if got := totalRequests(st, "r"); got != 40 {
		t.Fatalf("requests before the boundary = %d, want 40", got)
	}

	clk.Advance(time.Minute + time.Second)
	for _, l := range leases[40:] {
		l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 1})
	}
	if got := totalRequests(st, "r"); got != 60 {
		t.Errorf("requests after the boundary = %d, want 60 charged to the NEW window", got)
	}
	for i, k := range st.Snapshot("r") {
		if k.InFlight != 0 {
			t.Errorf("key %d InFlight = %d after every lease settled, want 0", i, k.InFlight)
		}
	}
}

func totalRequests(s *Store, route string) int64 {
	var n int64
	for _, k := range s.Snapshot(route) {
		n += k.Requests
	}
	return n
}

// ---------------------------------------------------------------------------
// Retirement reasons and inert inputs
// ---------------------------------------------------------------------------

func TestStore_RetireAttributesReasons(t *testing.T) {
	t.Parallel()
	clk, obs := newFakeClock(), newCountingObserver()
	st := NewStore(map[string]int{"r": 2}, WithClock(clk.Now), WithRetireObserver(obs))

	st.Retire("r", 0, clk.Now().Add(time.Minute))
	if got := obs.count(ReasonQuota); got != 1 {
		t.Errorf("retired{quota} = %d, want 1 (Retire is the upstream-quota path)", got)
	}
	st.RetireWithReason("r", 1, clk.Now().Add(time.Minute), ReasonError)
	if got := obs.count(ReasonError); got != 1 {
		t.Errorf("retired{error} = %d, want 1", got)
	}
	if got := obs.count(ReasonCap); got != 0 {
		t.Errorf("retired{cap} = %d, want 0: an upstream failure is not this gateway's accounting", got)
	}
	if got := obs.count(ReasonQuota); got != 1 {
		t.Errorf("retired{quota} = %d after an error retirement, want it unchanged at 1", got)
	}
}

func TestStore_RetireWithPastDeadlineIsNeverAnUnRetirement(t *testing.T) {
	t.Parallel()
	clk, obs := newFakeClock(), newCountingObserver()
	st := NewStore(map[string]int{"r": 2}, WithClock(clk.Now), WithRetireObserver(obs))

	deadline := clk.Now().Add(10 * time.Minute)
	st.Retire("r", 0, deadline)
	st.Retire("r", 0, clk.Now().Add(-time.Second))

	k0 := snapshotOf(t, st, "r", 0)
	if k0.Selectable {
		t.Fatalf("key 0 became selectable after a past-deadline Retire; that is an un-retirement")
	}
	if !k0.RetiredUntil.Equal(deadline) {
		t.Errorf("RetiredUntil = %v, want the original %v", k0.RetiredUntil, deadline)
	}
	if got := obs.total(); got != 1 {
		t.Errorf("retirement events = %d, want 1 (the no-op must not emit)", got)
	}
}

func TestStore_OutOfRangeAndUnknownRouteCallsAreInert(t *testing.T) {
	t.Parallel()
	clk, obs := newFakeClock(), newCountingObserver()
	st := NewStore(map[string]int{"r": 2}, WithClock(clk.Now), WithRetireObserver(obs))

	if got := st.Next("no-such-route"); got != -1 {
		t.Errorf("Next(unknown route) = %d, want -1", got)
	}
	st.RecordUsage("r", -1, 5)
	st.RecordUsage("r", 99, 5)
	st.Retire("r", -1, clk.Now().Add(time.Minute))
	st.Retire("no-such-route", 0, clk.Now().Add(time.Minute))
	st.RecordUsage("no-such-route", 0, 5)
	if snap := st.Snapshot("no-such-route"); snap != nil {
		t.Errorf("Snapshot(unknown route) = %v, want nil", snap)
	}
	if got := obs.total(); got != 0 {
		t.Errorf("retirement events = %d after inert calls, want 0", got)
	}
	for _, k := range st.Snapshot("r") {
		if k.Requests != 0 || k.Tokens != 0 || !k.Selectable {
			t.Errorf("valid route perturbed by out-of-range calls: %+v", k)
		}
	}
	if got := st.Next("r"); got != 0 {
		t.Errorf("Next on the valid route = %d, want 0", got)
	}
}

// TestStore_ContainsAnOutOfRangePolicyAnswer: returning a position rather than
// an index makes an out-of-range answer the only possible policy mistake, and
// the store must absorb it rather than index out of range.
func TestStore_ContainsAnOutOfRangePolicyAnswer(t *testing.T) {
	t.Parallel()
	for name, ret := range map[string]int{"too high": 42, "negative": -7} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := NewStore(map[string]int{"r": 3},
				WithRetireObserver(newCountingObserver()), WithPolicy(stubPolicy{ret: ret}))
			if got := st.Next("r"); got != 0 {
				t.Fatalf("first Next = %d, want 0 from the round-robin fallback", got)
			}
			if got := st.Next("r"); got != 1 {
				t.Fatalf("second Next = %d, want 1 from the round-robin fallback", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Leases
// ---------------------------------------------------------------------------

func TestStore_LeaseSettlementIsIdempotent(t *testing.T) {
	t.Parallel()
	st := NewStore(map[string]int{"r": 2}, WithRetireObserver(newCountingObserver()))
	l, ok := st.Acquire("r")
	if !ok {
		t.Fatal("Acquire = !ok on a fresh route")
	}
	l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 10})
	l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 10})

	k := snapshotOf(t, st, "r", l.Index())
	if k.InFlight != 0 {
		t.Errorf("InFlight = %d after double Settle, want 0", k.InFlight)
	}
	if k.Requests != 1 {
		t.Errorf("Requests = %d after double Settle, want exactly 1", k.Requests)
	}
	if k.Tokens != 10 {
		t.Errorf("Tokens = %d after double Settle, want 10 charged once", k.Tokens)
	}
}

// TestStore_FailedOutcomeReleasesWithoutCharging: a dead upstream must not
// make a healthy key look like the most-used one.
func TestStore_FailedOutcomeReleasesWithoutCharging(t *testing.T) {
	t.Parallel()
	st := NewStore(map[string]int{"r": 2}, WithRetireObserver(newCountingObserver()))
	l, _ := st.Acquire("r")
	l.Settle(UsageSample{Outcome: OutcomeFailed})

	k := snapshotOf(t, st, "r", l.Index())
	if k.InFlight != 0 {
		t.Errorf("InFlight = %d, want 0: a failed request must release its lease", k.InFlight)
	}
	if k.Requests != 0 || k.Tokens != 0 {
		t.Errorf("Requests=%d Tokens=%d, want both unchanged on a failure", k.Requests, k.Tokens)
	}
	if k.Errors != 1 {
		t.Errorf("Errors = %d, want 1", k.Errors)
	}
}

// TestStore_UnknownTokensChargeTheEstimateAndMarkTheKey is the streaming
// fallback: charging zero would let an all-streaming route spend a token
// budget that never advances.
func TestStore_UnknownTokensChargeTheEstimateAndMarkTheKey(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 2}, WithClock(clk.Now),
		WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: 5 * time.Minute, Tokens: 1000, EstimateTokens: 150}))

	l, _ := st.Acquire("r")
	l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: TokensUnknown})

	k := snapshotOf(t, st, "r", l.Index())
	if k.Requests != 1 {
		t.Errorf("Requests = %d, want 1", k.Requests)
	}
	if k.Tokens != 150 {
		t.Errorf("Tokens = %d, want the 150-token estimate, never 0", k.Tokens)
	}
	if !k.Estimated {
		t.Error("Estimated = false, want true so cross-key token comparisons stop being trusted")
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestStore_ConcurrentRetireNeverYieldsARetiredSelection: once a retirement
// has been committed, no later Acquire may lease that key. Select runs under
// the store lock, so there is no read-then-reserve gap to exploit.
func TestStore_ConcurrentRetireNeverYieldsARetiredSelection(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 4}, WithClock(clk.Now),
		WithRetireObserver(newCountingObserver()), WithPolicy(NewLeastUsedPolicy()))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(mine int) {
			defer wg.Done()
			st.Retire("r", mine, clk.Now().Add(time.Hour))
			for n := 0; n < 200; n++ {
				l, ok := st.Acquire("r")
				if !ok {
					continue
				}
				if l.Index() == mine {
					t.Errorf("Acquire leased key %d after its retirement was committed", mine)
				}
				l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 1})
			}
		}(i)
	}
	// Independent readers, so the lock is genuinely contended.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				_ = st.Snapshot("r")
				_, _ = st.RetryAfter("r")
			}
		}()
	}
	wg.Wait()

	if got := st.Next("r"); got != -1 {
		t.Errorf("Next = %d with all four keys retired for an hour, want -1", got)
	}
}

func TestStore_RolloverUnderConcurrentTrafficLosesNothing(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 4}, WithClock(clk.Now),
		WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: time.Minute}))

	var wg sync.WaitGroup
	release := make(chan struct{})
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			l, ok := st.Acquire("r")
			if !ok {
				t.Error("Acquire failed on an uncapped route")
				return
			}
			defer l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 7})
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-release
		for i := 0; i < 20; i++ {
			clk.Advance(10 * time.Second)
			_ = st.Snapshot("r")
		}
	}()
	close(release)
	wg.Wait()

	for i, k := range st.Snapshot("r") {
		if k.InFlight != 0 {
			t.Errorf("key %d InFlight = %d after every settlement, want 0", i, k.InFlight)
		}
		if k.Requests < 0 || k.Tokens < 0 {
			t.Errorf("key %d went negative across a boundary: %+v", i, k)
		}
	}
}

// TestStore_StartsNoGoroutines: rollover is lazy and evaluated from the clock
// on each call, so there is no timer goroutine to leak and goleak (which is
// not a dependency here) is unnecessary.
func TestStore_StartsNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 3}, WithClock(clk.Now),
		WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: time.Minute, Requests: 5, EstimateTokens: 1}))
	for i := 0; i < 20; i++ {
		if l, ok := st.Acquire("r"); ok {
			l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 1})
		}
		clk.Advance(20 * time.Second)
	}

	// Bounded settle-poll: unrelated goroutines from other tests may still be
	// winding down, so poll rather than assert on a single sample.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if runtime.NumGoroutine() <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d, want <= %d: the store must start none",
				runtime.NumGoroutine(), before)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Rotation configuration
// ---------------------------------------------------------------------------

// rotationRoute builds a POOLED inject route. Pooled is the only shape a
// rotation block is legal on, so every case below starts from one.
func rotationRoute(mutate func(r *Route)) Config {
	r := Route{
		Name: "mm", Prefix: "/mm/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnvs: []string{"TEST_ROTATION_KEY_A", "TEST_ROTATION_KEY_B"},
		Enabled: true,
	}
	if mutate != nil {
		mutate(&r)
	}
	return Config{Listen: "127.0.0.1:0", Routes: []Route{r}}
}

func TestConfigValidate_RotationRules(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		cfg  Config
		want string
	}{
		"singular and plural key sources mixed": {
			cfg:  rotationRoute(func(r *Route) { r.KeyEnv = "TEST_ONE_KEY" }),
			want: "credential sources are mutually exclusive",
		},
		"declared but empty key list": {
			cfg:  rotationRoute(func(r *Route) { r.KeyEnvs = []string{} }),
			want: "must not be empty",
		},
		"blank entry in a key list": {
			cfg:  rotationRoute(func(r *Route) { r.KeyEnvs = []string{"A", "  "} }),
			want: "contains a blank entry",
		},
		"same source named twice": {
			cfg:  rotationRoute(func(r *Route) { r.KeyEnvs = []string{"A", "A"} }),
			want: "duplicate key source",
		},
		"two spellings of one key file": {
			cfg: rotationRoute(func(r *Route) {
				r.KeyEnvs = nil
				r.KeyFiles = []string{"/run/secrets/a.key", "/run/secrets/./a.key"}
			}),
			want: "duplicate key source",
		},
		"malformed key_refs entry": {
			cfg: rotationRoute(func(r *Route) {
				r.KeyEnvs = nil
				r.KeyRefs = []string{"op://only/two"}
			}),
			want: "key_refs[0]",
		},
		"unknown policy": {
			cfg:  rotationRoute(func(r *Route) { r.Rotation = &RotationConfig{Policy: "random"} }),
			want: "rotation policy must be",
		},
		"negative soft ratio": {
			cfg: rotationRoute(func(r *Route) {
				r.Rotation = &RotationConfig{Budget: Budget{Window: time.Minute, SoftRatio: -0.5}}
			}),
			want: "soft_ratio",
		},
		"soft ratio above one": {
			cfg: rotationRoute(func(r *Route) {
				r.Rotation = &RotationConfig{Budget: Budget{Window: time.Minute, SoftRatio: 1.5}}
			}),
			want: "soft_ratio",
		},
		"token budget without an estimate charge": {
			cfg: rotationRoute(func(r *Route) {
				r.Rotation = &RotationConfig{Budget: Budget{Window: time.Minute, Tokens: 1000000}}
			}),
			want: "estimate_tokens",
		},
		"caps without a window": {
			cfg: rotationRoute(func(r *Route) {
				r.Rotation = &RotationConfig{Budget: Budget{Requests: 10}}
			}),
			want: "window",
		},
		"negative max_retry_after": {
			cfg: rotationRoute(func(r *Route) {
				r.Rotation = &RotationConfig{MaxRetryAfter: -time.Second}
			}),
			want: "max_retry_after must not be negative",
		},
		"rotation on a passthrough route": {
			cfg: Config{Listen: "127.0.0.1:0", Routes: []Route{{
				Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
				Auth: AuthPassthrough, Rotation: &RotationConfig{}, Enabled: true,
			}}},
			want: "nothing to rotate",
		},
		"plural key sources on a passthrough route": {
			cfg: Config{Listen: "127.0.0.1:0", Routes: []Route{{
				Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
				Auth: AuthPassthrough, KeyEnvs: []string{"A"}, Enabled: true,
			}}},
			want: "must not set",
		},
		// The rule neither source branch had: a budget an operator can write
		// and the gateway will never enforce is a silent failure, not a
		// default.
		"rotation on a single-key route": {
			cfg: Config{Listen: "127.0.0.1:0", Routes: []Route{{
				Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
				Auth: AuthInject, KeyEnv: "A", Rotation: &RotationConfig{}, Enabled: true,
			}}},
			want: "rotation requires a key pool",
		},
		// A header-auth upstream reports no usage.total_tokens, so
		// least_tokens there would silently behave as least_used.
		"least_tokens on a header route": {
			cfg: Config{Listen: "127.0.0.1:0", Routes: []Route{{
				Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
				Auth: AuthHeaderInject, KeyHeader: "x-api-key",
				KeyFiles: []string{"/run/secrets/a.key", "/run/secrets/b.key"},
				Rotation: &RotationConfig{Policy: PolicyLeastTokens}, Enabled: true,
			}}},
			want: `would silently behave as "least_used"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := tc.cfg
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestConfigValidate_LeastUsedIsSupportedOnAHeaderRoute is the other half of
// the header+budget composition rule: only least_tokens is rejected, because
// only least_tokens claims to compare a figure the upstream never reports.
func TestConfigValidate_LeastUsedIsSupportedOnAHeaderRoute(t *testing.T) {
	t.Parallel()
	cfg := Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "exa", Prefix: "/exa/", Upstream: "https://example.invalid",
		Auth: AuthHeaderInject, KeyHeader: "x-api-key",
		KeyFiles: []string{"/run/secrets/a.key", "/run/secrets/b.key"},
		Rotation: &RotationConfig{
			Policy: PolicyLeastUsed,
			Budget: Budget{Window: 24 * time.Hour, Requests: 1000},
		},
		Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v (auth: header with a request budget must be supported)", err)
	}
}

func TestConfigValidate_RotationDefaultsAreApplied(t *testing.T) {
	t.Parallel()
	cfg := rotationRoute(func(r *Route) {
		r.Rotation = &RotationConfig{Budget: Budget{Window: time.Minute, Requests: 10}}
	})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	rot := cfg.Routes[0].Rotation
	if rot.Policy != PolicyRoundRobin {
		t.Errorf("policy = %q, want %q so an un-annotated route keeps today's ordering", rot.Policy, PolicyRoundRobin)
	}
	if rot.Budget.SoftRatio != DefaultSoftRatio {
		t.Errorf("soft_ratio = %v, want %v", rot.Budget.SoftRatio, DefaultSoftRatio)
	}
	if rot.MaxRetryAfter != DefaultMaxRetryAfter {
		t.Errorf("max_retry_after = %v, want %v", rot.MaxRetryAfter, DefaultMaxRetryAfter)
	}
}

// ---------------------------------------------------------------------------
// The ONE rotation shape, with the shipped scalar shorthand
// ---------------------------------------------------------------------------

// TestRotationConfig_AcceptsBothShippedSpellings is what makes one schema serve
// two already-deployed example files: `rotation: round_robin` was shipped by
// one branch, `rotation: {policy: ..., budget: {...}}` by the other. Dropping
// either would turn a deployed config into a parse error on upgrade.
func TestRotationConfig_AcceptsBothShippedSpellings(t *testing.T) {
	t.Parallel()
	shorthand := writeConfig(t, `
listen: "127.0.0.1:0"
routes:
  - name: qwen
    prefix: /qwen/
    upstream: https://example.invalid
    auth: inject
    key_envs: [QWEN_A, QWEN_B]
    rotation: round_robin
    enabled: false
`)
	cfg, err := LoadConfig(shorthand)
	if err != nil {
		t.Fatalf("LoadConfig(scalar shorthand): %v", err)
	}
	if got := cfg.Routes[0].Rotation; got == nil || got.Policy != PolicyRoundRobin {
		t.Fatalf("rotation = %+v, want the scalar to mean {policy: round_robin}", got)
	}

	block := writeConfig(t, `
listen: "127.0.0.1:0"
routes:
  - name: mm
    prefix: /mm/
    upstream: https://example.invalid
    auth: inject
    key_files: ["/run/secrets/a.key", "/run/secrets/b.key"]
    rotation:
      policy: least_tokens
      max_retry_after: 15m
      budget:
        window: 1h
        tokens: 2000000
        soft_ratio: 0.5
        estimate_tokens: 1500
    enabled: false
`)
	cfg, err = LoadConfig(block)
	if err != nil {
		t.Fatalf("LoadConfig(mapping): %v", err)
	}
	rot := cfg.Routes[0].Rotation
	switch {
	case rot == nil:
		t.Fatal("rotation block was dropped")
	case rot.Policy != PolicyLeastTokens:
		t.Errorf("policy = %q, want %q", rot.Policy, PolicyLeastTokens)
	case rot.MaxRetryAfter != 15*time.Minute:
		t.Errorf("max_retry_after = %v, want 15m", rot.MaxRetryAfter)
	case rot.Budget.Tokens != 2_000_000 || rot.Budget.EstimateTokens != 1500:
		t.Errorf("budget = %+v, want tokens 2000000 and estimate 1500", rot.Budget)
	case rot.Budget.SoftRatio != 0.5:
		t.Errorf("soft_ratio = %v, want the configured 0.5 to survive the default", rot.Budget.SoftRatio)
	}
}

// TestRotationConfig_RejectsAnUnusableShape refuses to coerce a mis-indented
// block. Silently accepting it would configure no budget at all while looking
// configured.
func TestRotationConfig_RejectsAnUnusableShape(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
listen: "127.0.0.1:0"
routes:
  - name: mm
    prefix: /mm/
    upstream: https://example.invalid
    auth: inject
    key_envs: [A, B]
    rotation:
      - policy: round_robin
    enabled: false
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted a sequence for rotation, want an error naming the shape")
	}
	if !strings.Contains(err.Error(), "rotation must be a policy name or a mapping") {
		t.Errorf("error = %q, want it to name the two accepted shapes", err)
	}
	if !strings.Contains(err.Error(), "sequence") {
		t.Errorf("error = %q, want it to name the kind it actually got", err)
	}
}

// ---------------------------------------------------------------------------
// Pool resolution through the ONE secret seam
// ---------------------------------------------------------------------------

// TestResolveKeyPool_FrozenSlotOrder pins the property the whole key_index
// audit contract rests on: a given config yields the same slot for the same
// account on every node.
func TestResolveKeyPool_FrozenSlotOrder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.key")
	if err := os.WriteFile(fileA, []byte("  file-a-not-real\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	sp := newResolver(map[string]SecretProvider{
		SchemeEnv:  &envProvider{lookup: mapEnv(map[string]string{"E1": "env-1-not-real", "E2": "env-2-not-real"})},
		SchemeFile: newFileProvider(),
		SchemeOP:   &fakeProvider{fn: func(string) (string, error) { return "op-not-real", nil }},
	})
	r := Route{
		Name:     "mm",
		KeyEnvs:  []string{"E1", "E2"},
		KeyFiles: []string{fileA},
		KeyRefs:  []string{"op://v/i/f"},
	}
	got, err := resolveKeyPool(r, sp)
	if err != nil {
		t.Fatalf("resolveKeyPool: %v", err)
	}
	want := []string{"env-1-not-real", "env-2-not-real", "file-a-not-real", "op-not-real"}
	if len(got) != len(want) {
		t.Fatalf("pool size = %d, want %d (one key per declared slot, never a split source)", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slot %d = %q, want %q: order is key_envs, then key_files, then key_refs", i, got[i], want[i])
		}
	}
	if n := declaredKeyCount(r); n != len(want) {
		t.Errorf("declaredKeyCount = %d, want %d: the store is sized from this before anything resolves", n, len(want))
	}
}

// TestResolveKeyPool_UnresolvableSlotIsAStartupErrorNamingTheSlot: a pool that
// silently shrinks at boot is a capacity lie that only surfaces later as a
// quota alarm.
func TestResolveKeyPool_UnresolvableSlotIsAStartupErrorNamingTheSlot(t *testing.T) {
	t.Parallel()
	sp := envOnlyProvider(map[string]string{"E1": "env-1-not-real"})
	r := Route{Name: "mm", KeyEnvs: []string{"E1", "E2_MISSING"}}

	_, err := resolveKeyPool(r, sp)
	if err == nil {
		t.Fatal("resolveKeyPool accepted a pool with an unresolvable slot")
	}
	if !strings.Contains(err.Error(), "key_envs[1]") {
		t.Errorf("error = %q, want it to name the failing slot", err)
	}
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("error = %v, want it to wrap ErrSecretNotFound so callers can classify it", err)
	}
	if strings.Contains(err.Error(), "env-1-not-real") {
		t.Errorf("startup error leaked a resolved credential: %q", err)
	}
}

// TestResolveKeyPool_DuplicateCredentialNamesSlotsNotValues: two distinct
// SOURCES may still name one account, which only a value comparison can see —
// and the report must carry slot labels, never the shared credential.
func TestResolveKeyPool_DuplicateCredentialNamesSlotsNotValues(t *testing.T) {
	t.Parallel()
	sp := envOnlyProvider(map[string]string{"E1": "same-plan-not-real", "E2": "same-plan-not-real"})
	_, err := resolveKeyPool(Route{Name: "mm", KeyEnvs: []string{"E1", "E2"}}, sp)
	if err == nil {
		t.Fatal("resolveKeyPool accepted two slots backed by one account")
	}
	for _, want := range []string{"key_envs[1]", "key_envs[0]", "over-reports capacity"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "same-plan-not-real") {
		t.Errorf("duplicate error leaked the shared credential: %q", err)
	}
}
