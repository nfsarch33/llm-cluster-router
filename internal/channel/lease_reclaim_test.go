package channel

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// M3 — an unsettled Next() used to kill a key permanently.
//
// rollLocked resets requests, tokens and errors on a window boundary but never
// in-flight counts, and it must not: a live lease has to find its slot when it
// settles. admissibleLocked counts in-flight against the HARD request cap. Put
// together, a reservation whose caller never settled it held a slot that no
// amount of elapsed time could return — five leaks against a five-request cap
// left the key unreservable for the lifetime of the process, while /healthz
// went on reporting it selectable, available and not degraded.
//
// It is not reachable from the shipped gateway, which defers lease.Settle on
// every path. It is reachable from Next, which is the FIRST method of the
// exported RotationStore interface and is documented for direct use.
//
// The store now ages reservations and reclaims the stale ones. These tests pin
// both halves of that: that a leak clears, and that a request still running
// does not have its slot taken away.
// ---------------------------------------------------------------------------

// leakStore is the reproduction's fixture: one key, a one-hour window, a hard
// cap of five requests and nothing else in the way.
func leakStore(t *testing.T, opts ...StoreOption) (*Store, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	base := []StoreOption{
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		// SoftRatio 1 makes the hard cap the only cap, so what refuses a
		// reservation here is admission control and nothing else.
		WithBudget(Budget{Window: time.Hour, Requests: 5, SoftRatio: 1, EstimateTokens: 1}),
	}
	return NewStore(map[string]int{"r": 1}, append(base, opts...)...), clk
}

// TestStore_AnUnsettledLeaseDoesNotCostAKeyItsCapacityForever is the defect as
// REPRODUCED: five unsettled Next("r") against Requests:5 Window:1h, then 500
// hours on the clock. Before the fix that answered -1 with a snapshot reading
// requests=0 tokens=0 inflight=5 selectable=true drained=false — a key
// advertised as healthy and available that could never serve again.
func TestStore_AnUnsettledLeaseDoesNotCostAKeyItsCapacityForever(t *testing.T) {
	t.Parallel()
	st, clk := leakStore(t)

	for i := range 5 {
		if idx := st.Next("r"); idx != 0 {
			t.Fatalf("Next #%d = %d, want 0: the cap is five and nothing has been charged", i, idx)
		}
	}
	if idx := st.Next("r"); idx != -1 {
		t.Fatalf("Next #6 = %d, want -1: five in-flight leases fill a five-request cap", idx)
	}

	clk.Advance(500 * time.Hour)

	if idx := st.Next("r"); idx < 0 {
		t.Fatalf("Next after 500h of rollovers = %d, want a usable key: an unsettled reservation "+
			"outlived 500 window rollovers and permanently retired a key that nothing was wrong with", idx)
	}
	k := snapshotOf(t, st, "r", 0)
	if k.InFlight != 1 {
		t.Errorf("InFlight = %d, want 1 (only the reservation just taken); the five leaked slots were not reclaimed", k.InFlight)
	}
	if k.Reclaimed != 5 {
		t.Errorf("Reclaimed = %d, want 5: reclamation must be visible, or capacity evaporates with nothing to show for it", k.Reclaimed)
	}
	if k.Requests != 0 || k.Tokens != 0 {
		t.Errorf("Requests/Tokens = %d/%d after rollover, want 0/0", k.Requests, k.Tokens)
	}
	if !k.Selectable || k.Drained {
		t.Errorf("Selectable/Drained = %v/%v, want true/false", k.Selectable, k.Drained)
	}
}

// TestStore_ALeaseIsNotReclaimedWhileItsRequestCouldStillBeRunning is the
// counter-test, and the one that makes the timeout mean something. Reclaiming
// on any elapsed time at all — or on the window boundary alone — would take the
// slot out from under a request that is merely slow, and the cap it was
// counted against would then be overspendable by exactly the traffic that
// caused it.
func TestStore_ALeaseIsNotReclaimedWhileItsRequestCouldStillBeRunning(t *testing.T) {
	t.Parallel()
	const timeout = 30 * time.Minute
	st, clk := leakStore(t, WithLeaseTimeout(timeout))

	for range 5 {
		if idx := st.Next("r"); idx != 0 {
			t.Fatalf("Next = %d, want 0", idx)
		}
	}
	clk.Advance(timeout - time.Second)
	if idx := st.Next("r"); idx != -1 {
		t.Fatalf("Next one second before the lease timeout = %d, want -1: a request that has been "+
			"running for %v has not gone away, and its slot is still spoken for", idx, timeout-time.Second)
	}
	if k := snapshotOf(t, st, "r", 0); k.InFlight != 5 || k.Reclaimed != 0 {
		t.Errorf("InFlight/Reclaimed = %d/%d before the timeout, want 5/0", k.InFlight, k.Reclaimed)
	}

	clk.Advance(2 * time.Second)
	if idx := st.Next("r"); idx < 0 {
		t.Fatalf("Next one second after the lease timeout = %d, want a usable key", idx)
	}
	if k := snapshotOf(t, st, "r", 0); k.Reclaimed != 5 {
		t.Errorf("Reclaimed = %d after the timeout, want 5", k.Reclaimed)
	}
}

// TestStore_ASettledLeaseIsNeverReclaimed is the other side of the same coin: a
// reservation that WAS settled must leave no ghost behind for the timeout to
// find later. A reclaim counter that ticks in normal operation would be a false
// leak report, and the metric would be worthless the first time anyone looked.
func TestStore_ASettledLeaseIsNeverReclaimed(t *testing.T) {
	t.Parallel()
	st, clk := leakStore(t)

	for range 3 {
		lease, ok := st.Acquire("r")
		if !ok {
			t.Fatal("Acquire refused a lease on an untouched key")
		}
		lease.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 1})
	}
	clk.Advance(500 * time.Hour)

	k := snapshotOf(t, st, "r", 0)
	if k.Reclaimed != 0 {
		t.Errorf("Reclaimed = %d after three settled leases and 500h, want 0: "+
			"reclamation is a leak report and must not fire on ordinary traffic", k.Reclaimed)
	}
	if k.InFlight != 0 {
		t.Errorf("InFlight = %d, want 0", k.InFlight)
	}
}

// TestStore_ASettlementArrivingAfterItsSlotWasReclaimedDoesNotStealALiveOne
// pins the bookkeeping that makes reclamation safe.
//
// A settlement carries no lease identity, so once a slot has been reclaimed the
// store cannot tell a late settlement of THAT reservation from the settlement
// of a live one. Charging it against a live entry would under-count what is
// outstanding, and under-counting is precisely how admission control admits one
// request too many — the failure it exists to prevent. The rule is therefore to
// absorb the late settlement against the reclaimed slot.
func TestStore_ASettlementArrivingAfterItsSlotWasReclaimedDoesNotStealALiveOne(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 1},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithLeaseTimeout(30*time.Minute),
		// A cap high enough that admission never interferes: this test is
		// about the in-flight bookkeeping, not about refusal.
		WithBudget(Budget{Window: time.Hour, Requests: 100, SoftRatio: 1, EstimateTokens: 1}))

	leaked := st.Next("r") // never settled by its caller
	if leaked != 0 {
		t.Fatalf("Next = %d, want 0", leaked)
	}
	clk.Advance(31 * time.Minute) // past the lease timeout, inside the window
	if k := snapshotOf(t, st, "r", 0); k.InFlight != 0 || k.Reclaimed != 1 {
		t.Fatalf("InFlight/Reclaimed = %d/%d after the timeout, want 0/1", k.InFlight, k.Reclaimed)
	}

	live, ok := st.Acquire("r")
	if !ok {
		t.Fatal("Acquire refused a lease on a key with a reclaimed slot")
	}

	// The leaked reservation's request finally settles, long after its slot was
	// taken back.
	st.RecordUsage("r", leaked, 7)

	k := snapshotOf(t, st, "r", 0)
	if k.InFlight != 1 {
		t.Errorf("InFlight = %d after a late settlement, want 1: the late settlement released the LIVE "+
			"reservation's slot, so the store now under-counts what is outstanding and the hard cap "+
			"can be overspent by one", k.InFlight)
	}
	if k.Requests != 1 || k.Tokens != 7 {
		t.Errorf("Requests/Tokens = %d/%d, want 1/7: a late settlement still describes a real request "+
			"and must still be charged", k.Requests, k.Tokens)
	}

	live.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 3})
	if k := snapshotOf(t, st, "r", 0); k.InFlight != 0 {
		t.Errorf("InFlight = %d once the live lease settled, want 0", k.InFlight)
	}
}

// TestStore_ReclaimedIsALifetimeCountAndSurvivesARollover pins the one counter
// in KeyState that a window boundary must NOT reset. Every other figure there
// is per-window; this one is evidence of a caller bug, and evidence that clears
// itself every hour is evidence nobody ever sees.
func TestStore_ReclaimedIsALifetimeCountAndSurvivesARollover(t *testing.T) {
	t.Parallel()
	st, clk := leakStore(t)

	st.Next("r")
	clk.Advance(31 * time.Minute)
	if k := snapshotOf(t, st, "r", 0); k.Reclaimed != 1 {
		t.Fatalf("Reclaimed = %d, want 1", k.Reclaimed)
	}
	clk.Advance(10 * time.Hour) // several window rollovers
	if k := snapshotOf(t, st, "r", 0); k.Reclaimed != 1 {
		t.Errorf("Reclaimed = %d after ten hours of rollovers, want 1: a rollover cleared the only "+
			"record that a caller is leaking leases", k.Reclaimed)
	}
}

// TestNewStore_LeaseTimeoutDefaultsRatherThanDisabling pins that there is no
// way to switch reclamation off. A zero value meaning "never reclaim" would
// reinstate the defect through the option that was added to fix it, and it is
// the value a caller building a Store from a partially filled config gets.
func TestNewStore_LeaseTimeoutDefaultsRatherThanDisabling(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts []StoreOption
		want time.Duration
	}{
		{"unset", nil, DefaultLeaseTimeout},
		{"zero", []StoreOption{WithLeaseTimeout(0)}, DefaultLeaseTimeout},
		{"negative", []StoreOption{WithLeaseTimeout(-time.Hour)}, DefaultLeaseTimeout},
		{"explicit", []StoreOption{WithLeaseTimeout(90 * time.Second)}, 90 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := NewStore(map[string]int{"r": 1}, tc.opts...)
			if got := st.leaseTimeout; got != tc.want {
				t.Errorf("leaseTimeout = %v, want %v", got, tc.want)
			}
		})
	}
}
