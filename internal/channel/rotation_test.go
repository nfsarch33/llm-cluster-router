package channel

import (
	"strings"
	"testing"
)

// states builds a selectable KeyState slice in ascending Index order, which
// is the only shape a policy is ever handed.
func states(n int, mutate func(i int, k *KeyState)) []KeyState {
	out := make([]KeyState, n)
	for i := range out {
		out[i] = KeyState{Index: i, Selectable: true}
		if mutate != nil {
			mutate(i, &out[i])
		}
	}
	return out
}

func selectN(p RotationPolicy, s []KeyState, n int) []int {
	got := make([]int, 0, n)
	for i := 0; i < n; i++ {
		got = append(got, p.Select(s))
	}
	return got
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRoundRobinPolicy_ReproducesKeypoolCursor pins the migration contract: a
// route moved from the single-key path onto rotation must use the same key on
// its first request as it does today, which means the first Select returns
// position 0 exactly as internal/keypool's idx.Add(1)-1 does.
func TestRoundRobinPolicy_ReproducesKeypoolCursor(t *testing.T) {
	t.Parallel()
	p := NewRoundRobinPolicy()
	got := selectN(p, states(3, nil), 5)
	want := []int{0, 1, 2, 0, 1}
	if !equalInts(got, want) {
		t.Fatalf("round robin sequence = %v, want %v (first call must be position 0)", got, want)
	}
}

func TestLeastUsedPolicy_PicksFewestCompletedRequests(t *testing.T) {
	t.Parallel()
	reqs := []int64{9, 2, 7}
	s := states(3, func(i int, k *KeyState) { k.Requests = reqs[i] })
	if got := NewLeastUsedPolicy().Select(s); got != 1 {
		t.Fatalf("Select = %d, want 1 (Requests %v)", got, reqs)
	}
}

// TestLeastUsedPolicy_CountsInFlightLeases is the anti-stampede property: a
// burst that has not settled yet must already steer selection away from the
// busy key, or N simultaneous requests all see zero usage and pile onto one.
func TestLeastUsedPolicy_CountsInFlightLeases(t *testing.T) {
	t.Parallel()
	inflight := []int64{5, 0, 0}
	s := states(3, func(i int, k *KeyState) { k.InFlight = inflight[i] })
	p := NewLeastUsedPolicy()
	for i := 0; i < 6; i++ {
		got := p.Select(s)
		if got == 0 {
			t.Fatalf("Select = 0 on call %d, want 1 or 2: key 0 has %d unsettled leases", i, inflight[0])
		}
		if got != 1 && got != 2 {
			t.Fatalf("Select = %d on call %d, want 1 or 2", got, i)
		}
	}
}

func TestLeastTokensPolicy_PicksFewestChargedTokens(t *testing.T) {
	t.Parallel()
	toks := []int64{5000, 120, 900}
	s := states(3, func(i int, k *KeyState) { k.Tokens = toks[i] })
	if got := NewLeastTokensPolicy().Select(s); got != 1 {
		t.Fatalf("Select = %d, want 1 (Tokens %v)", got, toks)
	}
}

// TestLeastTokensPolicy_DegradesWhenAnySampleIsEstimated proves the skew
// guard: a key whose token total is untrustworthy must not win on a
// fabricated low total.
func TestLeastTokensPolicy_DegradesWhenAnySampleIsEstimated(t *testing.T) {
	t.Parallel()
	toks := []int64{0, 900}
	est := []bool{true, false}
	reqs := []int64{40, 1}
	s := states(2, func(i int, k *KeyState) {
		k.Tokens, k.Estimated, k.Requests = toks[i], est[i], reqs[i]
	})
	if got := NewLeastTokensPolicy().Select(s); got != 1 {
		t.Fatalf("Select = %d, want 1: key 0's 0 tokens is an estimate, so selection must fall back to request ordering", got)
	}
}

// TestPolicy_TieBreakIsRoundRobinAndDeterministic keeps selection assertable:
// an arbitrary tie-break would make every downstream test flaky.
func TestPolicy_TieBreakIsRoundRobinAndDeterministic(t *testing.T) {
	t.Parallel()
	s := states(3, func(_ int, k *KeyState) { k.Requests = 4 })
	got := selectN(NewLeastUsedPolicy(), s, 4)
	want := []int{0, 1, 2, 0}
	if !equalInts(got, want) {
		t.Fatalf("tie-break sequence = %v, want %v", got, want)
	}
}

func TestNewPolicy_NamesAndRejection(t *testing.T) {
	t.Parallel()
	for _, name := range []PolicyName{"", PolicyRoundRobin, PolicyLeastUsed, PolicyLeastTokens} {
		p, err := NewPolicy(name)
		if err != nil {
			t.Fatalf("NewPolicy(%q) = error %v, want a policy", name, err)
		}
		if p == nil {
			t.Fatalf("NewPolicy(%q) returned a nil policy", name)
		}
	}
	_, err := NewPolicy("random")
	if err == nil {
		t.Fatal("NewPolicy(\"random\") = nil error, want a rejection naming the accepted values")
	}
	for _, want := range []string{"round_robin", "least_used", "least_tokens", "random"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("NewPolicy error = %q, want it to name %q", err, want)
		}
	}
}

// TestPolicy_EmptyCandidateSetDeclines: the store filters retired keys out, so
// every policy must survive being handed nothing rather than index into it.
func TestPolicy_EmptyCandidateSetDeclines(t *testing.T) {
	t.Parallel()
	for name, p := range map[string]RotationPolicy{
		"round_robin":  NewRoundRobinPolicy(),
		"least_used":   NewLeastUsedPolicy(),
		"least_tokens": NewLeastTokensPolicy(),
	} {
		if got := p.Select(nil); got != -1 {
			t.Errorf("%s.Select(nil) = %d, want -1 (decline)", name, got)
		}
	}
}
