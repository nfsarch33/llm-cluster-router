package channel

import (
	"fmt"
	"sync/atomic"
	"time"
)

// KeyState is a snapshot of one key's accounting for the current window.
//
// The store hands policies a freshly allocated slice each selection, so a
// policy may read it freely; it must not mutate it.
type KeyState struct {
	// Index is the key's position in the route's key slice. It is what the
	// store maps a policy's answer back onto; policies never return it.
	Index int
	// Requests is the number of settled, completed requests this window.
	Requests int64
	// Tokens is the tokens charged this window, including estimated charges.
	Tokens int64
	// InFlight is the number of leases taken but not yet settled. Counting it
	// is what stops a concurrent burst from stampeding one key: every lease is
	// visible to the next selection before any of them completes.
	InFlight int64
	// Errors is the number of leases settled as failures this window.
	Errors int64
	// Estimated is true when at least one sample this window carried no
	// upstream token count and was charged Budget.EstimateTokens instead.
	// Cross-key token comparisons are untrustworthy when it is set.
	Estimated bool

	// Selectable reports whether the store would consider this key right now.
	// Policies only ever receive selectable keys, so it is always true there;
	// it exists for Snapshot, which reports every key.
	Selectable bool
	// SoftRetired is set when the soft cap took the key out of rotation for
	// the remainder of the window — a planned rotation, not an error.
	SoftRetired bool
	// Drained is set when the hard cap was reached. It is reported separately
	// from SoftRetired because "spent its whole plan" and "parked early on
	// purpose" are different operational facts, even though both keys are
	// equally unselectable.
	Drained bool
	// RetiredUntil is a non-zero deadline when the key was explicitly retired
	// (quota or error). It is independent of the accounting window, so an
	// hour-long provider cooldown outlives a five-minute window.
	RetiredUntil time.Time
	// Reason explains why the key is currently unselectable. It is empty for a
	// selectable key.
	Reason RetireReason
}

// RotationPolicy chooses which of the eligible keys to use next.
//
// Contract:
//   - states contains ONLY currently selectable keys, in ascending Index
//     order. Retired and drained keys are filtered out by the store, so a
//     policy never has to know those states exist (SRP).
//   - Select returns a POSITION IN states (0 <= n < len(states)), NEVER a
//     KeyState.Index. Returning a position makes an out-of-range answer the
//     only possible mistake, and the store detects and contains it.
//   - Select returns -1 to decline; the store falls back to round-robin.
//   - Select is invoked with the store's lock held. An implementation MUST
//     NOT call back into the store, and MUST NOT block.
//   - Select MUST be deterministic for a given sequence of inputs, so a test
//     can assert an exact selection order.
type RotationPolicy interface {
	Select(states []KeyState) int
}

// PolicyName is the YAML spelling of a rotation policy.
type PolicyName string

const (
	// PolicyRoundRobin is the default and preserves today's ordering.
	PolicyRoundRobin PolicyName = "round_robin"
	// PolicyLeastUsed selects the fewest completed requests this window.
	PolicyLeastUsed PolicyName = "least_used"
	// PolicyLeastTokens selects the fewest tokens charged this window.
	PolicyLeastTokens PolicyName = "least_tokens"
)

// NewPolicy builds the named policy. The empty name yields PolicyRoundRobin,
// which is what keeps an un-annotated route on today's behaviour.
func NewPolicy(n PolicyName) (RotationPolicy, error) {
	switch n {
	case "", PolicyRoundRobin:
		return NewRoundRobinPolicy(), nil
	case PolicyLeastUsed:
		return NewLeastUsedPolicy(), nil
	case PolicyLeastTokens:
		return NewLeastTokensPolicy(), nil
	default:
		return nil, fmt.Errorf("rotation policy must be %q, %q or %q (got %q)",
			PolicyRoundRobin, PolicyLeastUsed, PolicyLeastTokens, n)
	}
}

// roundRobinPolicy hands out keys in index order.
//
// It reproduces internal/keypool's cursor semantics exactly — the first
// Select after construction returns position 0 (keypool: idx.Add(1)-1) — so a
// route migrated off the single-key path uses the same key on its first
// request as it does today.
type roundRobinPolicy struct{ cursor atomic.Uint64 }

// NewRoundRobinPolicy returns the default policy.
func NewRoundRobinPolicy() RotationPolicy { return &roundRobinPolicy{} }

func (p *roundRobinPolicy) Select(states []KeyState) int {
	if len(states) == 0 {
		return -1
	}
	return int((p.cursor.Add(1) - 1) % uint64(len(states)))
}

// leastUsedPolicy selects the key with the fewest Requests+InFlight.
type leastUsedPolicy struct{ cursor atomic.Uint64 }

// NewLeastUsedPolicy selects the key with the fewest settled requests plus
// outstanding leases this window, breaking ties round-robin.
func NewLeastUsedPolicy() RotationPolicy { return &leastUsedPolicy{} }

func (p *leastUsedPolicy) Select(states []KeyState) int {
	return pickMin(&p.cursor, states, byLoad)
}

// leastTokensPolicy selects the key charged the fewest tokens.
type leastTokensPolicy struct{ cursor atomic.Uint64 }

// NewLeastTokensPolicy selects the key charged the fewest tokens this window,
// breaking ties round-robin.
//
// When ANY candidate carries an estimated sample the token totals are not
// comparable across keys, so this policy falls back to request ordering for
// that selection. Silently comparing a real total against an estimate is the
// skew this design exists to prevent.
func NewLeastTokensPolicy() RotationPolicy { return &leastTokensPolicy{} }

func (p *leastTokensPolicy) Select(states []KeyState) int {
	for _, s := range states {
		if s.Estimated {
			return pickMin(&p.cursor, states, byLoad)
		}
	}
	return pickMin(&p.cursor, states, func(k KeyState) int64 { return k.Tokens })
}

// byLoad scores a key by work already accepted, settled or not. Counting
// unsettled leases is what stops a simultaneous burst — which sees no settled
// usage at all — from stampeding one key.
func byLoad(k KeyState) int64 { return k.Requests + k.InFlight }

// pickMin returns the position of the minimum-scoring state, breaking ties by
// advancing a shared cursor across the tied candidates so the choice is
// round-robin, deterministic and assertable.
func pickMin(cursor *atomic.Uint64, states []KeyState, score func(KeyState) int64) int {
	if len(states) == 0 {
		return -1
	}
	best := score(states[0])
	tied := []int{0}
	for i := 1; i < len(states); i++ {
		switch v := score(states[i]); {
		case v < best:
			best, tied = v, []int{i}
		case v == best:
			tied = append(tied, i)
		}
	}
	return tied[int((cursor.Add(1)-1)%uint64(len(tied)))]
}
