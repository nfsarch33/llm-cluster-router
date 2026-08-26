package channel

import (
	"fmt"
	"time"
)

// BudgetAdvisory names one route whose per-key plan is denominated in TOKENS.
//
// Request budgets and token budgets are not two spellings of one feature, and
// the difference is not a rounding error.
//
// A REQUEST cap is EXACT under concurrency. requests+inFlight is invariant
// across a settlement and rises only on reservation, so the number of requests
// admitted in a window cannot exceed the cap however many callers arrive at
// once. Measured exact across a 12-combination pool-size x cap sweep at burst
// 60 — zero overspend, zero leaked in-flight, charged always equal to upstream
// hits (TestRotation_RequestCapIsExactAcrossThePoolSizeAndCapSweep).
//
// A TOKEN cap bounds the ESTIMATE, not the charge. Before a response exists,
// Budget.EstimateTokens is the only figure admission can project an unsettled
// lease by, so the cap admits ceil(Tokens/EstimateTokens) leases at once and
// every one of them then settles whatever the upstream actually reported.
// MEASURED: cap 1000 per key, estimate_tokens 100, a response reporting 5000
// real tokens — admission admitted 10 concurrent leases, each settled 5000, and
// 50000 was charged against a 1000-token cap. A 50x overshoot. The SEQUENTIAL
// worst case for the same numbers is 5000, so concurrency multiplies the
// overshoot one request already carries by exactly cap/estimate.
//
// Token budgets remain SUPPORTED and are not deprecated. They are ADVISORY:
// this type exists so that an operator who configures one is told the magnitude
// at startup rather than discovering it on a bill.
//
// FOLLOW-UP — THE KNOWN PATH TO EXACTNESS, DELIBERATELY NOT IMPLEMENTED:
// reserved-token accounting. A lease would RESERVE EstimateTokens against the
// cap at reservation time and RECONCILE that reservation at settlement — release
// the reserved figure, charge the real one — which makes the projection
// self-correcting and bounds a window's overshoot to what a single in-flight
// request exceeds its estimate by, instead of ceil(cap/estimate) of them. It is
// a change to the store's accounting model and to every caller that settles a
// lease, and the operator chose request budgets over it for now. This note is
// the record of that choice, not a plan of record: it is why the warning below
// says "advisory" rather than "broken", and it is what a future pass should
// implement if token-denominated plans ever have to be enforced exactly.
type BudgetAdvisory struct {
	// Route is the route name, as it appears in logs, metrics and the audit
	// trail.
	Route string
	// Enabled mirrors the route's feature flag. A disabled route is advised on
	// anyway: the cap behaves this way the moment the flag is flipped, and
	// finding that out at the flip is the failure this warning exists to
	// prevent.
	Enabled bool
	// Tokens is the configured hard per-key token cap.
	Tokens int64
	// EstimateTokens is what an unsettled lease is projected at, and what a
	// response reporting no usage is charged.
	EstimateTokens int64
	// Window is the accounting window the cap resets on.
	Window time.Duration
}

// ConcurrentLeases is how many leases admission control will grant against this
// cap at one instant: ceil(Tokens/EstimateTokens), which is exactly the
// arithmetic in admissibleLocked (it refuses once inFlight*EstimateTokens
// reaches Tokens). It is therefore also the factor by which a burst multiplies
// whatever one response overshoots its estimate by.
//
// A non-positive EstimateTokens yields 0, meaning the cap has no admission
// control at all and is checked only at settlement. Config.Validate rejects that
// pairing, so a loaded config cannot reach it; the guard is here because this
// type is exported and dividing by a zero estimate would panic.
func (a BudgetAdvisory) ConcurrentLeases() int64 {
	if a.EstimateTokens <= 0 {
		return 0
	}
	return (a.Tokens + a.EstimateTokens - 1) / a.EstimateTokens
}

// Warning is the operator-facing sentence, naming the overshoot ratio derived
// from THIS route's own numbers.
//
// It names the ratio rather than merely saying "may overshoot" because the two
// read completely differently to somebody deciding whether to care: cap 2000000
// against estimate_tokens 1500 is a plan that can be spent more than a thousand
// times over in one window, and no adjective conveys that.
func (a BudgetAdvisory) Warning() string {
	var tail string
	if !a.Enabled {
		tail = " This route is disabled today; the cap behaves exactly this way the moment it is enabled."
	}
	n := a.ConcurrentLeases()
	if n <= 0 {
		return fmt.Sprintf("WARNING: route %q budgets by TOKENS (rotation.budget.tokens=%d) with no rotation.budget.estimate_tokens, so the cap has NO admission control at all and is only ever checked at settlement. Token budgets are SUPPORTED but ADVISORY, never exact. Budget by requests instead: rotation.budget.requests is exact under concurrency (docs/helixchannel.md, \"Request budgets are exact; token budgets are advisory\").%s",
			a.Route, a.Tokens, tail)
	}
	return fmt.Sprintf("WARNING: route %q budgets by TOKENS (rotation.budget.tokens=%d, estimate_tokens=%d, window=%s), and a token cap bounds the ESTIMATE, not the charge. Admission projects every unsettled lease at estimate_tokens, so this cap admits up to %d requests at once (tokens/estimate_tokens = %d) and a concurrent burst charges the plan up to %dx whatever ONE response overshoots its estimate by. MEASURED at cap 1000 / estimate_tokens 100 with a real 5000-token response: 10 concurrent leases charged 50000 against a 1000-token cap, a 50x overshoot, where the sequential worst case for the same numbers was 5000. Token budgets are SUPPORTED but ADVISORY, never exact. Budget by requests instead: rotation.budget.requests is exact under concurrency (docs/helixchannel.md, \"Request budgets are exact; token budgets are advisory\").%s",
		a.Route, a.Tokens, a.EstimateTokens, a.Window, n, n, n, tail)
}

// TokenBudgetAdvisories reports every route that budgets by tokens, in
// configuration order.
//
// It reads the configuration and nothing else, so the startup banner, a
// config-linting caller and a test all derive the same numbers from the same
// place. An empty result is the shape every shipped example now has.
func (c *Config) TokenBudgetAdvisories() []BudgetAdvisory {
	var out []BudgetAdvisory
	for _, r := range c.Routes {
		if r.Rotation == nil || r.Rotation.Budget.Tokens <= 0 {
			continue
		}
		out = append(out, BudgetAdvisory{
			Route:          r.Name,
			Enabled:        r.Enabled,
			Tokens:         r.Rotation.Budget.Tokens,
			EstimateTokens: r.Rotation.Budget.EstimateTokens,
			Window:         r.Rotation.Budget.Window,
		})
	}
	return out
}
