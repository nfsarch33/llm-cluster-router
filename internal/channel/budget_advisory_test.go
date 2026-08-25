package channel

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// budgetedRoute is a pooled inject route carrying exactly the rotation block
// under test. Keys are named env vars and are never resolved: nothing here
// builds a Server, so no test in this file needs t.Setenv and every one of them
// can run in parallel.
func budgetedRoute(name string, enabled bool, b *Budget) Route {
	r := Route{
		Name: name, Prefix: "/" + name + "/", Upstream: "https://api.example.invalid",
		Auth: AuthInject, KeyEnvs: []string{name + "_K1", name + "_K2"}, Enabled: enabled,
	}
	if b != nil {
		r.Rotation = &RotationConfig{Budget: *b}
	}
	return r
}

// TestTokenBudgetAdvisories_NamesEveryTokenBudgetAndNothingElse is requirement 5
// in one assertion: a route configured with a token budget is advised on, and a
// route configured with a request budget is not.
//
// The mixed route is the case that decides the rule rather than illustrating it.
// A route carrying BOTH caps still has a token cap, and a token cap is exactly
// as inexact when a request cap happens to sit beside it, so "has a request
// budget" must not be allowed to suppress the warning.
func TestTokenBudgetAdvisories_NamesEveryTokenBudgetAndNothingElse(t *testing.T) {
	t.Parallel()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{
		budgetedRoute("tokens-only", true, &Budget{Window: time.Hour, Tokens: 1000, EstimateTokens: 100}),
		budgetedRoute("requests-only", true, &Budget{Window: time.Hour, Requests: 5000}),
		budgetedRoute("both", true, &Budget{Window: time.Hour, Tokens: 400, Requests: 10, EstimateTokens: 200}),
		budgetedRoute("no-budget", true, &Budget{}),
		budgetedRoute("no-rotation", true, nil),
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	got := cfg.TokenBudgetAdvisories()
	want := []string{"tokens-only", "both"}
	if len(got) != len(want) {
		t.Fatalf("TokenBudgetAdvisories() named %d routes (%v), want %v", len(got), advisoryNames(got), want)
	}
	for i, name := range want {
		if got[i].Route != name {
			t.Errorf("advisory[%d] = %q, want %q (configuration order)", i, got[i].Route, name)
		}
	}
	for _, a := range got {
		if strings.Contains(a.Route, "requests") {
			t.Errorf("route %q budgets by requests and must not be warned about", a.Route)
		}
	}
}

func advisoryNames(as []BudgetAdvisory) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.Route)
	}
	return out
}

// TestTokenBudgetAdvisories_CarryTheRoutesOwnNumbers pins the fields the warning
// is derived from. A warning that named the wrong route's cap would be worse
// than none: it would send an operator to tune a number that is not the one
// costing them money.
func TestTokenBudgetAdvisories_CarryTheRoutesOwnNumbers(t *testing.T) {
	t.Parallel()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{
		budgetedRoute("small", true, &Budget{Window: time.Hour, Tokens: 1000, EstimateTokens: 100}),
		budgetedRoute("large", false, &Budget{Window: 24 * time.Hour, Tokens: 2000000, EstimateTokens: 1500}),
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	got := cfg.TokenBudgetAdvisories()
	if len(got) != 2 {
		t.Fatalf("TokenBudgetAdvisories() = %v, want two advisories", advisoryNames(got))
	}
	want := []BudgetAdvisory{
		{Route: "small", Enabled: true, Tokens: 1000, EstimateTokens: 100, Window: time.Hour},
		{Route: "large", Enabled: false, Tokens: 2000000, EstimateTokens: 1500, Window: 24 * time.Hour},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("advisory[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestBudgetAdvisory_ConcurrentLeasesIsWhatAdmissionActuallyGrants is the
// assertion that keeps the warning honest.
//
// The ratio in the sentence an operator reads is derived arithmetic; what it
// claims about is the store. Deriving both here and comparing them means the
// warning cannot drift away from admissibleLocked without a test failing —
// which is the whole difference between a documented number and a measured one.
func TestBudgetAdvisory_ConcurrentLeasesIsWhatAdmissionActuallyGrants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tokens, estimate, want int64
	}{
		{tokens: 1000, estimate: 100, want: 10}, // the measured shape: a 10x multiplier
		{tokens: 1000, estimate: 500, want: 2},
		{tokens: 1000, estimate: 300, want: 4}, // not divisible: admission grants the ceiling
		{tokens: 1000, estimate: 1000, want: 1},
		{tokens: 1000, estimate: 4000, want: 1}, // an estimate over the cap still admits one
		{tokens: 15000, estimate: 1500, want: 10},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("tokens%d_estimate%d", tc.tokens, tc.estimate), func(t *testing.T) {
			t.Parallel()
			a := BudgetAdvisory{Route: "r", Tokens: tc.tokens, EstimateTokens: tc.estimate}
			if got := a.ConcurrentLeases(); got != tc.want {
				t.Fatalf("ConcurrentLeases() = %d, want %d", got, tc.want)
			}

			st := NewStore(map[string]int{"r": 1},
				WithClock(newFakeClock().Now), WithRetireObserver(newCountingObserver()),
				// SoftRatio 1 makes the hard cap the only cap, so what is counted
				// here is admission control and nothing else.
				WithBudget(Budget{Window: time.Hour, Tokens: tc.tokens, EstimateTokens: tc.estimate, SoftRatio: 1}))
			granted := int64(0)
			for range tc.want + 5 {
				if _, ok := st.Acquire("r"); ok {
					granted++
				}
			}
			if granted != tc.want {
				t.Errorf("admission granted %d concurrent leases against tokens=%d estimate_tokens=%d, but the warning would claim %d: "+
					"the advertised overshoot ratio must be the one the store enforces", granted, tc.tokens, tc.estimate, tc.want)
			}
		})
	}
}

// TestBudgetAdvisory_WarningNamesTheRatioAndSaysItIsAdvisory reads the sentence
// the operator actually sees.
func TestBudgetAdvisory_WarningNamesTheRatioAndSaysItIsAdvisory(t *testing.T) {
	t.Parallel()
	a := BudgetAdvisory{Route: "minimax-pool", Enabled: true, Tokens: 1000, EstimateTokens: 100, Window: time.Hour}
	got := a.Warning()
	for _, want := range []string{
		`"minimax-pool"`,
		"tokens/estimate_tokens = 10", // the ratio for THIS route's numbers
		"up to 10 requests at once",
		"10x",
		"rotation.budget.tokens=1000",
		"estimate_tokens=100",
		"ADVISORY",
		"rotation.budget.requests is exact under concurrency",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning does not contain %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "disabled") {
		t.Errorf("an enabled route must not be described as disabled:\n%s", got)
	}
}

// TestBudgetAdvisory_WarningScalesTheRatioWithTheRoute proves the number is
// computed rather than pasted. The shipped example's old cap and estimate —
// 2000000 against 1500 — is a plan spendable 1334 times over in one window, and
// an operator who is told "10" for it has been told a comforting fiction.
func TestBudgetAdvisory_WarningScalesTheRatioWithTheRoute(t *testing.T) {
	t.Parallel()
	a := BudgetAdvisory{Route: "big", Enabled: false, Tokens: 2000000, EstimateTokens: 1500, Window: time.Hour}
	got := a.Warning()
	if !strings.Contains(got, "tokens/estimate_tokens = 1334") {
		t.Errorf("warning does not name the 1334x ratio for tokens=2000000 estimate_tokens=1500:\n%s", got)
	}
	if strings.Contains(got, "tokens/estimate_tokens = 10)") {
		t.Errorf("warning appears to carry a hard-coded ratio:\n%s", got)
	}
	if !strings.Contains(got, "disabled today") {
		t.Errorf("a disabled route's warning must say the cap applies the moment it is enabled:\n%s", got)
	}
}

// TestBudgetAdvisory_AMissingEstimateIsReportedAsNoAdmissionControlAtAll covers
// the guard that keeps an exported type from dividing by zero. Config.Validate
// refuses tokens without estimate_tokens, so this shape cannot be loaded from
// disk — but BudgetAdvisory is exported, and "panics on a zero field" is not an
// acceptable contract for a type whose whole job is to warn.
func TestBudgetAdvisory_AMissingEstimateIsReportedAsNoAdmissionControlAtAll(t *testing.T) {
	t.Parallel()
	a := BudgetAdvisory{Route: "no-estimate", Enabled: true, Tokens: 1000, Window: time.Hour}
	if got := a.ConcurrentLeases(); got != 0 {
		t.Errorf("ConcurrentLeases() = %d, want 0 when estimate_tokens is unset", got)
	}
	got := a.Warning()
	if !strings.Contains(got, "NO admission control") {
		t.Errorf("warning does not say the cap is unenforced before settlement:\n%s", got)
	}
	if !strings.Contains(got, "ADVISORY") {
		t.Errorf("warning does not say token budgets are advisory:\n%s", got)
	}
}

// TestExampleConfig_BudgetsByRequestsNotTokens is requirement 1 as a gate.
//
// deploy/helixchannel/gateway.example.yml is the ONLY example config, and it is
// what a node is deployed from. A shipped example that budgets by tokens is not
// a documentation problem — it is the default an operator inherits without ever
// making the decision.
func TestExampleConfig_BudgetsByRequestsNotTokens(t *testing.T) {
	t.Parallel()
	const path = "../../deploy/helixchannel/gateway.example.yml"
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", path, err)
	}
	if advisories := cfg.TokenBudgetAdvisories(); len(advisories) != 0 {
		t.Errorf("%s budgets by tokens on %v; every shipped config must budget by requests", path, advisoryNames(advisories))
	}
	budgeted := 0
	for _, r := range cfg.Routes {
		if r.Rotation != nil && r.Rotation.Budget.Requests > 0 {
			budgeted++
		}
	}
	if budgeted == 0 {
		t.Errorf("%s ships no route with rotation.budget.requests; the example must SHOW the budget an operator should copy, not merely omit the one they should not", path)
	}
}
