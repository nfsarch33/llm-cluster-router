package channel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test doubles for burst arithmetic
// ---------------------------------------------------------------------------

// releaseGate holds every arriving upstream request until the whole burst has
// come to rest, so a concurrency defect is reproduced deterministically instead
// of being raced for.
//
// "At rest" is not "n arrivals": under working admission control most of a
// burst never reaches the upstream at all. It is n NOTICES, where every request
// notices exactly once — on arrival at the upstream, or on being refused by the
// gateway without a round trip. That predicate is reached in both the broken
// and the fixed build, which is what lets one assertion distinguish them
// without a timeout and without a sleep.
type releaseGate struct {
	want    int64
	seen    atomic.Int64
	once    sync.Once
	release chan struct{}
}

func newReleaseGate(want int) *releaseGate {
	return &releaseGate{want: int64(want), release: make(chan struct{})}
}

// note records one request coming to rest. It must be called exactly once per
// request in the burst.
func (g *releaseGate) note() {
	if g.seen.Add(1) >= g.want {
		g.once.Do(func() { close(g.release) })
	}
}

// wait blocks an upstream handler until the whole burst has come to rest.
func (g *releaseGate) wait() { <-g.release }

// steppingClock advances a fixed step on EVERY read.
//
// It exists to land a window rollover between two critical sections: any code
// that reads the clock twice and assumes the two readings describe the same
// window is wrong, and this clock makes that wrongness deterministic rather
// than a once-a-week production race.
type steppingClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func newSteppingClock(step time.Duration) *steppingClock {
	return &steppingClock{t: time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC), step: step}
}

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.step)
	return c.t
}

// retiredUntilOf reads a key's retirement deadline WITHOUT going through
// Snapshot, because Snapshot rolls the window first and a rollover would clear
// the very field under test. Same package, so the white-box read is available;
// the alternative is a test that cannot see the state it is about.
func retiredUntilOf(s *Store, route string, idx int) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, ok := s.routes[route]
	if !ok || idx < 0 || idx >= len(rs.keys) {
		return time.Time{}
	}
	return rs.keys[idx].retiredUntil
}

// chargedTokens totals what a route's store actually charged this window.
func chargedTokens(s *Store, route string) (tokens, requests, errors int64) {
	for _, k := range s.Snapshot(route) {
		tokens += k.Tokens
		requests += k.Requests
		errors += k.Errors
	}
	return tokens, requests, errors
}

// ---------------------------------------------------------------------------
// R1 — the hard cap is admission-controlled, not merely settled
// ---------------------------------------------------------------------------

// TestStore_HardRequestCapIsEnforcedAtReservationNotOnlyAtSettlement is the
// unit-level statement of the defect: selection consulted only "is this key
// retired", never "would this reservation exceed the plan". Sixty reservations
// against a five-request cap, none of them settled, is exactly the shape a
// concurrent burst presents.
func TestStore_HardRequestCapIsEnforcedAtReservationNotOnlyAtSettlement(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 1},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		// SoftRatio 1 makes the hard cap the only cap, so the arithmetic under
		// test is "five requests", not the default 80% rounding.
		WithBudget(Budget{Window: time.Hour, Requests: 5, SoftRatio: 1, EstimateTokens: 1}))

	granted := 0
	for range 60 {
		if _, ok := st.Acquire("r"); ok {
			granted++
		}
	}
	if granted != 5 {
		t.Errorf("Acquire granted %d of 60 leases against a 5-request cap, want 5: "+
			"a cap evaluated only at settlement is overspendable by the concurrency factor", granted)
	}
	if k := snapshotOf(t, st, "r", 0); k.InFlight != 5 {
		t.Errorf("InFlight = %d, want 5: every granted lease must be visible to the next reservation", k.InFlight)
	}
}

// TestStore_HardTokenCapCountsTheEstimateOfEveryInFlightLease: a token cap can
// only be admission-controlled against what an unsettled lease is GOING to
// cost, and Budget.EstimateTokens is the only figure available before the
// response exists. Two 500-token estimates fill a 1000-token plan.
func TestStore_HardTokenCapCountsTheEstimateOfEveryInFlightLease(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 1},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: time.Hour, Tokens: 1000, EstimateTokens: 500, SoftRatio: 1}))

	granted := 0
	for range 10 {
		if _, ok := st.Acquire("r"); ok {
			granted++
		}
	}
	if granted != 2 {
		t.Errorf("Acquire granted %d concurrent leases against 1000 tokens at a 500-token estimate, want 2", granted)
	}
}

// TestStore_AdmissionControlLeavesSequentialTrafficUnchanged pins the blast
// radius. Admission enforces the HARD cap only, so the soft cap — which trips
// first on sequential traffic — still decides when a key leaves rotation, and
// no existing budget behaviour moves.
func TestStore_AdmissionControlLeavesSequentialTrafficUnchanged(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 1},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: time.Hour, Requests: 10, SoftRatio: 0.8, EstimateTokens: 1}))

	served := 0
	for range 30 {
		l, ok := st.Acquire("r")
		if !ok {
			break
		}
		served++
		l.Settle(UsageSample{Outcome: OutcomeCompleted, Tokens: 1})
	}
	if served != 8 {
		t.Errorf("sequential traffic served %d requests, want 8 (the 80%% soft cap of 10): "+
			"admission control must not move the sequential boundary", served)
	}
}

// TestRotation_ConcurrentBurstCannotOverspendTheHardCap is the finding as
// MEASURED: cap 5, burst 60. Before the fix the upstream saw all 60 and the
// gateway answered zero 503s — a 12x overspend of the whole per-window plan.
//
// The test MUST be concurrent. The same route driven sequentially is exact,
// which is precisely why the defect survived a suite full of sequential budget
// tests.
func TestRotation_ConcurrentBurstCannotOverspendTheHardCap(t *testing.T) {
	t.Parallel()
	const (
		burst  = 60
		reqCap = 5
	)
	gate := newReleaseGate(burst)
	// A probe, not a bare httptest server: "the upstream saw exactly N" is
	// only true of an upstream no other process can reach, and the gate below
	// makes it worse than a miscount -- a note raised by a stray request
	// releases the burst before it has come to rest. See upstreamProbe.
	upstream := newUpstreamProbe(t, func(w http.ResponseWriter, _ *http.Request) {
		gate.note()
		gate.wait()
		_, _ = io.WriteString(w, `{"usage":{"total_tokens":1}}`)
	})

	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real"},
		&RotationConfig{Budget: Budget{
			Window: time.Hour, Requests: reqCap, SoftRatio: 1, EstimateTokens: 1,
		}}), nil, nil)
	handler := srv.Handler()

	var served, refused atomic.Int64
	var wg sync.WaitGroup
	wg.Add(burst)
	for range burst {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, upstream.stamp(httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil)))
			switch rec.Code {
			case http.StatusOK:
				served.Add(1)
			case http.StatusServiceUnavailable:
				refused.Add(1)
				gate.note() // refused without a round trip: this request is at rest
			default:
				refused.Add(1)
				gate.note()
				t.Errorf("status = %d, want 200 or 503", rec.Code)
			}
		}()
	}
	wg.Wait()

	if got := upstream.hitCount(); got != reqCap {
		t.Errorf("upstream saw %d of %d burst requests against a %d-request cap, want %d",
			got, burst, reqCap, reqCap)
	}
	if served.Load() != reqCap || refused.Load() != burst-reqCap {
		t.Errorf("served=%d refused=%d, want %d served and %d answered 503",
			served.Load(), refused.Load(), reqCap, burst-reqCap)
	}
	tokens, requests, _ := chargedTokens(storeFor(t, srv, "mm"), "mm")
	if requests != reqCap || tokens != reqCap {
		t.Errorf("charged requests=%d tokens=%d, want %d and %d: the window plan must not be exceeded",
			requests, tokens, reqCap, reqCap)
	}
}

// ---------------------------------------------------------------------------
// R2 — an upstream failure is not this gateway's spend
// ---------------------------------------------------------------------------

// TestRotation_UpstreamServerErrorIsNeverChargedAsSpend is the finding as
// MEASURED: four upstream 500s, zero real tokens, drained both keys' 1000-token
// plans through the 500-token streaming estimate, after which the route
// answered 503 with Retry-After 3600 for a six-hour window — a self-inflicted
// multi-hour quota outage, labelled reason=cap, caused by a transient outage.
func TestRotation_UpstreamServerErrorIsNeverChargedAsSpend(t *testing.T) {
	t.Parallel()
	// A probe, not a bare httptest server. This count was MEASURED wrong on a
	// STRICTLY SEQUENTIAL test: five requests, eight arrivals, because three
	// came from another test binary that had been handed this port. See
	// upstreamProbe.
	upstream := newUpstreamProbe(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"upstream exploded"}`)
	})

	obs := newCountingObserver()
	var audit bytes.Buffer
	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{
			Window: 6 * time.Hour, Tokens: 1000, EstimateTokens: 500, SoftRatio: 1,
		}}), nil, &audit, WithRotationRetireObserver(obs))

	for i := range 4 {
		rec := serve(srv, http.MethodGet, "/mm/v1/chat", upstream.header(nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("request %d status = %d, want the upstream 500 relayed", i, rec.Code)
		}
	}

	tokens, requests, errs := chargedTokens(storeFor(t, srv, "mm"), "mm")
	if tokens != 0 {
		t.Errorf("charged %d tokens for four upstream 500s that produced none, want 0: "+
			"a transient upstream outage must not spend the plan", tokens)
	}
	if requests != 0 {
		t.Errorf("charged %d requests for four upstream 500s, want 0", requests)
	}
	if errs != 4 {
		t.Errorf("errors = %d, want 4: a 5xx is a failure, and OutcomeFailed is how one is recorded", errs)
	}
	if n := obs.count(ReasonCap); n != 0 {
		t.Errorf("cap retirements = %d, want 0: nothing was spent, so no plan was capped", n)
	}

	fifth := serve(srv, http.MethodGet, "/mm/v1/chat", upstream.header(nil))
	if fifth.Code == http.StatusServiceUnavailable {
		t.Fatalf("status = 503 (Retry-After %q) after four upstream failures; "+
			"an upstream outage must not become a self-inflicted quota outage",
			fifth.Header().Get("Retry-After"))
	}
	if fifth.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want the upstream 500 still relayed", fifth.Code)
	}
	if got := upstream.hitCount(); got != 5 {
		t.Errorf("upstream saw %d requests, want 5: the route must still be serving", got)
	}
	for _, l := range auditLines(t, &audit) {
		if _, present := l["tokens"]; present {
			t.Errorf("audit line %v charges tokens for a request the upstream failed", l)
		}
		if l["tokens_estimated"] == true {
			t.Errorf("audit line %v marks an estimate for a request that was never charged", l)
		}
	}
}

// TestRotation_ClientErrorIsChargedAsARequestButNeverAnEstimate DOCUMENTS the
// 4xx half of the policy, which is deliberately not the 5xx half:
//
//	5xx  the upstream did not serve the request  -> OutcomeFailed, no charge
//	4xx  the upstream served it and said no      -> a request, and ONLY the
//	     tokens it actually reported (usually none)
//
// A 400 consumed upstream work and counts against a request plan; it generated
// no completion, so charging it a streaming estimate would be inventing spend
// in the other direction.
func TestRotation_ClientErrorIsChargedAsARequestButNeverAnEstimate(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"bad model"}}`)
	}))
	defer upstream.Close()

	var audit bytes.Buffer
	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{
			Window: time.Hour, Tokens: 1000, EstimateTokens: 500, SoftRatio: 1,
		}}), nil, &audit)

	if rec := serve(srv, http.MethodGet, "/mm/v1/chat", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want the upstream 400 relayed", rec.Code)
	}

	tokens, requests, errs := chargedTokens(storeFor(t, srv, "mm"), "mm")
	if requests != 1 {
		t.Errorf("requests = %d, want 1: a 4xx reached the upstream and counts against a request plan", requests)
	}
	if tokens != 0 {
		t.Errorf("tokens = %d, want 0: a rejected request generated no completion to charge for", tokens)
	}
	if errs != 0 {
		t.Errorf("errors = %d, want 0: the upstream answered, so this is not an upstream failure", errs)
	}
	for _, l := range auditLines(t, &audit) {
		if l["tokens_estimated"] == true {
			t.Errorf("audit line %v marks an estimate for a 4xx that was charged nothing", l)
		}
	}
}

// ---------------------------------------------------------------------------
// R3 — one retirement is one metric increment
// ---------------------------------------------------------------------------

// TestRotation_QuotaRetirementIsCountedOncePerKeyOnTheMinimalConfig is the
// finding as MEASURED: sixty concurrent 429s across two keys produced sixty
// increments for two real retirements, on the MINIMAL DOCUMENTED rotation block
// (`rotation: {}` — no budget window). The counter is the required alerting
// surface, so a config that inflates it 30x makes the alert unusable.
func TestRotation_QuotaRetirementIsCountedOncePerKeyOnTheMinimalConfig(t *testing.T) {
	t.Parallel()
	const burst = 60
	gate := newReleaseGate(burst)
	// A probe: this test counts no arrivals, but it does GATE on them, and a
	// note raised by another process releases the burst before all sixty are
	// in flight -- which is the whole premise of the test. See upstreamProbe.
	upstream := newUpstreamProbe(t, func(w http.ResponseWriter, _ *http.Request) {
		// Hold every request until the whole burst is in flight, so all sixty
		// settle against a key that is already retired.
		gate.note()
		gate.wait()
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate limited"}`)
	})

	obs := newCountingObserver()
	// &RotationConfig{} is exactly what the documented minimal block
	// `rotation: {}` decodes to; TestRotationConfig_AcceptsBothShippedSpellings
	// pins that mapping.
	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"}, &RotationConfig{}),
		nil, nil, WithRotationRetireObserver(obs))
	handler := srv.Handler()

	var wg sync.WaitGroup
	wg.Add(burst)
	for range burst {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, upstream.stamp(httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil)))
			if rec.Code != http.StatusTooManyRequests {
				t.Errorf("status = %d, want the upstream 429 relayed", rec.Code)
			}
		}()
	}
	wg.Wait()

	if got := obs.count(ReasonQuota); got != 2 {
		t.Errorf("retired{reason=quota} = %d for %d concurrent 429s over 2 keys, want 2: "+
			"one increment per key that actually left rotation", got, burst)
	}
	if got := obs.total(); got != 2 {
		t.Errorf("total retirement events = %d, want 2", got)
	}
	for i, k := range storeFor(t, srv, "mm").Snapshot("mm") {
		if k.Selectable {
			t.Errorf("key %d still selectable after answering a quota status", i)
		}
	}
}

// TestStore_RetirementSurvivesARolloverLandingMidCall is the secondary half of
// R3: the deadline was computed under one critical section and applied under
// another, so a window rollover arriving between them silently downgraded the
// retirement to a no-op — the key stayed in rotation and no event was emitted.
//
// The stepping clock advances on every read, so the second reading is always in
// a later window than the first. Arithmetic, with a 60s window and a 40s step:
// NewStore reads once (windowStart = t0+40s); the retirement reads again
// (t0+80s, no rollover yet, deadline = windowStart+60s = t0+100s). A second,
// separate reading would land at t0+120s, roll the window to t0+100s, and find
// the deadline already in the past.
func TestStore_RetirementSurvivesARolloverLandingMidCall(t *testing.T) {
	t.Parallel()
	clk := newSteppingClock(40 * time.Second)
	obs := newCountingObserver()
	st := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(obs),
		WithBudget(Budget{Window: time.Minute}))

	st.retireForWindow("r", 0, ReasonQuota)

	if got := retiredUntilOf(st, "r", 0); got.IsZero() {
		t.Error("key 0 was never retired: a rollover between the deadline's computation " +
			"and its application turned the retirement into a silent no-op")
	}
	if got := obs.count(ReasonQuota); got != 1 {
		t.Errorf("retired{reason=quota} = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// R4 — the audit stream reconciles to the store
// ---------------------------------------------------------------------------

// TestRotation_EstimatedChargeIsRecoverableFromTheAuditStream is the finding as
// MEASURED: the store charged 750 estimated tokens and the audit line omitted
// "tokens" entirely, so summing the NDJSON stream under-reported consumption by
// the whole of every streaming request. tokens_estimated says HOW the figure
// was arrived at; it is not a substitute for the figure.
func TestRotation_EstimatedChargeIsRecoverableFromTheAuditStream(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		for _, chunk := range []string{
			"data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
			"data: [DONE]\n\n",
		} {
			_, _ = io.WriteString(w, chunk)
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer upstream.Close()

	var audit bytes.Buffer
	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{
			Window: time.Hour, Tokens: 100000, EstimateTokens: 750,
		}}), nil, &audit)

	const calls = 3
	for i := range calls {
		if rec := serve(srv, http.MethodGet, "/mm/v1/chat", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, rec.Code)
		}
	}

	tokens, _, _ := chargedTokens(storeFor(t, srv, "mm"), "mm")
	if tokens != calls*750 {
		t.Fatalf("store charged %d tokens, want %d", tokens, calls*750)
	}

	var audited float64
	for _, l := range auditLines(t, &audit) {
		if l["tokens_estimated"] != true {
			t.Errorf("audit line %v: tokens_estimated = %v, want true", l, l["tokens_estimated"])
		}
		n, present := l["tokens"].(float64)
		if !present {
			t.Errorf("audit line %v omits the charged amount; the stream cannot be summed", l)
		}
		audited += n
	}
	if int64(audited) != tokens {
		t.Errorf("audit stream totals %v tokens, store charged %d: the two must reconcile", audited, tokens)
	}
}

// ---------------------------------------------------------------------------
// R7 — a charge is only authoritative if it was actually readable
// ---------------------------------------------------------------------------

// TestUsageExtractor_UnreadableTotalDemotesToAnEstimateInsteadOfATrustedCharge.
//
// The digit scan stopped at the first non-digit and the terminator check
// accepted whatever that byte was, so `"total_tokens":1.5` was charged as an
// authoritative 1 — a malformed or hostile upstream could drive the charge
// arbitrarily low while Estimated stayed false, which is the one combination
// that also suppresses leastTokens' own degrade-to-request-ordering guard.
//
// The correct answer for anything unreadable is the estimate, never a
// plausible-looking prefix of it.
func TestUsageExtractor_UnreadableTotalDemotesToAnEstimateInsteadOfATrustedCharge(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"fractional":           `{"usage":{"total_tokens":1.5}}`,
		"scientific":           `{"usage":{"total_tokens":1.5e3}}`,
		"leading zero decimal": `{"usage":{"total_tokens":0.9}}`,
		"digits then rubbish":  `{"usage":{"total_tokens":12x}}`,
		"quoted number":        `{"usage":{"total_tokens":"4321"}}`,
		"negative":             `{"usage":{"total_tokens":-5}}`,
		"unterminated by tail": `{"usage":{"total_tokens":4321`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := observeAll(NewUsageExtractor(), body)
			if got.Tokens != TokensUnknown {
				t.Errorf("Tokens = %d for %s, want TokensUnknown (%d): an unreadable total "+
					"must demote to an estimate, never be charged as authoritative",
					got.Tokens, body, TokensUnknown)
			}
			if !got.Estimated {
				t.Errorf("Estimated = false for %s, want true", body)
			}
		})
	}
}

// TestUsageExtractor_ReadableTotalsAreStillCharged is the other half: the
// terminator rule must not reject the shapes real providers actually send.
func TestUsageExtractor_ReadableTotalsAreStillCharged(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		want int64
	}{
		"object close":     {`{"usage":{"total_tokens":4321}}`, 4321},
		"comma":            {`{"usage":{"total_tokens":4321,"prompt_tokens":7}}`, 4321},
		"space then close": {`{"usage":{"total_tokens": 4321 }}`, 4321},
		"sse newline":      {"data: {\"usage\":{\"total_tokens\":4321}}\n\n", 4321},
		"zero":             {`{"usage":{"total_tokens":0}}`, 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := observeAll(NewUsageExtractor(), tc.body)
			if got.Tokens != tc.want || got.Estimated {
				t.Errorf("Tokens=%d Estimated=%v for %s, want %d and false",
					got.Tokens, got.Estimated, tc.body, tc.want)
			}
		})
	}
}

// TestRotation_AuditNamesTheEstimateEvenWhenTheBudgetIsZero pins the corner the
// reconciliation rests on: with no estimate configured the charge really is
// zero, so omitting "tokens" is correct and the sum is still exact.
func TestRotation_AuditNamesTheEstimateEvenWhenTheBudgetIsZero(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	var audit bytes.Buffer
	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{Window: time.Hour, Requests: 100, SoftRatio: 1}}), nil, &audit)

	if rec := serve(srv, http.MethodGet, "/mm/v1/chat", nil); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	tokens, _, _ := chargedTokens(storeFor(t, srv, "mm"), "mm")
	if tokens != 0 {
		t.Fatalf("store charged %d tokens with no estimate configured, want 0", tokens)
	}
	line := audit.String()
	if !strings.Contains(line, `"tokens_estimated":true`) {
		t.Errorf("audit = %s, want the estimate marker", line)
	}
	if strings.Contains(line, `"tokens":`) {
		t.Errorf("audit = %s, want no token figure when the charge really was zero", line)
	}
}
