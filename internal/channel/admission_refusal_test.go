package channel

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// ---------------------------------------------------------------------------
// M4 — the R1 admission fix created a NEW refusal mode and labelled it with the
// OLD one.
//
// MEASURED: while refusing, /healthz reported {Keys:2 Available:2
// Degraded:false} and every key state read Selectable:true Drained:false, yet
// callers received {"error":"keys_exhausted","hint":"every upstream key on this
// route is retired or drained"}. An operator paging on that hunts a billing
// problem that does not exist, and the one signal that could have contradicted
// them agreed with the truth instead of with the error.
// ---------------------------------------------------------------------------

// refusalBody decodes a 503 answer. The body is the operator-facing half of the
// contract, so the assertions are written against it rather than against the
// internals that produced it.
func refusalBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode 503 body %q: %v", body, err)
	}
	return m
}

// fillWithUnsettledLeases takes one lease per key and never settles them, which
// is what an in-flight burst looks like to the store: the plan is untouched, the
// requests simply have not come back yet.
func fillWithUnsettledLeases(t *testing.T, st *Store, route string, n int) {
	t.Helper()
	for i := range n {
		if _, ok := st.Acquire(route); !ok {
			t.Fatalf("lease %d of %d was refused; this fixture must FILL the route, not exhaust it", i, n)
		}
	}
}

// oneRequestPerKeyBudget makes the hard cap the only cap and sets it at one
// request per key, so two unsettled leases are exactly a full route.
func oneRequestPerKeyBudget() *RotationConfig {
	return &RotationConfig{Budget: Budget{Window: time.Hour, Requests: 1, SoftRatio: 1, EstimateTokens: 1}}
}

// admissionRoute is a two-key pooled route whose forwarder FAILS THE TEST if it
// is ever called: every refusal here must be answered before any upstream call.
func admissionRoute(t *testing.T, name string, audit io.Writer) *Server {
	t.Helper()
	return rotServer(t, rotatingConfig(t, name, "https://example.invalid",
		[]string{"k0-not-real", "k1-not-real"}, oneRequestPerKeyBudget()),
		failForwarder{t: t}, audit)
}

// TestRotation_AdmissionRefusalIsNotReportedAsAnExhaustedPlan is M4 as measured.
func TestRotation_AdmissionRefusalIsNotReportedAsAnExhaustedPlan(t *testing.T) {
	t.Parallel()
	const route = "admission-live"
	var audit bytes.Buffer
	srv := admissionRoute(t, route, &audit)
	st := storeFor(t, srv, route)
	fillWithUnsettledLeases(t, st, route, 2)

	rec := serve(srv, http.MethodGet, "/mm/v1/chat", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	body := refusalBody(t, rec.Body.String())
	if got := body["error"]; got != "admission_limited" {
		t.Errorf("error = %v, want %q: no key is retired and no key is drained, so this is a concurrency "+
			"refusal and reporting it as a spent plan sends an operator after a billing problem that does not exist",
			got, "admission_limited")
	}
	hint, _ := body["hint"].(string)
	if strings.Contains(hint, "retired or drained") {
		t.Errorf("hint = %q, want it not to repeat the exhausted-plan wording; no key here is either", hint)
	}
	if !strings.Contains(hint, "in flight") {
		t.Errorf("hint = %q, want it to name the actual cause — leases already in flight — so the reader is not left "+
			"to guess which of the two 503s they are holding", hint)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want %q: an admission refusal clears when an in-flight lease settles, "+
			"not when the accounting window rolls", got, "1")
	}

	// The half of the measurement that makes this a defect rather than a
	// wording quibble: every health signal said the keys were fine, and it was
	// RIGHT. Only the error contradicted it.
	inv := srv.KeyInventory()[route]
	want := KeyInventory{Mode: AuthInject, Pooled: true, Keys: 2, Available: 2, Degraded: false}
	if inv != want {
		t.Errorf("KeyInventory = %+v, want %+v", inv, want)
	}
	for i, k := range st.Snapshot(route) {
		if !k.Selectable || k.Drained || k.SoftRetired {
			t.Errorf("key %d = %+v, want Selectable with nothing retired: the fixture must refuse on admission, not on exhaustion", i, k)
		}
	}

	line := audit.String()
	if !strings.Contains(line, `"status":503`) || !strings.Contains(line, `"error":"admission_limited"`) {
		t.Errorf("audit = %s, want status 503 and error admission_limited", line)
	}
}

// TestRotation_DrainedRouteStillReportsKeysExhausted is the counter-test. The
// split is only worth anything if the OTHER label still means what it always
// meant: a genuinely spent route must keep answering keys_exhausted, with the
// wait the store can actually name.
func TestRotation_DrainedRouteStillReportsKeysExhausted(t *testing.T) {
	t.Parallel()
	const route = "drained-live"
	var audit bytes.Buffer
	srv := admissionRoute(t, route, &audit)

	st := storeFor(t, srv, route)
	deadline := time.Now().Add(90 * time.Second)
	st.Retire(route, 0, deadline)
	st.Retire(route, 1, deadline)

	rec := serve(srv, http.MethodGet, "/mm/v1/chat", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	body := refusalBody(t, rec.Body.String())
	if got := body["error"]; got != "keys_exhausted" {
		t.Errorf("error = %v, want %q on a route whose every key is retired", got, "keys_exhausted")
	}
	if hint, _ := body["hint"].(string); !strings.Contains(hint, "retired or drained") {
		t.Errorf("hint = %q, want it to name the retirement", hint)
	}
	if got := rec.Header().Get("Retry-After"); got != "90" {
		t.Errorf("Retry-After = %q, want %q — the wait the store can name, not the floor", got, "90")
	}
	if inv := srv.KeyInventory()[route]; !inv.Degraded || inv.Available != 0 {
		t.Errorf("KeyInventory = %+v, want available 0 and degraded true", inv)
	}
	if line := audit.String(); !strings.Contains(line, `"error":"keys_exhausted"`) {
		t.Errorf("audit = %s, want error keys_exhausted", line)
	}
}

// TestRotation_RefusalsAreCountedUnderSeparateMetricReasons pins the alerting
// surface. Both refusals answer 503, so a counter that does not separate them
// leaves an operator unable to distinguish "the plans are spent" from "the route
// is being offered more concurrency than its plan allows" — which is exactly the
// distinction the error code now makes in the body.
//
// Route names are unique to this test so its label sets are private to it and
// the global counter needs no reset.
func TestRotation_RefusalsAreCountedUnderSeparateMetricReasons(t *testing.T) {
	t.Parallel()
	const (
		admissionRoute503 = "admission-metric"
		drainedRoute503   = "drained-metric"
	)
	count := func(route, reason string) float64 {
		return testutil.ToFloat64(AdmissionRefusedTotal.WithLabelValues(route, reason))
	}

	admSrv := admissionRoute(t, admissionRoute503, nil)
	fillWithUnsettledLeases(t, storeFor(t, admSrv, admissionRoute503), admissionRoute503, 2)
	if got := serve(admSrv, http.MethodGet, "/mm/v1/chat", nil).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("admission status = %d, want 503", got)
	}

	drnSrv := admissionRoute(t, drainedRoute503, nil)
	drnStore := storeFor(t, drnSrv, drainedRoute503)
	deadline := time.Now().Add(90 * time.Second)
	drnStore.Retire(drainedRoute503, 0, deadline)
	drnStore.Retire(drainedRoute503, 1, deadline)
	if got := serve(drnSrv, http.MethodGet, "/mm/v1/chat", nil).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("drained status = %d, want 503", got)
	}

	if got := count(admissionRoute503, "admission_limited"); got != 1 {
		t.Errorf("admission_limited{route=%q} = %v, want 1", admissionRoute503, got)
	}
	if got := count(admissionRoute503, "keys_exhausted"); got != 0 {
		t.Errorf("keys_exhausted{route=%q} = %v, want 0: an admission refusal must not inflate the billing series",
			admissionRoute503, got)
	}
	if got := count(drainedRoute503, "keys_exhausted"); got != 1 {
		t.Errorf("keys_exhausted{route=%q} = %v, want 1", drainedRoute503, got)
	}
	if got := count(drainedRoute503, "admission_limited"); got != 0 {
		t.Errorf("admission_limited{route=%q} = %v, want 0", drainedRoute503, got)
	}
}

// TestStore_ReserveReportsWhichFilterEmptiedTheCandidateSet pins the same split
// one layer down, so the guarantee is a property of the STORE rather than of the
// handler that currently reads it. A future caller that asks the store directly
// gets the same two answers.
func TestStore_ReserveReportsWhichFilterEmptiedTheCandidateSet(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	st := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: time.Hour, Requests: 1, SoftRatio: 1, EstimateTokens: 1}))

	for i := range 2 {
		if _, refusal := st.acquire("r"); refusal != refusalNone {
			t.Fatalf("lease %d refused with %v, want a grant", i, refusal)
		}
	}
	if _, refusal := st.acquire("r"); refusal != refusalAdmission {
		t.Errorf("refusal with both keys selectable and both at cap in flight = %v, want refusalAdmission", refusal)
	}

	drained := NewStore(map[string]int{"r": 2},
		WithClock(clk.Now), WithRetireObserver(newCountingObserver()),
		WithBudget(Budget{Window: time.Hour, Requests: 1, SoftRatio: 1, EstimateTokens: 1}))
	until := clk.Now().Add(time.Minute)
	drained.Retire("r", 0, until)
	drained.Retire("r", 1, until)
	if _, refusal := drained.acquire("r"); refusal != refusalDrained {
		t.Errorf("refusal with every key retired = %v, want refusalDrained", refusal)
	}

	if _, refusal := st.acquire("no-such-route"); refusal != refusalDrained {
		t.Errorf("refusal for an unknown route = %v, want refusalDrained: an unknown route will not clear on its own, "+
			"so it must not promise a caller the short admission wait", refusal)
	}
}
