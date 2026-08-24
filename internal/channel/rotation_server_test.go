package channel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// ---------------------------------------------------------------------------
// Helpers and forwarder doubles
// ---------------------------------------------------------------------------

// failForwarder fails the test if the gateway ever reaches an upstream.
type failForwarder struct{ t *testing.T }

func (f failForwarder) Forward(context.Context, *http.Request, *boundRoute) (*http.Response, error) {
	f.t.Error("Forwarder invoked although every key was spent; the 503 must be answered before any upstream call")
	return nil, errors.New("forwarder must not be called")
}

// errForwarder stands in for a genuinely broken upstream.
type errForwarder struct{ err error }

func (f errForwarder) Forward(context.Context, *http.Request, *boundRoute) (*http.Response, error) {
	return nil, f.err
}

// rotServer validates, constructs and returns a gateway with an explicit
// Forwarder. Credentials come from real files under t.TempDir(), so no test
// needs t.Setenv and every one of them can run in parallel.
func rotServer(t *testing.T, cfg *Config, fwd Forwarder, audit io.Writer, opts ...ServerOption) *Server {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if fwd == nil {
		fwd = NewHTTPForwarder()
	}
	if audit == nil {
		audit = io.Discard
	}
	srv, err := NewServer(cfg, fwd, NewAuditor(audit), opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// rotatingConfig builds a pooled inject route whose keys live in real files.
func rotatingConfig(t *testing.T, name, upstream string, keys []string, rot *RotationConfig) *Config {
	t.Helper()
	dir := t.TempDir()
	files := make([]string, 0, len(keys))
	for i, k := range keys {
		files = append(files, writeKeyFile(t, dir, "k"+strconv.Itoa(i)+".key", k+"\n"))
	}
	return &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: name, Prefix: "/mm/", Upstream: upstream,
		Auth: AuthInject, KeyFiles: files, Rotation: rot, Enabled: true,
	}}}
}

// storeFor reaches a route's accounting Store the only way anything can: through
// the *rotatingInjector that owns it.
//
// There is deliberately no Server.rotation map. A second reference read only by
// tests is a field that drifts out of date, which is exactly what the retired
// map did.
func storeFor(t *testing.T, s *Server, route string) *Store {
	t.Helper()
	for _, rt := range s.routes {
		if rt.Route.Name != route {
			continue
		}
		ri, ok := rt.Auth.(*rotatingInjector)
		if !ok || ri.store == nil {
			t.Fatalf("route %q has authenticator %T with no Store", route, rt.Auth)
		}
		return ri.store
	}
	t.Fatalf("no route named %q", route)
	return nil
}

// ---------------------------------------------------------------------------
// Byte-identical outbound requests
// ---------------------------------------------------------------------------

// TestRotation_LegacyAndSingleKeyRotatingOutboundsAreIdentical is the migration
// guarantee: a single-key route must produce a byte-identical outbound request
// to baseline 6e32801, and a one-key POOL must produce the same bytes as that.
func TestRotation_LegacyAndSingleKeyRotatingOutboundsAreIdentical(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var seen []http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		_, _ = io.WriteString(w, `{"object":"list"}`)
	}))
	defer upstream.Close()

	const key = "test-key-not-real"
	dir := t.TempDir()
	keyPath := writeKeyFile(t, dir, "one.key", key+"\n")

	call := func(srv *Server) {
		req := httptest.NewRequest(http.MethodGet, "/mm/v1/models", nil)
		req.Header.Set("Authorization", "Bearer placeholder-from-client")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	}

	legacy := rotServer(t, &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: upstream.URL,
		Auth: AuthInject, KeyFile: keyPath, Enabled: true,
	}}}, nil, nil)
	legacyAuth := legacy.match("/mm/v1/models").Auth
	if _, ok := legacyAuth.(*bearerInjector); !ok {
		t.Fatalf("legacy route authenticator = %T, want *bearerInjector (the untouched path)", legacyAuth)
	}
	if _, ok := legacyAuth.(keyLeaser); ok {
		t.Error("a single-key route advertises keyLeaser; it must never take the leasing path")
	}
	call(legacy)

	rotating := rotServer(t, rotatingConfig(t, "mm", upstream.URL, []string{key}, nil), nil, nil)
	if _, ok := rotating.match("/mm/v1/models").Auth.(*rotatingInjector); !ok {
		t.Fatalf("pooled route authenticator = %T, want *rotatingInjector",
			rotating.match("/mm/v1/models").Auth)
	}
	call(rotating)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(seen))
	}
	if !reflect.DeepEqual(seen[0], seen[1]) {
		t.Errorf("outbound header sets differ.\nlegacy = %v\npooled = %v", seen[0], seen[1])
	}
	if got := seen[1]["Authorization"]; len(got) != 1 || got[0] != "Bearer "+key {
		t.Errorf("pooled Authorization = %v, want exactly one %q", got, "Bearer "+key)
	}

	// The only permitted difference: budget accounting now runs.
	if got := storeFor(t, rotating, "mm").Snapshot("mm"); len(got) != 1 || got[0].Requests != 1 {
		t.Errorf("pooled snapshot = %+v, want one key with Requests 1", got)
	}
}

// ---------------------------------------------------------------------------
// 503 vs 502
// ---------------------------------------------------------------------------

func TestRotation_AllKeysSpentReturns503WithRetryAfterAndNeverCallsUpstream(t *testing.T) {
	t.Parallel()
	var audit bytes.Buffer
	srv := rotServer(t, rotatingConfig(t, "mm", "https://example.invalid",
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{Window: 5 * time.Minute, Requests: 10, EstimateTokens: 1}}),
		failForwarder{t: t}, &audit)

	st := storeFor(t, srv, "mm")
	deadline := time.Now().Add(90 * time.Second)
	st.Retire("mm", 0, deadline)
	st.Retire("mm", 1, deadline)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/models", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf(`status = %d, want 503: an operator must be able to tell "all plans spent" from "upstream broken"`, rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "90" {
		t.Errorf("Retry-After = %q, want %q", got, "90")
	}
	if body := rec.Body.String(); !strings.Contains(body, "keys_exhausted") {
		t.Errorf("body = %q, want it to name keys_exhausted", body)
	}
	line := audit.String()
	if !strings.Contains(line, `"status":503`) || !strings.Contains(line, `"error":"keys_exhausted"`) {
		t.Errorf("audit = %s, want status 503 and error keys_exhausted", line)
	}
}

func TestRotation_BrokenUpstreamIsStill502WithNoRetryAfter(t *testing.T) {
	t.Parallel()
	srv := rotServer(t, rotatingConfig(t, "mm", "https://example.invalid",
		[]string{"k1-not-real", "k2-not-real"}, nil),
		errForwarder{err: errors.New("dial tcp 127.0.0.1:1: connection refused")}, nil)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/models", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a genuinely broken upstream", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q on a 502, want none: the 502/503 distinction must not collapse", got)
	}
	var live int64
	for _, k := range storeFor(t, srv, "mm").Snapshot("mm") {
		if k.InFlight != 0 {
			t.Errorf("InFlight = %d after a failed forward, want the lease released", k.InFlight)
		}
		live += k.Requests
		if k.Tokens != 0 {
			t.Errorf("Tokens = %d after a failed forward, want 0", k.Tokens)
		}
	}
	if live != 0 {
		t.Errorf("settled Requests = %d after a failed forward, want 0: a dead upstream must not make a healthy key look used", live)
	}
}

// TestRotation_ExhaustionOutputCarriesNoCredential: the 503 body and the audit
// line are both operator-facing surfaces, and neither may carry key material.
func TestRotation_ExhaustionOutputCarriesNoCredential(t *testing.T) {
	t.Parallel()
	var audit bytes.Buffer
	srv := rotServer(t, rotatingConfig(t, "mm", "https://example.invalid",
		[]string{"secret-key-not-real-1", "secret-key-not-real-2"}, nil),
		failForwarder{t: t}, &audit)

	st := storeFor(t, srv, "mm")
	st.Retire("mm", 0, time.Now().Add(time.Minute))
	st.Retire("mm", 1, time.Now().Add(time.Minute))

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/models", nil))

	out := rec.Body.String() + rec.Header().Get("Retry-After") + audit.String()
	for _, forbidden := range []string{"secret-key-not-real-1", "secret-key-not-real-2", "Authorization"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("exhaustion output leaked %q: %s", forbidden, out)
		}
	}
	if !strings.Contains(rec.Body.String(), `"route":"mm"`) {
		t.Errorf("503 body = %q, want the route named", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "retry_after_seconds") {
		t.Errorf("503 body = %q, want retry_after_seconds", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Usage accounting through the gateway
// ---------------------------------------------------------------------------

func TestRotation_JSONUsageIsChargedExactly(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"x","usage":{"total_tokens":4321}}`)
	}))
	defer upstream.Close()

	var audit bytes.Buffer
	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{Window: time.Hour, Tokens: 100000, EstimateTokens: 150}}), nil, &audit)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var tokens, reqs int64
	for _, k := range storeFor(t, srv, "mm").Snapshot("mm") {
		tokens += k.Tokens
		reqs += k.Requests
		if k.InFlight != 0 {
			t.Errorf("InFlight = %d, want 0", k.InFlight)
		}
		if k.Estimated {
			t.Error("Estimated = true although the upstream reported a real total")
		}
	}
	if tokens != 4321 || reqs != 1 {
		t.Errorf("charged tokens=%d requests=%d, want 4321 and 1", tokens, reqs)
	}
	if !strings.Contains(audit.String(), `"tokens":4321`) {
		t.Errorf("audit = %s, want the observed token count", audit.String())
	}
	if strings.Contains(audit.String(), "tokens_estimated") {
		t.Errorf("audit = %s, want no estimate marker when a real total was reported", audit.String())
	}
}

// TestRotation_StreamingWithoutUsageChargesAMarkedEstimate: SSE that carries no
// usage must charge Budget.EstimateTokens and say so, not silently skew.
func TestRotation_StreamingWithoutUsageChargesAMarkedEstimate(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		for _, chunk := range []string{
			"data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
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
		&RotationConfig{Budget: Budget{Window: time.Hour, Tokens: 1000, EstimateTokens: 150}}), nil, &audit)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var tokens, reqs int64
	estimated := false
	for _, k := range storeFor(t, srv, "mm").Snapshot("mm") {
		tokens += k.Tokens
		reqs += k.Requests
		estimated = estimated || k.Estimated
	}
	if reqs != 1 {
		t.Errorf("requests = %d, want 1", reqs)
	}
	if tokens != 150 {
		t.Errorf("tokens = %d, want the 150-token estimate, never 0", tokens)
	}
	if !estimated {
		t.Error("no key marked Estimated after an SSE response with no usage object")
	}
	if !strings.Contains(audit.String(), `"tokens_estimated":true`) {
		t.Errorf("audit = %s, want tokens_estimated true", audit.String())
	}
	if strings.Contains(audit.String(), `"tokens":`) {
		t.Errorf("audit = %s, want no invented token figure when the upstream reported none", audit.String())
	}
}

// ---------------------------------------------------------------------------
// Quota retirement
// ---------------------------------------------------------------------------

// quotaRoute drives one pooled route whose first key answers status and whose
// second answers 200, and reports what the upstream saw.
func quotaRoute(t *testing.T, route string, status int) (*Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var sawKeys []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		sawKeys = append(sawKeys, auth)
		mu.Unlock()
		if auth == "Bearer k1-not-real" {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"quota"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)

	srv := rotServer(t, rotatingConfig(t, route, upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{Window: 10 * time.Minute, Requests: 100, EstimateTokens: 1}}), nil, nil)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sawKeys...)
	}
}

// TestRotation_UpstreamQuotaStatusRetiresWithReasonQuota covers BOTH quota
// signals. 429 is the OpenAI-compatible shape; 402 Payment Required is how the
// header-auth providers (Exa, Tavily class) report a spent plan. Treating 402 as
// a generic upstream error would keep re-selecting the dead key until the
// window rolled.
func TestRotation_UpstreamQuotaStatusRetiresWithReasonQuota(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		route  string
	}{
		{"429 too many requests", http.StatusTooManyRequests, "quota-429"},
		{"402 payment required", http.StatusPaymentRequired, "quota-402"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, saw := quotaRoute(t, tc.route, tc.status)

			before := testutil.ToFloat64(KeyRetiredTotal.WithLabelValues(tc.route, string(ReasonQuota)))
			capBefore := testutil.ToFloat64(KeyRetiredTotal.WithLabelValues(tc.route, string(ReasonCap)))

			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil))
			if rec.Code != tc.status {
				t.Fatalf("first status = %d, want the upstream %d relayed", rec.Code, tc.status)
			}

			if got := testutil.ToFloat64(KeyRetiredTotal.WithLabelValues(tc.route, string(ReasonQuota))) - before; got != 1 {
				t.Errorf("retired{reason=quota} delta = %v, want 1", got)
			}
			if got := testutil.ToFloat64(KeyRetiredTotal.WithLabelValues(tc.route, string(ReasonCap))) - capBefore; got != 0 {
				t.Errorf("retired{reason=cap} delta = %v, want 0: an upstream quota signal is not our accounting", got)
			}
			if k := storeFor(t, srv, tc.route).Snapshot(tc.route)[0]; k.Selectable {
				t.Error("key 0 still selectable after answering a quota status")
			}

			rec2 := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil))
			if rec2.Code != http.StatusOK {
				t.Fatalf("second status = %d, want 200 on the surviving key", rec2.Code)
			}
			if got := saw(); len(got) != 2 || got[1] != "Bearer k2-not-real" {
				t.Errorf("upstream saw %v, want the second request on k2-not-real", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Concurrency through the gateway
// ---------------------------------------------------------------------------

func TestRotation_ConcurrentBurstFansOutAcrossKeys(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"usage":{"total_tokens":3}}`)
	}))
	defer upstream.Close()

	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real", "k3-not-real", "k4-not-real"},
		&RotationConfig{Policy: PolicyLeastUsed}), nil, nil)
	handler := srv.Handler()

	const total = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
		}()
	}
	close(start)
	wg.Wait()

	snap := storeFor(t, srv, "mm").Snapshot("mm")
	if len(snap) != 4 {
		t.Fatalf("snapshot has %d keys, want 4", len(snap))
	}
	// Slack is documented rather than tight: leastUsed scores on
	// Requests+InFlight, which steers a burst evenly but does not serialise it.
	const slack = 30
	var settled int64
	for i, k := range snap {
		if k.Requests == 0 {
			t.Errorf("key %d received no traffic; the burst did not fan out", i)
		}
		if k.Requests > total/4+slack {
			t.Errorf("key %d took %d of %d requests, want at most %d", i, k.Requests, total, total/4+slack)
		}
		if k.InFlight != 0 {
			t.Errorf("key %d InFlight = %d after the burst settled, want 0", i, k.InFlight)
		}
		settled += k.Requests
	}
	if settled != total {
		t.Errorf("settled requests = %d, want %d", settled, total)
	}
}

// ---------------------------------------------------------------------------
// Deterministic accounting through an injected clock
// ---------------------------------------------------------------------------

// TestRotation_WindowRolloverThroughTheGatewayRestoresTheRoute proves the
// server-level clock option reaches the per-route Store, so a window can be
// rolled in a test without sleeping.
func TestRotation_WindowRolloverThroughTheGatewayRestoresTheRoute(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"usage":{"total_tokens":1}}`)
	}))
	defer upstream.Close()

	clk := newFakeClock()
	obs := newCountingObserver()
	srv := rotServer(t, rotatingConfig(t, "mm", upstream.URL,
		[]string{"k1-not-real", "k2-not-real"},
		&RotationConfig{Budget: Budget{Window: time.Hour, Requests: 1, SoftRatio: 1, EstimateTokens: 1}}),
		nil, nil, WithRotationClock(clk.Now), WithRotationRetireObserver(obs))

	call := func() int {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil))
		return rec.Code
	}
	for i := range 2 {
		if got := call(); got != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, got)
		}
	}
	if got := call(); got != http.StatusServiceUnavailable {
		t.Fatalf("third status = %d, want 503 with both keys drained", got)
	}
	if n := obs.count(ReasonCap); n != 2 {
		t.Errorf("cap retirements = %d, want one per key", n)
	}
	if inv := srv.KeyInventory()["mm"]; !inv.Degraded || inv.Available != 0 || inv.Keys != 2 {
		t.Errorf("KeyInventory = %+v, want a degraded two-key pool", inv)
	}

	clk.Advance(time.Hour)
	if got := call(); got != http.StatusOK {
		t.Fatalf("status after the window rolled = %d, want 200", got)
	}
	if inv := srv.KeyInventory()["mm"]; inv.Degraded {
		t.Errorf("KeyInventory = %+v, want the route restored after rollover", inv)
	}
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

func TestRotation_MetricsRegistrationIsOptInAndIsolatable(t *testing.T) {
	t.Parallel()
	// Touch one child so the family is materialised for Gather.
	KeyRetiredTotal.WithLabelValues("metrics-test-route", string(ReasonCap)).Add(0)

	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	const want = "llm_cluster_router_helixchannel_key_retired_total"
	var found bool
	for _, f := range families {
		if f.GetName() != want {
			continue
		}
		found = true
		var names []string
		for _, l := range f.GetMetric()[0].GetLabel() {
			names = append(names, l.GetName())
		}
		if !reflect.DeepEqual(names, []string{"reason", "route"}) {
			t.Errorf("label names = %v, want [reason route]", names)
		}
	}
	if !found {
		var got []string
		for _, f := range families {
			got = append(got, f.GetName())
		}
		t.Fatalf("registry has %v, want a family named %q", got, want)
	}

	def, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather default registry: %v", err)
	}
	for _, f := range def {
		if f.GetName() == want {
			t.Fatalf("importing internal/channel registered %q on the default registry", want)
		}
	}
}
