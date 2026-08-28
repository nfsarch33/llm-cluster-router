// loopback_surfaces_v18778_test.go -- the surfaces the bearer rollout
// does not cover.
//
// Bearer auth guards /v1/* and nothing else. Everything asserted here is
// about what remains reachable without a credential once the token is
// switched on: the pprof listener, the metrics listener, and the forced
// upstream probe hiding behind /healthz?live=1.
//
// The /v1/* cases are PINS, not new behaviour. They exist so this change
// cannot alter the auth boundary it is working next to.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cfgpkg "github.com/nfsarch33/llm-cluster-router/internal/config"
	"github.com/nfsarch33/llm-cluster-router/internal/health"
	"github.com/nfsarch33/llm-cluster-router/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The serving path must apply the loopback rule itself, not merely trust
// LoadConfig to have done it. A Config can reach runServe without passing
// through LoadConfig.
func TestDiagnosticListenAddr_WiredOnTheServingPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"host-less pprof port binds loopback", ":6060", "127.0.0.1:6060"},
		{"host-less metrics port binds loopback", ":9091", "127.0.0.1:9091"},
		{"an explicit address still wins", "0.0.0.0:6060", "0.0.0.0:6060"},
		{"empty stays empty (pprof off)", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := diagnosticListenAddr(tc.in); got != tc.want {
				t.Fatalf("diagnosticListenAddr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	if diagnosticListenAddr(":6060") != cfgpkg.DiagnosticListenAddr(":6060") {
		t.Fatal("main's resolver has drifted from config.DiagnosticListenAddr")
	}
}

// pprof is off by default. Moving it to loopback is not a licence to
// switch it on for every deployment that has it off today.
func TestDebugAddr_DefaultsOff(t *testing.T) {
	var zero config
	if got := diagnosticListenAddr(zero.DebugAddr); got != "" {
		t.Fatalf("zero-value DebugAddr resolved to %q, want \"\" (pprof off)", got)
	}
}

// The debug mux serves what it has always served -- the point of the
// change is where it binds, not what it exposes.
func TestNewDebugMux_ServesPprofAndNothingElse(t *testing.T) {
	srv := httptest.NewServer(newDebugMux())
	t.Cleanup(srv.Close)

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap?debug=1", "/debug/pprof/cmdline", "/debug/pprof/symbol"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status %d, want 200", path, resp.StatusCode)
		}
	}
	// Not a general-purpose listener: no metrics, no health, no /v1.
	for _, path := range []string{"/metrics", "/healthz", "/v1/models", "/"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s status %d on the debug listener, want 404", path, resp.StatusCode)
		}
	}
}

// serveMuxFixture builds the real public mux with a real bearer wrapper.
func serveMuxFixture(t *testing.T, token string) *http.ServeMux {
	t.Helper()
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")
	r.cfg.AuthToken = token
	return serveMux(r, bearerAuthFunc(r.AuthToken))
}

func doGet(t *testing.T, mux *http.ServeMux, target, authz string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// THE PIN. Liveness stays anonymous; /v1/* stays gated exactly as it is
// today, including the empty-token short circuit the rollout is about to
// end. Nothing in this change may move a row of this table.
func TestServeMux_AuthBoundaryUnchanged(t *testing.T) {
	const token = "pinned-token"

	tests := []struct {
		name       string
		token      string
		path       string
		authz      string
		wantStatus int
	}{
		{"healthz anonymous with a token configured", token, "/healthz", "", http.StatusOK},
		{"health anonymous with a token configured", token, "/health", "", http.StatusOK},
		{"healthz anonymous with no token configured", "", "/healthz", "", http.StatusOK},

		{"models 401 without a credential", token, "/v1/models", "", http.StatusUnauthorized},
		{"models 401 with the wrong credential", token, "/v1/models", "Bearer nope", http.StatusUnauthorized},
		{"models 401 with a bare token", token, "/v1/models", token, http.StatusUnauthorized},
		{"models 200 with the right credential", token, "/v1/models", "Bearer " + token, http.StatusOK},

		{"chat 401 without a credential", token, "/v1/chat/completions", "", http.StatusUnauthorized},
		{"completions 401 without a credential", token, "/v1/completions", "", http.StatusUnauthorized},
		{"embeddings 401 without a credential", token, "/v1/embeddings", "", http.StatusUnauthorized},

		// Today's behaviour with an empty token, pinned so this change
		// cannot be blamed for it and cannot silently alter it: the
		// bearer middleware short-circuits and /v1/* answers anonymously.
		// This is the state the credential rollout ends.
		{"models anonymous while the token is empty", "", "/v1/models", "", http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := serveMuxFixture(t, tc.token)
			rec := doGet(t, mux, tc.path, tc.authz)
			if rec.Code != tc.wantStatus {
				t.Fatalf("GET %s (token=%q authz=%q) = %d, want %d; body: %s",
					tc.path, tc.token, tc.authz, rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// /readyz is anonymous too, and its status depends on upstream state
// rather than on the credential, so the assertion is "never 401" rather
// than a fixed code.
func TestServeMux_ReadyzStaysAnonymous(t *testing.T) {
	for _, token := range []string{"", "a-configured-token"} {
		mux := serveMuxFixture(t, token)
		rec := doGet(t, mux, "/readyz", "")
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("/readyz answered 401 with token=%q; kubelet and load balancers poll it without a credential", token)
		}
		if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("/readyz = %d, want 200 or 503; body: %s", rec.Code, rec.Body.String())
		}
	}
}

// Plain /healthz must be byte-for-byte the shape its anonymous callers
// already parse: no new required key, no throttle marker, no live_probe.
func TestHandleHealth_PlainResponseUnchanged(t *testing.T) {
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")

	// Exhaust the forced-probe budget first. Plain liveness must be
	// completely unaffected by the state of that bucket.
	for i := 0; i < health.DefaultLiveProbeBurst+5; i++ {
		_ = doGet(t, serveMux(r, bearerAuthFunc(r.AuthToken)), "/healthz?live=1", "")
	}

	rec := httptest.NewRecorder()
	r.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("plain /healthz = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("plain /healthz body not JSON: %v", err)
	}
	for _, key := range []string{"ok", "healthy_nodes", "total_nodes", "queue_depth",
		"inflight_requests", "max_queue_depth", "max_concurrency",
		"buffered_bodies", "peak_buffered_bodies", "nodes"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("plain /healthz lost key %q; existing anonymous callers parse it. body: %s", key, rec.Body.String())
		}
	}
	for _, key := range []string{"live_probe", "probe_timeout", "live_probe_throttled"} {
		if _, ok := body[key]; ok {
			t.Fatalf("plain /healthz gained key %q; it must be indistinguishable from today's response. body: %s",
				key, rec.Body.String())
		}
	}
}

// The forced variant is bounded, and exceeding the bound degrades to the
// cached view rather than answering an error.
func TestHandleHealth_ForcedProbeIsBounded(t *testing.T) {
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")
	mux := serveMux(r, bearerAuthFunc(r.AuthToken))

	before := testutil.ToFloat64(metrics.LiveProbeThrottledTotal)

	const attempts = 12
	forced, throttled := 0, 0
	for i := 0; i < attempts; i++ {
		rec := doGet(t, mux, "/healthz?live=1&timeout=500ms", "")
		// Never an error: /healthz is a liveness endpoint first, and a
		// 429 here would manufacture the outage signal the bound exists
		// to protect.
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: /healthz?live=1 = %d, want 200 even when throttled; body: %s",
				i, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("attempt %d: body not JSON: %v", i, err)
		}
		switch {
		case body["live_probe"] == true:
			forced++
			if _, ok := body["live_probe_throttled"]; ok {
				t.Fatalf("attempt %d: a served forced probe is also marked throttled: %s", i, rec.Body.String())
			}
		case body["live_probe_throttled"] == true:
			throttled++
			if body["live_probe"] != false {
				t.Fatalf("attempt %d: throttled response must say live_probe:false, got %s", i, rec.Body.String())
			}
			// The cached view is still a complete answer.
			if _, ok := body["nodes"]; !ok {
				t.Fatalf("attempt %d: throttled response dropped the nodes array: %s", i, rec.Body.String())
			}
		default:
			t.Fatalf("attempt %d: response is neither forced nor throttled: %s", i, rec.Body.String())
		}
	}

	if forced != health.DefaultLiveProbeBurst {
		t.Fatalf("served %d forced probes out of %d requests, want exactly the burst %d",
			forced, attempts, health.DefaultLiveProbeBurst)
	}
	if throttled != attempts-health.DefaultLiveProbeBurst {
		t.Fatalf("throttled %d of %d, want %d", throttled, attempts, attempts-health.DefaultLiveProbeBurst)
	}
	if delta := testutil.ToFloat64(metrics.LiveProbeThrottledTotal) - before; delta != float64(throttled) {
		t.Fatalf("llm_router_health_live_probe_throttled_total rose by %v, want %d", delta, throttled)
	}
}

// The bound is honoured whichever alias the caller uses, and it is one
// shared budget rather than one per path -- otherwise /health is a free
// second bucket for the same amplification.
func TestHandleHealth_ForcedProbeBudgetIsShared(t *testing.T) {
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")
	mux := serveMux(r, bearerAuthFunc(r.AuthToken))

	forced := 0
	for i := 0; i < health.DefaultLiveProbeBurst+4; i++ {
		path := "/healthz?live=1"
		if i%2 == 1 {
			path = "/health?live=1"
		}
		rec := doGet(t, mux, path, "")
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["live_probe"] == true {
			forced++
		}
	}
	if forced != health.DefaultLiveProbeBurst {
		t.Fatalf("alternating /healthz and /health served %d forced probes, want one shared budget of %d",
			forced, health.DefaultLiveProbeBurst)
	}
}

// The forced variant stays ANONYMOUS. Gating it on the bearer was the
// rejected alternative: it is inert while the configured token is empty,
// and it 401s existing anonymous callers the moment the token lands.
func TestHandleHealth_ForcedProbeStaysAnonymous(t *testing.T) {
	upstream := newStubRouterEndpoint(t, 0, 0)
	r := newTestRouter(t, upstream.URL, "stub-model")
	r.cfg.AuthToken = "a-configured-token"
	mux := serveMux(r, bearerAuthFunc(r.AuthToken))

	rec := doGet(t, mux, "/healthz?live=1&timeout=500ms", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz?live=1 without a credential = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["live_probe"] != true {
		t.Fatalf("first anonymous forced probe was not served with a token configured: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "unauthorized") {
		t.Fatalf("forced probe answered an auth error: %s", rec.Body.String())
	}
}

// A router assembled by hand -- no newRouter, no LoadConfig -- is still
// bounded. The lazy build must not leave a nil limiter reading as
// "allowed".
func TestForcedProbeAllowed_BoundedOnAHandBuiltRouter(t *testing.T) {
	r := &router{}
	allowed := 0
	for i := 0; i < 50; i++ {
		if r.forcedProbeAllowed() {
			allowed++
		}
	}
	if allowed != health.DefaultLiveProbeBurst {
		t.Fatalf("hand-built router admitted %d forced probes, want the default burst %d",
			allowed, health.DefaultLiveProbeBurst)
	}
	if r.liveGate == nil {
		t.Fatal("liveGate still nil after forcedProbeAllowed; the lazy build did not run")
	}
}

// An operator-configured bound is the one that applies.
func TestForcedProbeAllowed_HonoursConfiguredBound(t *testing.T) {
	r := &router{}
	r.cfg.HealthCheck.LiveProbe = cfgpkg.LiveProbeConfig{
		Interval: durationValue{Duration: time.Hour},
		Burst:    1,
	}
	if !r.forcedProbeAllowed() {
		t.Fatal("first forced probe denied under burst=1")
	}
	if r.forcedProbeAllowed() {
		t.Fatal("second forced probe allowed under burst=1 with a one-hour refill")
	}
	if got := r.liveGate.Interval(); got != time.Hour {
		t.Fatalf("limiter interval = %v, want the configured 1h", got)
	}
}
