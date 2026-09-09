package channel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// slowHeaderUpstream stands in for a non-streaming completions endpoint: it
// sends NO byte of the response — status line included — until it has finished
// "generating". That shape is the entire defect these tests pin. A header-phase
// timer cannot tell it apart from an upstream that has hung, because on the
// wire, for the whole of delay, they are identical.
func slowHeaderUpstream(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"text":"generated"}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// gatewayFor builds a one-route gateway around fwd. Passthrough is chosen so no
// credential, environment variable or secret provider is involved: these tests
// are about a clock, and anything else in the fixture is a way for them to fail
// for a reason they are not testing.
func gatewayFor(t *testing.T, routeName, upstream string, budget time.Duration, fwd Forwarder, audit io.Writer) *Server {
	t.Helper()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: routeName, Prefix: "/" + routeName + "/", Upstream: upstream,
		Auth: AuthPassthrough, Enabled: true, Timeout: budget,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, fwd, NewAuditor(audit))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func completionRequest(routeName string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/"+routeName+"/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
}

// TestNewHTTPForwarder_NoResponseHeaderCeiling pins the absence of a constant.
//
// The default transport carried ResponseHeaderTimeout: 60s. Every other budget
// in the path was larger, so that field — not the route budget, not the
// server default, not any caller's deadline — was what every non-streaming
// completion actually ran against, and any generation that took longer than a
// minute came back to the caller as "502 upstream unavailable".
//
// This asserts the field is zero rather than "large enough", because the two
// are different promises. A larger constant would still be a second ceiling,
// still invisible in the configuration, and still the thing an operator's
// timeout edit silently failed to move.
func TestNewHTTPForwarder_NoResponseHeaderCeiling(t *testing.T) {
	t.Parallel()
	fwd, ok := NewHTTPForwarder().(*httpForwarder)
	if !ok {
		t.Fatalf("NewHTTPForwarder returned %T, want *httpForwarder", NewHTTPForwarder())
	}
	tr, ok := fwd.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", fwd.client.Transport)
	}
	if tr.ResponseHeaderTimeout != 0 {
		t.Errorf("ResponseHeaderTimeout = %v, want 0: the route budget is the only ceiling, and a second one here is invisible to whoever configured the first", tr.ResponseHeaderTimeout)
	}
	// The same defect in its more severe spelling. A Client.Timeout bounds the
	// whole exchange rather than the header phase, so it would cut streaming
	// responses mid-stream as well as capping long generations — and it would
	// be just as unreachable from any configuration file.
	if fwd.client.Timeout != 0 {
		t.Errorf("client.Timeout = %v, want 0: a whole-request client deadline would cap generations AND truncate streams", fwd.client.Timeout)
	}
	// The phase timeouts that bound something no route budget describes stay.
	// Losing them with the defect would trade one silent failure for another.
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout = 0: a handshake that never completes is not what the route budget is for")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout = 0: pooled connections would never be reaped")
	}
}

// TestForward_SlowHeaderUpstreamSucceeds is the defect, end to end, at a scale
// a test suite can afford: an upstream that withholds its headers for longer
// than the transport's old ceiling permitted, against a route budget that
// comfortably allows it.
//
// The control is what makes this a regression test rather than a tautology.
// The same request, the same upstream and the same budget are run a second time
// through a forwarder whose ONLY difference is a short ResponseHeaderTimeout —
// and it must fail. Without that arm, a green result would be equally
// consistent with the header delay never having been slow enough to matter,
// which is precisely the way a timing test rots into a decoration.
func TestForward_SlowHeaderUpstreamSucceeds(t *testing.T) {
	t.Parallel()
	const (
		headerDelay = 600 * time.Millisecond
		budget      = 20 * time.Second
		ceiling     = 100 * time.Millisecond
	)
	upstream := slowHeaderUpstream(t, headerDelay)

	t.Run("shipped forwarder relays it", func(t *testing.T) {
		srv := gatewayFor(t, "slowok", upstream.URL, budget, NewHTTPForwarder(), io.Discard)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, completionRequest("slowok"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: a generation slower than the old ceiling must now reach the caller (body %q)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "generated") {
			t.Errorf("body = %q, want the upstream payload", rec.Body.String())
		}
	})

	t.Run("control: a header ceiling below the delay still kills it", func(t *testing.T) {
		capped := &httpForwarder{client: &http.Client{
			CheckRedirect: refuseRedirect,
			Transport:     &http.Transport{ResponseHeaderTimeout: ceiling},
		}}
		var audit bytes.Buffer
		srv := gatewayFor(t, "slowcapped", upstream.URL, budget, capped, &audit)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, completionRequest("slowcapped"))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502: this arm exists to prove the header ceiling is what killed the request", rec.Code)
		}
		// Note what the audit says, because it is the reason the defect stayed
		// unattributed: "timeout" — the same word a genuinely exceeded route
		// budget produces. The two were distinguishable only by latency_ms
		// landing on a number matching no configured budget, and nothing
		// counted or alerted on that. A reader of this line was told the truth
		// in a vocabulary that could not name which clock had fired.
		if !strings.Contains(audit.String(), `"error":"timeout"`) {
			t.Errorf("audit error class = %s, want timeout", audit.String())
		}
		if !strings.Contains(audit.String(), `"status":502`) {
			t.Errorf("audit status = %s, want 502", audit.String())
		}
	})
}

// TestForward_RouteBudgetStillBoundsASilentUpstream is the other half of the
// fix, and the one that would matter if this change were wrong: removing the
// transport ceiling must not leave a stalled upstream unbounded.
//
// It also pins the classification. The deadline that fires is now the route
// budget, so the failure arrives as context.DeadlineExceeded and errorClass
// calls it "timeout" — in the audit line and on the counter alike. Under the
// old constant the same stall produced "upstream_error", which is a sentence
// about the provider rather than about the configuration, and it is the reason
// a mis-set budget was not diagnosable from the telemetry.
func TestForward_RouteBudgetStillBoundsASilentUpstream(t *testing.T) {
	t.Parallel()
	const (
		route  = "budget-bound"
		budget = 250 * time.Millisecond
	)
	// An order of magnitude past the budget — enough that only the budget can
	// explain a prompt 502, short enough that httptest.Server.Close is not left
	// waiting on a handler the gateway has already stopped caring about. A
	// cancelled outbound request does not reliably release the upstream handler
	// here, so the delay, not the cancellation, is what bounds this test's cost.
	upstream := slowHeaderUpstream(t, 3*time.Second)

	before := testutil.ToFloat64(ForwardFailedTotal.WithLabelValues(route, "timeout"))
	var audit bytes.Buffer
	srv := gatewayFor(t, route, upstream.URL, budget, NewHTTPForwarder(), &audit)

	rec := httptest.NewRecorder()
	start := time.Now()
	srv.Handler().ServeHTTP(rec, completionRequest(route))
	elapsed := time.Since(start)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: an upstream that never answers must still be cut", rec.Code)
	}
	// Generous upper bound: this asserts the budget bounded the request, not
	// how promptly a loaded CI box schedules a goroutine.
	if elapsed > 10*time.Second {
		t.Errorf("took %v with a %v budget: the route budget is not bounding the request", elapsed, budget)
	}
	if !strings.Contains(audit.String(), `"error":"timeout"`) {
		t.Errorf("audit error class = %s, want timeout", audit.String())
	}
	// ForwardFailedTotal is a package global with no reset, so this is a delta
	// against a reading taken before the request. Asserting an absolute value
	// would make the package fail under -count>1 and cost it its flake
	// detector, which is the lesson the admission-refusal sibling records.
	if got := testutil.ToFloat64(ForwardFailedTotal.WithLabelValues(route, "timeout")) - before; got != 1 {
		t.Errorf("ForwardFailedTotal{%s,timeout} delta = %v, want 1", route, got)
	}
}

// TestForwardFailedTotal_CountsEveryUnreachableUpstream covers the class this
// gateway sees most outside a timeout — nothing listening — and pins that the
// counter and the audit line agree on the word. They are computed once
// precisely so they cannot drift apart.
func TestForwardFailedTotal_CountsEveryUnreachableUpstream(t *testing.T) {
	t.Parallel()
	const route = "refused-route"
	// A server taken down leaves an address with certainty that nothing is
	// listening on it, which is steadier than picking a port and hoping.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	before := testutil.ToFloat64(ForwardFailedTotal.WithLabelValues(route, "refused"))
	var audit bytes.Buffer
	srv := gatewayFor(t, route, deadURL, 5*time.Second, NewHTTPForwarder(), &audit)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, completionRequest(route))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if got := testutil.ToFloat64(ForwardFailedTotal.WithLabelValues(route, "refused")) - before; got != 1 {
		t.Errorf("ForwardFailedTotal{%s,refused} delta = %v, want 1 (audit line: %s)", route, got, audit.String())
	}
	if !strings.Contains(audit.String(), `"error":"refused"`) {
		t.Errorf("audit error class = %s, want refused — the counter and the audit line must not be able to disagree", audit.String())
	}
}

// TestValidate_TimeoutMustNotBeNegative guards the invariant the forwarder now
// leans on. With no ceiling left in the transport, the validated route budget
// is the only thing standing between a quiet upstream and a request that never
// resolves, so "positive on every route" has to be a property Validate enforces
// rather than a habit configurations happen to have.
func TestValidate_TimeoutMustNotBeNegative(t *testing.T) {
	t.Parallel()
	route := func(timeout time.Duration) Route {
		return Route{Name: "r", Prefix: "/r/", Upstream: "https://example.invalid", Auth: AuthPassthrough, Enabled: true, Timeout: timeout}
	}
	t.Run("server budget", func(t *testing.T) {
		cfg := &Config{Listen: "127.0.0.1:0", Timeout: -time.Second, Routes: []Route{route(0)}}
		if err := cfg.Validate(); err == nil {
			t.Fatal("Validate accepted a negative server timeout")
		} else if !strings.Contains(err.Error(), "must not be negative") {
			t.Errorf("error = %v, want it to name the negative timeout", err)
		}
	})
	t.Run("route budget", func(t *testing.T) {
		cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{route(-time.Millisecond)}}
		if err := cfg.Validate(); err == nil {
			t.Fatal("Validate accepted a negative route timeout")
		} else if !strings.Contains(err.Error(), `route "r"`) {
			t.Errorf("error = %v, want it to name the offending route", err)
		}
	})
	// Positive controls: zero keeps its documented meaning at both levels, so
	// the check above cannot pass by rejecting everything.
	t.Run("zero inherits, and inheritance is positive", func(t *testing.T) {
		cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{route(0)}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate rejected the documented default-inheriting config: %v", err)
		}
		if cfg.Timeout != DefaultTimeout {
			t.Errorf("server timeout = %v, want the default %v", cfg.Timeout, DefaultTimeout)
		}
		if cfg.Routes[0].Timeout != DefaultTimeout {
			t.Errorf("route timeout = %v, want it to inherit %v", cfg.Routes[0].Timeout, DefaultTimeout)
		}
	})
	t.Run("an explicit route budget survives validation", func(t *testing.T) {
		cfg := &Config{Listen: "127.0.0.1:0", Timeout: 30 * time.Second, Routes: []Route{route(4 * time.Minute)}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if cfg.Routes[0].Timeout != 4*time.Minute {
			t.Errorf("route timeout = %v, want the configured 4m to be left alone — a long-generation route is the whole point of the key", cfg.Routes[0].Timeout)
		}
	})
}
