package channel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// C2 / H1 / M1 — http.Client.CheckRedirect was nil, so the stdlib followed up
// to ten hops REPLAYING the injected credential.
//
// MEASURED cross-domain, with Go's own cross-domain header strip fully in
// force: the redirect target received x-api-key="XAPIKEY-SERVER-SECRET" from a
// single-key header route and x-api-key="POOLKEY-SECRET-1" from a pooled one.
// Authorization stayed behind only because net/http strips that one header name
// across a domain change, which is an accident of the standard library and no
// help at all on a same-domain redirect.
//
// Every test here asserts the property where it is observable — what the
// REDIRECT TARGET sees, and what the caller gets back — and is deliberately
// blind to how the refusal is implemented.
// ---------------------------------------------------------------------------

// redirectTarget stands in for wherever a redirect points. It records every
// request that reaches it, so "did anything at all go there" and "did a
// credential go with it" are the same recording.
type redirectTarget struct {
	mu   sync.Mutex
	seen []http.Header
}

func (rt *redirectTarget) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.mu.Lock()
		rt.seen = append(rt.seen, r.Header.Clone())
		rt.mu.Unlock()
		_, _ = io.WriteString(w, `{"exfiltrated":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (rt *redirectTarget) observed() []http.Header {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]http.Header, len(rt.seen))
	copy(out, rt.seen)
	return out
}

func (rt *redirectTarget) hits() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.seen)
}

// credentialish flattens an observed header set into "name: value" lines
// carrying anything that looks like a credential this suite plants — the
// gateway's own keys are spelled "gateway-...-not-real" and a caller's are
// spelled with credStripCallerMarker. Reporting the actual lines is what makes
// a failure name the leak rather than merely count it.
func credentialish(headers []http.Header) []string {
	var out []string
	for _, h := range headers {
		for k, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, "not-real") || strings.Contains(v, credStripCallerMarker) {
					out = append(out, k+": "+v)
				}
			}
		}
	}
	return out
}

// redirectingUpstream answers every request with a 302 to loc and counts its own
// arrivals, which is how a redirect CHAIN is distinguished from a single hop.
func redirectingUpstream(t *testing.T, loc func() string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, loc(), http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// callerCredential is what a caller presents on every request in this file. On
// an injecting mode it is stripped before the first hop; on passthrough it is
// carried to the provider on purpose. Neither mode may replay it to a redirect
// target.
func callerCredential() http.Header {
	return http.Header{"Authorization": []string{"Bearer " + credStripCallerMarker}}
}

// TestForward_RedirectToAnotherHostIsRefusedAndReplaysNoCredential is C2.
//
// The redirect target here is a different origin on 127.0.0.1, which is the
// STRICTLY WORSE case than the localhost/127.0.0.1 pair the finding was measured
// on: net/http compares hostnames, not origins, so it considers these the same
// domain and would replay Authorization here as well as x-api-key. If the
// gateway is safe against this, it is safe against the measured one.
//
// The whole mode table runs, passthrough included, because the fix has no
// per-mode exception and a per-mode exception is what would have to be argued
// about later.
func TestForward_RedirectToAnotherHostIsRefusedAndReplaysNoCredential(t *testing.T) {
	t.Parallel()
	for _, m := range credStripModes() {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			target := &redirectTarget{}
			tsrv := target.serve(t)
			want := tsrv.URL + "/steal"
			provider, providerHits := redirectingUpstream(t, func() string { return want })

			srv := credStripServer(t, provider.URL, m.route(t))
			rec := serve(srv, http.MethodGet, "/x/v1/models", callerCredential())

			if n := target.hits(); n != 0 {
				t.Fatalf("the redirect target received %d requests, want 0; it observed %v\n"+
					"a nil CheckRedirect makes the gateway replay the credential it holds to a host of the upstream's choosing",
					n, credentialish(target.observed()))
			}
			if leaks := credentialish(target.observed()); len(leaks) > 0 {
				t.Fatalf("credential material reached the redirect target on auth %s: %v", m.name, leaks)
			}
			if got := providerHits.Load(); got != 1 {
				t.Errorf("provider saw %d requests, want exactly 1", got)
			}
			if rec.Code != http.StatusFound {
				t.Fatalf("gateway status = %d, want 302 relayed to the caller (body %q): "+
					"the gateway must hand the client the redirect, not follow it holding a server key",
					rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != want {
				t.Errorf("Location = %q, want the upstream's own %q: the caller must be able to decide for itself", got, want)
			}
		})
	}
}

// TestForward_SameHostRedirectIsRefusedToo pins the DECISION, not an accident:
// there is no same-host exception, so no request ever has its destination
// chosen by the upstream.
//
// A same-host exception would buy nothing and cost the property. The credential
// would survive (same host), the round trips would still multiply, and the
// "same host" comparison would itself become a security control living in the
// forwarder — which is the shape of the bug being fixed.
func TestForward_SameHostRedirectIsRefusedToo(t *testing.T) {
	t.Parallel()
	moved := &redirectTarget{}
	var firstHop atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models-moved" {
			moved.mu.Lock()
			moved.seen = append(moved.seen, r.Header.Clone())
			moved.mu.Unlock()
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		firstHop.Add(1)
		http.Redirect(w, r, "/v1/models-moved", http.StatusFound)
	}))
	defer provider.Close()

	srv := credStripServer(t, provider.URL, Route{
		Name: "same-host", Auth: AuthHeaderInject, KeyHeader: "x-api-key",
		KeyFile: writeKeyFile(t, t.TempDir(), "k.key", "gateway-same-host-not-real\n"),
	})
	rec := serve(srv, http.MethodGet, "/x/v1/models", callerCredential())

	if n := moved.hits(); n != 0 {
		t.Fatalf("the same-host redirect was followed: the moved path saw %d requests carrying %v, want 0",
			n, credentialish(moved.observed()))
	}
	if got := firstHop.Load(); got != 1 {
		t.Errorf("first hop saw %d requests, want exactly 1", got)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want the 302 relayed (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/v1/models-moved" {
		t.Errorf("Location = %q, want %q", got, "/v1/models-moved")
	}
}

// TestForward_RedirectChainCostsExactlyOneUpstreamRoundTripAndOneCharge is M1.
//
// A chain inside ONE Forward was one caller request against the cap and up to
// ten upstream round trips against the provider — the cap counted the wrong
// thing entirely. Refusing to follow makes the two the same number, which is
// the only relationship a budget can be written against.
func TestForward_RedirectChainCostsExactlyOneUpstreamRoundTripAndOneCharge(t *testing.T) {
	t.Parallel()
	var hop atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hop.Add(1)
		// A fresh path each time, so nothing but the refusal can stop the walk.
		http.Redirect(w, r, "/v1/hop-"+strconv.FormatInt(n, 10), http.StatusFound)
	}))
	defer provider.Close()

	srv := rotServer(t, rotatingConfig(t, "mm", provider.URL, []string{"k0-not-real"},
		&RotationConfig{Budget: Budget{Window: time.Hour, Requests: 5, SoftRatio: 1, EstimateTokens: 1}}),
		nil, nil)

	if got := serve(srv, http.MethodGet, "/mm/v1/chat", nil).Code; got != http.StatusFound {
		t.Fatalf("status = %d, want the first 302 relayed", got)
	}
	if got := hop.Load(); got != 1 {
		t.Fatalf("one caller request produced %d upstream round trips, want 1: "+
			"a chain followed inside a single Forward is charged once and spends many", got)
	}
	tokens, requests, errs := chargedTokens(storeFor(t, srv, "mm"), "mm")
	if requests != 1 || tokens != 0 || errs != 0 {
		t.Errorf("charged requests=%d tokens=%d errors=%d, want 1/0/0: "+
			"a relayed 3xx is one served request that generated no completion", requests, tokens, errs)
	}
}

// TestAudit_ProxyLineNamesTheHostActuallyContacted is H1's other half.
//
// The line recorded rt.Route.Upstream — the CONFIGURED host — so a gateway that
// had just been driven to a host in no configuration recorded that it had gone
// where it was told. upstream is intent; upstream_host is fact; a line where
// they disagree is the signature.
func TestAudit_ProxyLineNamesTheHostActuallyContacted(t *testing.T) {
	t.Parallel()

	t.Run("plain request", func(t *testing.T) {
		t.Parallel()
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"usage":{"total_tokens":7}}`)
		}))
		defer provider.Close()
		want := mustHost(t, provider.URL)

		var audit bytes.Buffer
		srv := rotServer(t, rotatingConfig(t, "mm", provider.URL, []string{"k0-not-real"}, nil), nil, &audit)
		if got := serve(srv, http.MethodGet, "/mm/v1/chat", nil).Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}

		line := auditLines(t, &audit)[0]
		if got := line["upstream_host"]; got != want {
			t.Errorf("upstream_host = %v, want %q — the host actually contacted, read back from the response", got, want)
		}
		if got := line["upstream"]; got != provider.URL {
			t.Errorf("upstream = %v, want the configured %q; both are recorded on purpose", got, provider.URL)
		}
		if s, _ := line["upstream_host"].(string); strings.Contains(s, "://") {
			t.Errorf("upstream_host = %q looks like the configured URL, not a host: "+
				"it must be read from the request net/http actually sent", s)
		}
	})

	t.Run("refused redirect", func(t *testing.T) {
		t.Parallel()
		target := &redirectTarget{}
		tsrv := target.serve(t)
		provider, _ := redirectingUpstream(t, func() string { return tsrv.URL + "/steal" })
		wantHost, attackerHost := mustHost(t, provider.URL), mustHost(t, tsrv.URL)

		var audit bytes.Buffer
		srv := rotServer(t, rotatingConfig(t, "mm", provider.URL, []string{"k0-not-real"}, nil), nil, &audit)
		if got := serve(srv, http.MethodGet, "/mm/v1/chat", nil).Code; got != http.StatusFound {
			t.Fatalf("status = %d, want the 302 relayed", got)
		}

		line := auditLines(t, &audit)[0]
		if got := line["upstream_host"]; got != wantHost {
			t.Errorf("upstream_host = %v, want %q (the provider); it must never be %q", got, wantHost, attackerHost)
		}
		if got := line["error"]; got != "redirect_not_followed" {
			t.Errorf("error = %v, want %q: a refused redirect is a distinct, countable outcome", got, "redirect_not_followed")
		}
	})
}

// mustHost is the host:port half of a test server URL.
func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Host
}

// TestForward_PassthroughRefusesRedirectsWithoutLosingItsOwnPurpose states the
// passthrough decision explicitly, because passthrough is the one mode exempt
// from the credential strip and an exemption there would be easy to assume.
//
// It is NOT exempt from the redirect refusal. The credential replayed on a
// passthrough redirect is the CALLER's, sent to a host the caller never chose,
// and the SSRF and spend arguments are indifferent to whose key is on the wire.
// The second half is the positive control: refusing redirects must not stop
// passthrough carrying the caller's credential to the provider it was pointed
// at, which is the entire reason the mode exists.
func TestForward_PassthroughRefusesRedirectsWithoutLosingItsOwnPurpose(t *testing.T) {
	t.Parallel()

	target := &redirectTarget{}
	tsrv := target.serve(t)
	redirecting, _ := redirectingUpstream(t, func() string { return tsrv.URL + "/steal" })

	ptRoute := func() Route { return Route{Name: "pt", Auth: AuthPassthrough} }

	rec := serve(credStripServer(t, redirecting.URL, ptRoute()), http.MethodGet, "/x/v1/models", callerCredential())
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want the 302 relayed to the caller", rec.Code)
	}
	if n := target.hits(); n != 0 {
		t.Fatalf("passthrough followed the redirect: the target saw %d requests carrying %v, want 0",
			n, credentialish(target.observed()))
	}

	honest, seen := credStripUpstream(t)
	observed := credStripCall(t, credStripServer(t, honest.URL, ptRoute()), seen,
		map[string]string{"Authorization": "Bearer " + credStripCallerMarker})
	if got := observed.Get("Authorization"); got != "Bearer "+credStripCallerMarker {
		t.Errorf("upstream Authorization = %q, want the caller's own credential carried through: "+
			"refusing redirects must not break the mode that exists to carry it", got)
	}
}
