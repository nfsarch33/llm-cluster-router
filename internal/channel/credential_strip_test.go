package channel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// P1/R6 — a caller-supplied credential header must never reach the upstream on
// a mode where the GATEWAY supplies the credential.
//
// forward.go copied every non-hop-by-hop inbound header verbatim, and the only
// deletions anywhere were of "Authorization": bearerInjector overwrote it, and
// leasedInjector deleted it when writing a different header. So a caller could
// present X-Api-Key (Anthropic, Exa, Tavily), Api-Key (Azure OpenAI),
// X-Goog-Api-Key (Google) or Cookie and the provider received it ALONGSIDE the
// gateway key — on inject, on header, single-key and pooled alike.
//
// These tests assert the property where it is observable: what the UPSTREAM
// sees. They are deliberately blind to how the strip is implemented.
// ---------------------------------------------------------------------------

// credStripCallerMarker appears in every value a CALLER sends here and in no
// value the gateway writes, so "did the caller bytes reach the upstream" is one
// substring scan over the whole observed header set rather than a per-header
// allow-list that a renamed copy could slip past.
const credStripCallerMarker = "caller-not-real"

// credStripProbe is one credential-bearing header a caller might present.
//
// This is a PROBE table, not the production table. The production deny-set
// living elsewhere is the point: adding a provider header must be a data edit.
type credStripProbe struct {
	header string
	value  string
	// hopByHop headers are dropped by RFC 9110 section 7.6.1 on EVERY mode,
	// passthrough included, so the passthrough expectation inverts for them.
	hopByHop bool
}

var credStripProbes = []credStripProbe{
	{header: "Authorization", value: "Bearer " + credStripCallerMarker},
	{header: "Proxy-Authorization", value: "Basic " + credStripCallerMarker, hopByHop: true},
	{header: "X-Api-Key", value: "sk-ant-" + credStripCallerMarker},
	{header: "Api-Key", value: "azure-" + credStripCallerMarker},
	{header: "X-Goog-Api-Key", value: "goog-" + credStripCallerMarker},
	{header: "Cookie", value: "session=" + credStripCallerMarker},
	// Not credentials — spend direction. On an inject mode the gateway holds
	// the key, so a caller that sets these chooses which organisation or
	// project inside the gateway's own account is billed.
	{header: "OpenAI-Organization", value: "org-" + credStripCallerMarker},
	{header: "OpenAI-Project", value: "proj_" + credStripCallerMarker},
}

// credStripUpstream is a recording provider. It returns an accessor rather than
// the slice, so nothing can read the recording without the mutex.
func credStripUpstream(t *testing.T) (*httptest.Server, func() []http.Header) {
	t.Helper()
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(srv.Close)
	return srv, func() []http.Header {
		mu.Lock()
		defer mu.Unlock()
		out := make([]http.Header, len(seen))
		copy(out, seen)
		return out
	}
}

// credStripCall sends one request through the gateway and returns the header
// set the upstream observed FOR THAT REQUEST.
func credStripCall(t *testing.T, srv *Server, seen func() []http.Header, set map[string]string) http.Header {
	t.Helper()
	before := len(seen())
	req := httptest.NewRequest(http.MethodGet, "/x/v1/models", nil)
	for k, v := range set {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("gateway status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	got := seen()
	if len(got) != before+1 {
		t.Fatalf("upstream saw %d requests, want %d", len(got), before+1)
	}
	return got[len(got)-1]
}

// credStripLeaks reports every observed header carrying the caller bytes, under
// ANY name — a strip that merely renames the header is still a leak.
func credStripLeaks(h http.Header) []string {
	var out []string
	for k, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, credStripCallerMarker) {
				out = append(out, k+": "+v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// credStripMode is one auth mode under test, carrying the credential the
// GATEWAY is expected to write so the tests also prove the strip did not break
// injection itself.
type credStripMode struct {
	name string
	// route is a func because each mode needs its own t.TempDir key files.
	route func(t *testing.T) Route
	// gwHeader/gwPrefix describe the gateway credential. Empty on passthrough,
	// which writes nothing.
	gwHeader string
	gwPrefix string
	// forwardsCaller is true only for passthrough: that mode exists precisely
	// to carry the client credential to the provider.
	forwardsCaller bool
}

func credStripModes() []credStripMode {
	return []credStripMode{
		{
			name: "inject/single-key",
			route: func(t *testing.T) Route {
				return Route{Name: "single-inject", Auth: AuthInject,
					KeyFile: writeKeyFile(t, t.TempDir(), "k.key", "gateway-single-inject-not-real\n")}
			},
			gwHeader: "Authorization", gwPrefix: "Bearer gateway-",
		},
		{
			name: "inject/pooled",
			route: func(t *testing.T) Route {
				dir := t.TempDir()
				return Route{Name: "pooled-inject", Auth: AuthInject, KeyFiles: []string{
					writeKeyFile(t, dir, "k0.key", "gateway-pool-inject-0-not-real\n"),
					writeKeyFile(t, dir, "k1.key", "gateway-pool-inject-1-not-real\n"),
				}}
			},
			gwHeader: "Authorization", gwPrefix: "Bearer gateway-",
		},
		{
			// The spelling deploy/helixchannel/gateway.example.yml ships.
			name: "header/single-key",
			route: func(t *testing.T) Route {
				return Route{Name: "single-header", Auth: AuthHeaderInject, KeyHeader: "x-api-key",
					KeyFile: writeKeyFile(t, t.TempDir(), "k.key", "gateway-single-header-not-real\n")}
			},
			gwHeader: "X-Api-Key", gwPrefix: "gateway-",
		},
		{
			name: "header/pooled",
			route: func(t *testing.T) Route {
				dir := t.TempDir()
				return Route{Name: "pooled-header", Auth: AuthHeaderInject, KeyHeader: "x-api-key", KeyFiles: []string{
					writeKeyFile(t, dir, "k0.key", "gateway-pool-header-0-not-real\n"),
					writeKeyFile(t, dir, "k1.key", "gateway-pool-header-1-not-real\n"),
				}}
			},
			gwHeader: "X-Api-Key", gwPrefix: "gateway-",
		},
		{
			name:           "passthrough",
			route:          func(*testing.T) Route { return Route{Name: "pt", Auth: AuthPassthrough} },
			forwardsCaller: true,
		},
	}
}

func credStripServer(t *testing.T, upstream string, r Route) *Server {
	t.Helper()
	r.Prefix, r.Upstream, r.Enabled = "/x/", upstream, true
	return rotServer(t, &Config{Listen: "127.0.0.1:0", Routes: []Route{r}}, nil, nil)
}

// TestForward_CredentialInjectingModesStripEveryCallerCredentialHeader is the
// P1/R6 regression: one subtest per header per auth mode, each asserting the
// upstream never observes the caller value.
func TestForward_CredentialInjectingModesStripEveryCallerCredentialHeader(t *testing.T) {
	t.Parallel()
	for _, m := range credStripModes() {
		if m.forwardsCaller {
			continue
		}
		t.Run(m.name, func(t *testing.T) {
			up, seen := credStripUpstream(t)
			srv := credStripServer(t, up.URL, m.route(t))
			for _, p := range credStripProbes {
				t.Run(p.header, func(t *testing.T) {
					observed := credStripCall(t, srv, seen, map[string]string{p.header: p.value})
					if leaks := credStripLeaks(observed); len(leaks) > 0 {
						t.Errorf("caller %s reached the upstream on auth %s: %v\n"+
							"a mode where the gateway supplies the credential must strip the caller one",
							p.header, m.name, leaks)
					}
					if got := observed.Get(m.gwHeader); !strings.HasPrefix(got, m.gwPrefix) {
						t.Errorf("upstream %s = %q, want the gateway credential with prefix %q; "+
							"stripping the caller header must not also drop the injected key",
							m.gwHeader, got, m.gwPrefix)
					}
				})
			}
		})
	}
}

// TestForward_PassthroughStillCarriesTheCallerOwnCredential is the counter-test.
// passthrough exists so a client session token terminates at the provider; a
// deny-set that also fired there would break the mode outright.
func TestForward_PassthroughStillCarriesTheCallerOwnCredential(t *testing.T) {
	t.Parallel()
	var pt credStripMode
	for _, m := range credStripModes() {
		if m.forwardsCaller {
			pt = m
		}
	}
	up, seen := credStripUpstream(t)
	srv := credStripServer(t, up.URL, pt.route(t))
	for _, p := range credStripProbes {
		t.Run(p.header, func(t *testing.T) {
			observed := credStripCall(t, srv, seen, map[string]string{p.header: p.value})
			leaks := credStripLeaks(observed)
			if p.hopByHop {
				if len(leaks) > 0 {
					t.Errorf("hop-by-hop %s survived to the upstream: %v (RFC 9110 section 7.6.1)", p.header, leaks)
				}
				return
			}
			if len(leaks) == 0 {
				t.Errorf("auth passthrough dropped the caller %s; that mode forwards the client credential "+
					"by definition, so the deny-set must not apply to it", p.header)
			}
		})
	}
}

// TestForward_StripsTheRouteOwnConfiguredKeyHeaderWhateverItIsNamed pins the
// clause that cannot be a static list: an operator may name any header.
func TestForward_StripsTheRouteOwnConfiguredKeyHeaderWhateverItIsNamed(t *testing.T) {
	t.Parallel()
	up, seen := credStripUpstream(t)
	srv := credStripServer(t, up.URL, Route{
		Name: "custom-header", Auth: AuthHeaderInject, KeyHeader: "X-Tenant-Key",
		KeyFile: writeKeyFile(t, t.TempDir(), "k.key", "gateway-custom-header-not-real\n"),
	})
	observed := credStripCall(t, srv, seen, map[string]string{"X-Tenant-Key": "tenant-" + credStripCallerMarker})
	if leaks := credStripLeaks(observed); len(leaks) > 0 {
		t.Errorf("caller value survived in the route own key_header: %v", leaks)
	}
	if got := observed.Values("X-Tenant-Key"); len(got) != 1 || got[0] != "gateway-custom-header-not-real" {
		t.Errorf("upstream X-Tenant-Key = %v, want exactly one gateway credential", got)
	}
}

// TestCallerCredentialHeaders_IsABlocklistAndCannotBeComplete is the honest
// bound on everything above.
//
// The deny-set forwards by default and strips by exception, so its guarantee is
// "not through THESE headers", never "not at all". This pins that as a fact
// rather than leaving it to be discovered: an unlisted spend-direction header
// reaches the upstream on an inject mode, exactly as Openai-Organization did
// until it was listed. It exists so a reader who wants the stronger guarantee
// has to change the construction, not add another name.
func TestCallerCredentialHeaders_IsABlocklistAndCannotBeComplete(t *testing.T) {
	t.Parallel()
	up, seen := credStripUpstream(t)
	srv := credStripServer(t, up.URL, Route{
		Name: "blocklist", Auth: AuthInject,
		KeyFile: writeKeyFile(t, t.TempDir(), "k.key", "gateway-blocklist-not-real\n"),
	})
	// A plausible next provider header that nobody has listed yet.
	const unlisted = "X-Billing-Account"
	observed := credStripCall(t, srv, seen, map[string]string{unlisted: "acct-" + credStripCallerMarker})
	if leaks := credStripLeaks(observed); len(leaks) == 0 {
		t.Errorf("the caller %s did NOT reach the upstream. If that is because the name was added to "+
			"callerCredentialHeaders, pick another unlisted one; if it is because the deny-set became an "+
			"allow-list, delete this test and the paragraph in forward.go that it pins", unlisted)
	}
	if isCallerCredential(unlisted, "") {
		t.Errorf("isCallerCredential(%q) = true; this test needs an unlisted header to be about anything", unlisted)
	}
}

// TestForward_NonCredentialHeadersStillReachTheUpstream is the over-stripping
// guard. The gateway is a transparent proxy for everything that is not a
// credential; a deny-set that swallowed content negotiation or idempotency keys
// would break real clients while looking secure.
func TestForward_NonCredentialHeadersStillReachTheUpstream(t *testing.T) {
	t.Parallel()
	up, seen := credStripUpstream(t)
	srv := credStripServer(t, up.URL, Route{
		Name: "transparent", Auth: AuthInject,
		KeyFile: writeKeyFile(t, t.TempDir(), "k.key", "gateway-transparent-not-real\n"),
	})
	want := map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "text/event-stream",
		"Idempotency-Key": "req-0001",
		"X-Request-Id":    "trace-0001",
		"Anthropic-Beta":  "prompt-caching-2024-07-31",
	}
	observed := credStripCall(t, srv, seen, want)
	for k, v := range want {
		if got := observed.Get(k); got != v {
			t.Errorf("upstream %s = %q, want %q: only credential headers may be stripped", k, got, v)
		}
	}
}

// TestCallerCredentialHeaders_CoversTheDocumentedMinimumCaseInsensitively pins
// the deny-set as DATA, and pins the matching as case-insensitive.
//
// The names are asserted through the predicate rather than by comparing the
// slice, so the table may be reordered or extended freely — only shrinking it
// below the documented minimum fails.
func TestCallerCredentialHeaders_CoversTheDocumentedMinimumCaseInsensitively(t *testing.T) {
	t.Parallel()
	minimum := []string{
		"aUtHoRiZaTiOn",
		"PROXY-AUTHORIZATION",
		"x-api-key",
		"API-Key",
		"X-GOOG-api-KEY",
		"cookie",
		"openai-organization",
		"OPENAI-PROJECT",
	}
	for _, name := range minimum {
		if !isCallerCredential(name, "") {
			t.Errorf("isCallerCredential(%q, %q) = false; the deny-set must cover it, case-insensitively", name, "")
		}
	}
	if isCallerCredential("Content-Type", "") {
		t.Error("isCallerCredential(Content-Type) = true; the gateway must stay a transparent proxy for non-credential headers")
	}
	if !isCallerCredential("X-Tenant-Key", "x-tenant-key") {
		t.Error("isCallerCredential(X-Tenant-Key, x-tenant-key) = false; a route own key_header is credential-bearing whatever it is named")
	}
	if isCallerCredential("X-Tenant-Key", "") {
		t.Error("isCallerCredential(X-Tenant-Key, no key_header) = true; only the configured key_header may extend the deny-set")
	}
}
