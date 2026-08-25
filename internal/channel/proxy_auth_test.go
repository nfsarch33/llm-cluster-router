package channel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Fixtures
//
// Every credential here is resolved through a stub SecretProvider rather than
// through the environment, so nothing in this file needs t.Setenv and every
// test can run in parallel.
// ---------------------------------------------------------------------------

const (
	gwAuthRouteKeyRef = "env:GWAUTH_ROUTE_KEY"
	gwAuthTokenRef    = "env:GWAUTH_TOKEN"
	gwAuthConnRef     = "env:GWAUTH_CONNECT_TOKEN"

	gwAuthRouteKey = "server-side-route-key-not-real"
	gwAuthToken    = "gateway-token-not-real"
	gwAuthConnTok  = "connect-token-not-real"

	// TEST-NET-3, so a stray dial can never leave the machine.
	gwAuthRemotePeer = "203.0.113.7:44100"
	gwAuthLoopback   = "127.0.0.1:44100"
	gwAuthLoopback8  = "127.9.9.9:44100"
	gwAuthLoopbackV6 = "[::1]:44100"

	gwAuthChallenge = `HelixChannel realm="helixchannel-gateway", header="X-HelixChannel-Token"`
)

// gwAuthUpstream is a mock provider that counts what actually reached it. The
// count is the assertion that matters on a refusal: a 401 that still contacted
// the upstream has already spent the key it was meant to protect.
type gwAuthUpstream struct {
	mu   sync.Mutex
	hits int
	last http.Header
}

func (u *gwAuthUpstream) record(h http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hits++
	u.last = h.Clone()
}

func (u *gwAuthUpstream) seen() (int, http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits, u.last
}

func newGWAuthUpstream(t *testing.T) (*httptest.Server, *gwAuthUpstream) {
	t.Helper()
	probe := &gwAuthUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probe.record(r.Header)
		_, _ = io.WriteString(w, `{"object":"list"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, probe
}

// gwAuthSecrets answers the three references this file uses and nothing else,
// so a typo in a ref is a resolution failure rather than a silent success.
func gwAuthSecrets(gatewayToken, connectToken string) *fakeProvider {
	return refProvider(map[string]string{
		gwAuthRouteKeyRef: gwAuthRouteKey,
		gwAuthTokenRef:    gatewayToken,
		gwAuthConnRef:     connectToken,
	})
}

// gwAuthConfig is one enabled inject route plus the supplied gateway_auth block.
func gwAuthConfig(upstream string, ga GatewayAuthConfig) *Config {
	return &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{{
			Name: "mm", Prefix: "/mm/", Upstream: upstream,
			Auth: AuthInject, KeyRef: gwAuthRouteKeyRef, Enabled: true,
		}},
		GatewayAuth: ga,
	}
}

func gwAuthServer(t *testing.T, cfg *Config, audit io.Writer) *Server {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if audit == nil {
		audit = io.Discard
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(audit),
		WithSecretProvider(gwAuthSecrets(gwAuthToken, gwAuthConnTok)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// tokenExempt is the default posture: a token, loopback exempt.
func tokenExempt() GatewayAuthConfig { return GatewayAuthConfig{TokenRef: gwAuthTokenRef} }

// tokenEverywhere requires the token from loopback too.
func tokenEverywhere() GatewayAuthConfig {
	no := false
	return GatewayAuthConfig{TokenRef: gwAuthTokenRef, ExemptLoopback: &no}
}

// gwAuthCall drives the handler with an explicit peer address, because the
// loopback exemption is a decision about the peer and httptest.NewRequest's
// default RemoteAddr would make every test accidentally non-loopback.
func gwAuthCall(t *testing.T, srv *Server, peer string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mm/v1/models", strings.NewReader(`{"model":"x"}`))
	req.RemoteAddr = peer
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func gwAuthErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error  string   `json:"error"`
		Header string   `json:"header"`
		Routes []string `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode refusal body: %v (%q)", err, rec.Body.String())
	}
	if len(body.Routes) != 0 {
		t.Errorf("refusal body listed routes %v; an unauthenticated caller must not be handed the route table", body.Routes)
	}
	if body.Header != GatewayTokenHeader {
		t.Errorf("refusal body header = %q, want %q: a refused caller has no other way to learn where the token goes", body.Header, GatewayTokenHeader)
	}
	return body.Error
}

// ---------------------------------------------------------------------------
// The defect: an anonymous caller reached the provider with the gateway's key
// ---------------------------------------------------------------------------

// TestProxyAuth_AnonymousNonLoopbackCallerIsRefusedBeforeTheUpstream is the
// regression test for C1. Against the live pilot gateway an anonymous POST with
// no headers at all reached the provider's production load balancer with the
// server-held key injected; the provider's own request-id headers came back.
//
// The upstream hit count is the assertion that matters. A 401 that still
// forwarded would have spent the key it exists to protect.
func TestProxyAuth_AnonymousNonLoopbackCallerIsRefusedBeforeTheUpstream(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)

	rec := gwAuthCall(t, srv, gwAuthRemotePeer, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != gwAuthChallenge {
		t.Errorf("WWW-Authenticate = %q, want %q", got, gwAuthChallenge)
	}
	if got := gwAuthErrorCode(t, rec); got != string(refusalTokenRequired) {
		t.Errorf("error = %q, want %q", got, refusalTokenRequired)
	}
	if hits, _ := probe.seen(); hits != 0 {
		t.Errorf("upstream was contacted %d times; an unauthenticated caller must be refused before any upstream call", hits)
	}
	if strings.Contains(rec.Body.String(), gwAuthToken) || strings.Contains(rec.Body.String(), gwAuthRouteKey) {
		t.Error("refusal body leaked a credential")
	}
}

// TestProxyAuth_ValidTokenIsServedAndNeverReachesTheUpstream covers the other
// half: the token admits the caller, and then stops. It authenticates this hop
// and has no meaning at the provider, so forwarding it would hand the gateway's
// own admission credential to a third party.
func TestProxyAuth_ValidTokenIsServedAndNeverReachesTheUpstream(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)

	rec := gwAuthCall(t, srv, gwAuthRemotePeer, map[string]string{GatewayTokenHeader: gwAuthToken})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	hits, got := probe.seen()
	if hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	if v := got.Get(GatewayTokenHeader); v != "" {
		t.Errorf("upstream received %s = %q; the gateway token must not leave the gateway", GatewayTokenHeader, v)
	}
	if v := got.Get("Authorization"); v != "Bearer "+gwAuthRouteKey {
		t.Errorf("upstream Authorization = %q, want the server-held route key", v)
	}
}

// TestProxyAuth_WrongTokenIsRefusedAsInvalidNotAsMissing keeps the two refusals
// distinct. "You sent nothing" is an unconfigured client; "you sent the wrong
// thing" is a stale credential or a hostile caller, and an operator triages them
// differently.
func TestProxyAuth_WrongTokenIsRefusedAsInvalidNotAsMissing(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)

	rec := gwAuthCall(t, srv, gwAuthRemotePeer, map[string]string{
		GatewayTokenHeader: gwAuthToken + "-tampered",
	})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := gwAuthErrorCode(t, rec); got != string(refusalTokenInvalid) {
		t.Errorf("error = %q, want %q", got, refusalTokenInvalid)
	}
	if hits, _ := probe.seen(); hits != 0 {
		t.Errorf("upstream hits = %d, want 0", hits)
	}
}

// TestProxyAuth_LoopbackIsExemptButCannotBeClaimedByAHeader is the spoofing
// case. The exemption is what keeps every existing local client working at
// cutover, so it is also the thing an attacker would most like to claim: if any
// forwarded-for header were honoured, the exemption would be a bypass rather
// than an exemption.
func TestProxyAuth_LoopbackIsExemptButCannotBeClaimedByAHeader(t *testing.T) {
	t.Parallel()
	upstream, _ := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)

	served := []struct{ name, peer string }{
		{"ipv4 loopback", gwAuthLoopback},
		{"anywhere in 127.0.0.0/8", gwAuthLoopback8},
		{"ipv6 loopback", gwAuthLoopbackV6},
	}
	for _, tc := range served {
		t.Run("served/"+tc.name, func(t *testing.T) {
			if rec := gwAuthCall(t, srv, tc.peer, nil); rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200: a %s peer is exempt and must keep working unchanged", rec.Code, tc.name)
			}
		})
	}

	spoofs := []struct{ name, header, value string }{
		{"x-forwarded-for", "X-Forwarded-For", "127.0.0.1"},
		{"x-forwarded-for chain", "X-Forwarded-For", "127.0.0.1, 203.0.113.7"},
		{"x-real-ip", "X-Real-Ip", "127.0.0.1"},
		{"forwarded", "Forwarded", `for="127.0.0.1"`},
		{"x-forwarded-for v6", "X-Forwarded-For", "::1"},
	}
	for _, tc := range spoofs {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			rec := gwAuthCall(t, srv, gwAuthRemotePeer, map[string]string{tc.header: tc.value})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s claimed loopback from a non-loopback peer", rec.Code, tc.header)
			}
			if got := gwAuthErrorCode(t, rec); got != string(refusalTokenRequired) {
				t.Errorf("error = %q, want %q", got, refusalTokenRequired)
			}
		})
	}
}

// TestProxyAuth_ExemptLoopbackFalseRequiresTheTokenFromLoopbackToo proves the
// exemption is genuinely configurable rather than hardcoded — it is the setting
// an operator needs when a same-host terminator is the thing making the
// connection.
func TestProxyAuth_ExemptLoopbackFalseRequiresTheTokenFromLoopbackToo(t *testing.T) {
	t.Parallel()
	upstream, _ := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)

	if got := srv.ProxyAuthMode(); got != ProxyAuthToken {
		t.Fatalf("ProxyAuthMode() = %q, want %q", got, ProxyAuthToken)
	}
	if rec := gwAuthCall(t, srv, gwAuthLoopback, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous loopback status = %d, want 401 under exempt_loopback: false", rec.Code)
	}
	rec := gwAuthCall(t, srv, gwAuthLoopback, map[string]string{GatewayTokenHeader: gwAuthToken})
	if rec.Code != http.StatusOK {
		t.Errorf("authenticated loopback status = %d, want 200", rec.Code)
	}
}

// TestProxyAuth_APresentedTokenIsCheckedEvenFromLoopback pins the asymmetry the
// documentation states: the exemption waives HAVING to present a token, not the
// check on one that was presented. A local client carrying a stale token fails
// on the bench rather than the day it is moved off the box.
func TestProxyAuth_APresentedTokenIsCheckedEvenFromLoopback(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)

	rec := gwAuthCall(t, srv, gwAuthLoopback, map[string]string{GatewayTokenHeader: "stale-token"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := gwAuthErrorCode(t, rec); got != string(refusalTokenInvalid) {
		t.Errorf("error = %q, want %q", got, refusalTokenInvalid)
	}
	if hits, _ := probe.seen(); hits != 0 {
		t.Errorf("upstream hits = %d, want 0", hits)
	}
}

// TestProxyAuth_ABlankPresentedTokenIsNeverCompared closes the
// whitespace-credential class on this new surface before it can reappear.
//
// subtle.ConstantTimeCompare([]byte(""), []byte("")) returns 1. A server in a
// token posture whose token were empty would therefore AUTHORISE a caller that
// sent an empty header, which is an unauthenticated funded relay. The guard is
// the early return on a blank presented value, and it is load-bearing twice:
// here, where it is the only thing between an empty header and an authorised
// request, and on a correctly configured server, where it is what reports an
// absent credential as gateway_token_required rather than gateway_token_invalid.
func TestProxyAuth_ABlankPresentedTokenIsNeverCompared(t *testing.T) {
	t.Parallel()
	blanks := []struct{ name, header string }{
		{"absent", ""},
		{"empty", ""},
		{"one space", " "},
		{"tab", "\t"},
		{"newline", "\n"},
		{"spaces", "   "},
	}

	// A server that should be impossible to construct: a token posture with no
	// token. NewServer refuses it, so it is built by hand — the point is that
	// authorizeProxy refuses it too, and does not depend on that constructor
	// staying correct.
	empty := &Server{proxyAuth: ProxyAuthToken, proxyToken: ""}
	for _, tc := range blanks {
		t.Run("empty server token/"+tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/mm/v1/models", nil)
			req.RemoteAddr = gwAuthLoopback
			if tc.header != "" {
				req.Header.Set(GatewayTokenHeader, tc.header)
			}
			if got := empty.authorizeProxy(req); got != refusalTokenRequired {
				t.Errorf("authorizeProxy = %q, want %q: an empty configured token must never authorise anybody", got, refusalTokenRequired)
			}
		})
	}

	upstream, _ := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)
	for _, tc := range blanks {
		t.Run("real server token/"+tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.header != "" {
				headers[GatewayTokenHeader] = tc.header
			}
			rec := gwAuthCall(t, srv, gwAuthRemotePeer, headers)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got := gwAuthErrorCode(t, rec); got != string(refusalTokenRequired) {
				t.Errorf("error = %q, want %q: a blank credential is a missing one, not a wrong one", got, refusalTokenRequired)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// TestNewServer_RefusesABlankGatewayToken is the startup half of the same
// property: the blank never gets as far as a request.
func TestNewServer_RefusesABlankGatewayToken(t *testing.T) {
	t.Parallel()
	for _, tc := range blankCredentials {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Listen: "127.0.0.1:0",
				Routes: []Route{{
					Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
					Auth: AuthPassthrough, Enabled: true,
				}},
				GatewayAuth: GatewayAuthConfig{TokenRef: gwAuthTokenRef},
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			_, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard),
				WithSecretProvider(blankProvider(tc.val)))
			if err == nil {
				t.Fatalf("NewServer = nil error with a %s gateway token; an empty token authorises an empty header", tc.name)
			}
			if !errors.Is(err, ErrSecretEmpty) {
				t.Errorf("error = %v, want it to wrap ErrSecretEmpty", err)
			}
			if !strings.Contains(err.Error(), "gateway_auth") {
				t.Errorf("error = %v, want it to name gateway_auth", err)
			}
		})
	}
}

// TestNewServer_RefusesAGatewayTokenThatIsAlsoTheConnectToken enforces the
// separation the design rests on. One secret gating both legs grants every
// holder of a tunnel credential the ability to spend every route key, and
// startup is the only moment anyone would notice.
func TestNewServer_RefusesAGatewayTokenThatIsAlsoTheConnectToken(t *testing.T) {
	t.Parallel()
	build := func(t *testing.T, gatewayToken, connectToken string) error {
		t.Helper()
		cfg := &Config{
			Listen: "127.0.0.1:0",
			Routes: []Route{{
				Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
				Auth: AuthPassthrough, Enabled: true,
			}},
			Connect: ConnectConfig{
				Enabled: true, TokenRef: gwAuthConnRef,
				AllowedHosts: []string{"api.example.invalid:443"},
			},
			GatewayAuth: GatewayAuthConfig{TokenRef: gwAuthTokenRef},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		_, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard),
			WithSecretProvider(gwAuthSecrets(gatewayToken, connectToken)))
		return err
	}

	err := build(t, "one-shared-secret", "one-shared-secret")
	if err == nil {
		t.Fatal("NewServer accepted one secret for both legs; the CONNECT token would then authorise spending every route key")
	}
	if !strings.Contains(err.Error(), "distinct") {
		t.Errorf("error = %v, want it to say the two tokens must be distinct", err)
	}
	if strings.Contains(err.Error(), "one-shared-secret") {
		t.Error("startup error echoed the secret")
	}
	if err := build(t, gwAuthToken, gwAuthConnTok); err != nil {
		t.Errorf("two distinct tokens = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// TestConfigValidate_RefusesAWideBindWithNoGatewayToken is the footgun turned
// into a startup error. "No caller authentication" and "reachable from other
// hosts" are each defensible alone and catastrophic together, and nothing in a
// config, a log line or /healthz used to say which one you had.
func TestConfigValidate_RefusesAWideBindWithNoGatewayToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, listen string
		ga           GatewayAuthConfig
		wantErr      bool
	}{
		{"wildcard v4, no token", "0.0.0.0:14443", GatewayAuthConfig{}, true},
		{"empty host, no token", ":14443", GatewayAuthConfig{}, true},
		{"wildcard v6, no token", "[::]:14443", GatewayAuthConfig{}, true},
		{"routable address, no token", "192.0.2.10:14443", GatewayAuthConfig{}, true},
		{"hostname, no token", "gateway.internal:14443", GatewayAuthConfig{}, true},
		{"loopback v4, no token", "127.0.0.1:14443", GatewayAuthConfig{}, false},
		{"anywhere in 127/8, no token", "127.0.0.53:14443", GatewayAuthConfig{}, false},
		{"loopback v6, no token", "[::1]:14443", GatewayAuthConfig{}, false},
		// A NAME is not proof of a loopback-only bind, "localhost"
		// included: see isLoopbackListen. Deciding it would mean resolving
		// it at startup, and a host file that pointed it at a routable
		// address would silently waive this very rule.
		{"localhost, no token", "localhost:14443", GatewayAuthConfig{}, true},
		{"localhost with a token", "localhost:14443", GatewayAuthConfig{TokenEnv: "GW"}, false},
		{"loopback in an inet_aton spelling, no token", "127.1:14443", GatewayAuthConfig{}, false},
		{"loopback in hex, no token", "0x7f000001:14443", GatewayAuthConfig{}, false},
		{"wildcard with a token", "0.0.0.0:14443", GatewayAuthConfig{TokenFile: "/run/secrets/gw"}, false},
		{"wildcard with token_env", "0.0.0.0:14443", GatewayAuthConfig{TokenEnv: "GW"}, false},
		{"wildcard with token_ref", "0.0.0.0:14443", GatewayAuthConfig{TokenRef: gwAuthTokenRef}, false},
		{"wildcard, explicitly accepted", "0.0.0.0:14443", GatewayAuthConfig{AllowUnauthenticated: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Listen: tc.listen,
				Routes: []Route{{
					Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
					Auth: AuthPassthrough, Enabled: true,
				}},
				GatewayAuth: tc.ga,
			}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want a refusal: %q authenticates nobody and is reachable from other hosts", tc.listen)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "gateway_auth") {
				t.Errorf("error = %v, want it to name gateway_auth", err)
			}
		})
	}
}

// TestConfigValidate_RefusesContradictoryGatewayAuth refuses rather than
// resolves: each of these has two plausible readings, and silently picking one
// is how an operator ends up with the posture they did not choose.
func TestConfigValidate_RefusesContradictoryGatewayAuth(t *testing.T) {
	t.Parallel()
	no := false
	cases := map[string]struct {
		ga   GatewayAuthConfig
		want string
	}{
		"token and allow_unauthenticated": {
			GatewayAuthConfig{TokenRef: gwAuthTokenRef, AllowUnauthenticated: true},
			"allow_unauthenticated must not be set together with a token source",
		},
		"exempt_loopback false with no token": {
			GatewayAuthConfig{ExemptLoopback: &no},
			"exempt_loopback: false requires a token source",
		},
		"malformed token_ref": {
			GatewayAuthConfig{TokenRef: "vault:/nope"},
			"gateway_auth",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{
				Listen: "127.0.0.1:0",
				Routes: []Route{{
					Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
					Auth: AuthPassthrough, Enabled: true,
				}},
				GatewayAuth: tc.ga,
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestGatewayAuthConfig_ModeIsDerivedFromTheConfiguration pins the derivation.
// The posture is reported in three places — the startup banner, the
// --print-routes envelope and /healthz — and all three read this one function,
// so what the gateway says it does cannot drift from what it does.
func TestGatewayAuthConfig_ModeIsDerivedFromTheConfiguration(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	cases := []struct {
		name string
		ga   GatewayAuthConfig
		want ProxyAuthMode
	}{
		{"nothing configured", GatewayAuthConfig{}, ProxyAuthLoopbackOnly},
		{"explicitly open", GatewayAuthConfig{AllowUnauthenticated: true}, ProxyAuthOpen},
		{"token, exemption implied", GatewayAuthConfig{TokenRef: gwAuthTokenRef}, ProxyAuthTokenLoopbackExempt},
		{"token, exemption explicit", GatewayAuthConfig{TokenEnv: "GW", ExemptLoopback: &yes}, ProxyAuthTokenLoopbackExempt},
		{"token, no exemption", GatewayAuthConfig{TokenFile: "/run/secrets/gw", ExemptLoopback: &no}, ProxyAuthToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ga.Mode(); got != tc.want {
				t.Errorf("Mode() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestExampleConfig_ShipsAGatewayToken guards the deployment contract. The
// shipped example binds a wildcard address because that is what a container
// needs, which makes it precisely the file that must not demonstrate an
// unauthenticated proxy leg.
func TestExampleConfig_ShipsAGatewayToken(t *testing.T) {
	t.Parallel()
	const path = "../../deploy/helixchannel/gateway.example.yml"
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", path, err)
	}
	if !cfg.GatewayAuth.hasToken() {
		t.Fatal("the example config names no gateway token; the one file operators copy must not demonstrate an unauthenticated proxy leg")
	}
	if got := cfg.GatewayAuth.Mode(); got != ProxyAuthTokenLoopbackExempt {
		t.Errorf("example proxy_auth = %q, want %q", got, ProxyAuthTokenLoopbackExempt)
	}
	if cfg.GatewayAuth.AllowUnauthenticated {
		t.Error("the example config waives caller authentication")
	}
	if isLoopbackListen(cfg.Listen) {
		t.Logf("example listen = %q (loopback)", cfg.Listen)
	}
}

// ---------------------------------------------------------------------------
// /healthz and the CONNECT leg
// ---------------------------------------------------------------------------

func gwAuthHealth(t *testing.T, srv *Server, peer string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = peer
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode healthz: %v (%q)", err, rec.Body.String())
	}
	return rec.Code, body
}

// TestHealthz_GatesTheInventoryButNotLiveness splits the endpoint along the one
// line that matters. Liveness has to stay anonymous and stay 200 or every
// orchestrator in front of the gateway reads the change as an outage; the
// inventory is a route table, an auth mode per route and a live count of
// selectable plans, which is reconnaissance and an oracle both.
func TestHealthz_GatesTheInventoryButNotLiveness(t *testing.T) {
	t.Parallel()
	upstream, _ := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)

	code, body := gwAuthHealth(t, srv, gwAuthRemotePeer, nil)
	if code != http.StatusOK {
		t.Fatalf("anonymous liveness status = %d, want 200: a 401 here reads as 'down' to an orchestrator", code)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["proxy_auth"] != string(ProxyAuthTokenLoopbackExempt) {
		t.Errorf("proxy_auth = %v, want %q", body["proxy_auth"], ProxyAuthTokenLoopbackExempt)
	}
	for _, k := range []string{"routes", "keys", "connect"} {
		if _, ok := body[k]; ok {
			t.Errorf("anonymous healthz disclosed %q = %v", k, body[k])
		}
	}

	code, body = gwAuthHealth(t, srv, gwAuthRemotePeer, map[string]string{GatewayTokenHeader: gwAuthToken})
	if code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200", code)
	}
	for _, k := range []string{"routes", "keys", "connect"} {
		if _, ok := body[k]; !ok {
			t.Errorf("authenticated healthz withheld %q; the inventory is gated, not removed", k)
		}
	}
	if body["proxy_auth"] != string(ProxyAuthTokenLoopbackExempt) {
		t.Errorf("proxy_auth = %v, want it reported in both halves", body["proxy_auth"])
	}

	// An exempt loopback peer sees the inventory, because it may use the leg.
	if _, body := gwAuthHealth(t, srv, gwAuthLoopback, nil); body["routes"] == nil {
		t.Error("exempt loopback peer was denied the inventory it is allowed to use")
	}
}

// TestHealthz_KeepsTheInventoryOpenWhenNothingIsAuthenticated states the other
// side of the same rule: the gate is the proxy leg's decision, not a second one.
// Where every caller may spend every key, withholding the count would be
// theatre — and this is the behaviour every pre-existing deployment has.
func TestHealthz_KeepsTheInventoryOpenWhenNothingIsAuthenticated(t *testing.T) {
	t.Parallel()
	upstream, _ := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, GatewayAuthConfig{}), nil)

	if got := srv.ProxyAuthMode(); got != ProxyAuthLoopbackOnly {
		t.Fatalf("ProxyAuthMode() = %q, want %q", got, ProxyAuthLoopbackOnly)
	}
	code, body := gwAuthHealth(t, srv, gwAuthRemotePeer, nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["routes"] == nil {
		t.Error("routes withheld although the proxy leg authenticates nobody")
	}
	if body["proxy_auth"] != string(ProxyAuthLoopbackOnly) {
		t.Errorf("proxy_auth = %v, want %q", body["proxy_auth"], ProxyAuthLoopbackOnly)
	}
}

// TestConnectLeg_IsUnaffectedByTheProxyLegToken proves the two credentials do
// not bleed into one another in either direction. The docs promise the channel
// token gates the CONNECT leg and nothing else, and that has to stay true now
// that a second token exists.
func TestConnectLeg_IsUnaffectedByTheProxyLegToken(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Listen: "127.0.0.1:0",
		Connect: ConnectConfig{
			Enabled: true, TokenRef: gwAuthConnRef,
			AllowedHosts: []string{"allowed.example:443"},
		},
		GatewayAuth: tokenEverywhere(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard),
		WithSecretProvider(gwAuthSecrets(gwAuthToken, gwAuthConnTok)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cases := []struct {
		name              string
		proxyAuthz, token string
		host              string
		want              int
	}{
		// The gateway token does not open the tunnel...
		{"gateway token instead of the channel token", "", gwAuthToken, "allowed.example:443", http.StatusProxyAuthRequired},
		// ...and the channel token is still all the tunnel needs, even under
		// exempt_loopback: false, which would otherwise demand the other one.
		{"channel token alone still authorises", "Bearer " + gwAuthConnTok, "", "evil.example:443", http.StatusForbidden},
		{"channel token plus gateway token", "Bearer " + gwAuthConnTok, gwAuthToken, "evil.example:443", http.StatusForbidden},
		{"wrong channel token", "Bearer nope", "", "allowed.example:443", http.StatusProxyAuthRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodConnect, "http://"+tc.host, nil)
			req.Host = tc.host
			req.RemoteAddr = gwAuthRemotePeer
			if tc.proxyAuthz != "" {
				req.Header.Set("Proxy-Authorization", tc.proxyAuthz)
			}
			if tc.token != "" {
				req.Header.Set(GatewayTokenHeader, tc.token)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestProxyAuth_RefusalsAreAuditedWithoutTheCredential keeps the NDJSON stream
// the forensic record the docs say it is: a refusal that appears nowhere is a
// credential-stuffing run nobody can count.
func TestProxyAuth_RefusalsAreAuditedWithoutTheCredential(t *testing.T) {
	t.Parallel()
	var audit bytes.Buffer
	upstream, _ := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), &audit)

	gwAuthCall(t, srv, gwAuthRemotePeer, map[string]string{GatewayTokenHeader: "guessed-token"})

	line := audit.String()
	if !strings.Contains(line, `"event":"proxy_denied"`) {
		t.Fatalf("audit stream has no proxy_denied line: %s", line)
	}
	if !strings.Contains(line, `"error":"gateway_token_invalid"`) {
		t.Errorf("audit line does not name the refusal: %s", line)
	}
	if !strings.Contains(line, `"status":401`) {
		t.Errorf("audit line does not carry the status: %s", line)
	}
	if !strings.Contains(line, gwAuthRemotePeer) {
		t.Errorf("audit line does not name the client: %s", line)
	}
	for _, forbidden := range []string{"guessed-token", gwAuthToken, gwAuthRouteKey} {
		if strings.Contains(line, forbidden) {
			t.Errorf("audit line leaked %q: %s", forbidden, line)
		}
	}
}

// TestIsLoopbackPeer_ParsesThePeerAndNothingElse covers the shapes RemoteAddr
// actually takes. Everything unparseable must answer false: the safe answer to
// "I could not tell" is the one that asks for a token.
func TestIsLoopbackPeer_ParsesThePeerAndNothingElse(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"127.0.0.1:1234":           true,
		"127.0.0.53:1":             true,
		"127.255.255.254:65535":    true,
		"[::1]:1234":               true,
		"[::1%lo]:1234":            true,
		"[::ffff:127.0.0.1]:1234":  true,
		"127.0.0.1":                true,
		"::1":                      true,
		"192.0.2.1:1234":           false,
		"203.0.113.7:44100":        false,
		"[2001:db8::1]:443":        false,
		"[fe80::1%eth0]:443":       false,
		"10.0.0.1:80":              false,
		"":                         false,
		"@":                        false,
		"/run/helixchannel.sock":   false,
		"localhost:8080":           false,
		"127.0.0.1.evil.test:8080": false,
	}
	for addr, want := range cases {
		t.Run(addr, func(t *testing.T) {
			if got := isLoopbackPeer(addr); got != want {
				t.Errorf("isLoopbackPeer(%q) = %v, want %v", addr, got, want)
			}
		})
	}
}
