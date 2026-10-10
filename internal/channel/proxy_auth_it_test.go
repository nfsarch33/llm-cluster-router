//go:build integration

// Integration coverage for caller authentication on the reverse-proxy leg.
//
// These run over a REAL loopback listener with a real http.Client, because the
// two properties under test are exactly the ones a handler-level test cannot
// see: RemoteAddr as net/http actually fills it in from an accepted connection,
// and the bytes a provider actually receives.
//
// Run: go test -race -tags integration -run 'TestIT_' ./internal/channel/
package channel

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// kiloPlaceholderBearer is the shape clients are told to configure: Kilo Code
// will not send a request without some API key, so it sends a meaningless one.
const kiloPlaceholderBearer = "Bearer sk-helixchannel-placeholder"

// TestIT_KiloPlaceholderAuthorizationSurvivesGatewayTokenAuth is the contract
// this change most easily could have broken.
//
// Kilo Code sends a placeholder in Authorization. If caller authentication had
// been read out of that header — the obvious place to put it — every configured
// client would have broken at cutover, and the gateway's admission decision
// would have depended on a value clients were explicitly told was meaningless.
// The gateway token rides in its own header instead, so all three facts hold at
// once: the request is served, the placeholder never leaves the gateway, and the
// server-held key is what the provider sees.
//
// exempt_loopback is false on purpose. Over a real listener the client IS a
// loopback peer, so with the default exemption the token would never be checked
// and this test would prove nothing about it.
func TestIT_KiloPlaceholderAuthorizationSurvivesGatewayTokenAuth(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)
	gw := realGateway(t, srv)

	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mm/v1/chat/completions",
		strings.NewReader(`{"model":"MiniMax-M3","messages":[]}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", kiloPlaceholderBearer)
	req.Header.Set(GatewayTokenHeader, gwAuthToken)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", resp.StatusCode, body)
	}

	hits, seen := probe.seen()
	if hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	if got := seen.Get("Authorization"); got != "Bearer "+gwAuthRouteKey {
		t.Errorf("upstream Authorization = %q, want the server-held key %q", got, "Bearer "+gwAuthRouteKey)
	}
	if strings.Contains(seen.Get("Authorization"), "placeholder") {
		t.Error("the client's placeholder bearer reached the provider")
	}
	if got := seen.Get(GatewayTokenHeader); got != "" {
		t.Errorf("upstream received %s = %q; the gateway token authenticates this hop only", GatewayTokenHeader, got)
	}
}

// TestIT_AnonymousCallerOverARealListenerNeverReachesTheProvider reproduces the
// defect over the wire rather than through the handler.
//
// The measured failure was an anonymous `curl -X POST` with no headers at all
// reaching the provider's production load balancer with the server-held key
// injected. The upstream hit count is the assertion; the 401 is a courtesy.
func TestIT_AnonymousCallerOverARealListenerNeverReachesTheProvider(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)
	gw := realGateway(t, srv)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post(
		gw.URL+"/mm/v1/models", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != gwAuthChallenge {
		t.Errorf("WWW-Authenticate = %q, want %q", got, gwAuthChallenge)
	}
	var refusal struct {
		Error  string   `json:"error"`
		Routes []string `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refusal); err != nil {
		t.Fatalf("decode refusal: %v", err)
	}
	if refusal.Error != string(refusalTokenRequired) {
		t.Errorf("error = %q, want %q", refusal.Error, refusalTokenRequired)
	}
	if len(refusal.Routes) != 0 {
		t.Errorf("refusal disclosed the route table: %v", refusal.Routes)
	}
	if hits, _ := probe.seen(); hits != 0 {
		t.Fatalf("upstream hits = %d, want 0: the provider was contacted with the gateway's key on an unauthenticated request", hits)
	}
}

// TestIT_LoopbackExemptionKeepsExistingLocalClientsWorking is the cutover
// promise: a client that worked before this existed, with no headers of any
// kind, still works from loopback under the default posture.
func TestIT_LoopbackExemptionKeepsExistingLocalClientsWorking(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenExempt()), nil)
	gw := realGateway(t, srv)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(gw.URL + "/mm/v1/models")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (body %q): a loopback client must not need a token at cutover", resp.StatusCode, body)
	}
	if hits, _ := probe.seen(); hits != 1 {
		t.Errorf("upstream hits = %d, want 1", hits)
	}

	// The same peer presenting a WRONG token is still refused: the exemption
	// waives having to present one, not the check on one that was presented.
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/mm/v1/models", nil)
	req.Header.Set(GatewayTokenHeader, "stale-token")
	stale, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = stale.Body.Close() }()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Errorf("stale-token status = %d, want 401", stale.StatusCode)
	}
}

// TestIT_HealthzOverARealListenerGatesTheInventory checks the split where an
// orchestrator's probe actually reaches it: liveness anonymous and 200, the
// route and key inventory only for a caller the proxy leg would serve.
func TestIT_HealthzOverARealListenerGatesTheInventory(t *testing.T) {
	t.Parallel()
	upstream, _ := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)
	gw := realGateway(t, srv)

	get := func(t *testing.T, token string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, gw.URL+"/healthz", nil)
		if token != "" {
			req.Header.Set(GatewayTokenHeader, token)
		}
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("healthz: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode healthz: %v", err)
		}
		return resp.StatusCode, body
	}

	code, anon := get(t, "")
	if code != http.StatusOK {
		t.Fatalf("anonymous healthz = %d, want 200", code)
	}
	if anon["status"] != "ok" || anon["proxy_auth"] != string(ProxyAuthToken) {
		t.Errorf("anonymous healthz = %v, want status ok and proxy_auth %q", anon, ProxyAuthToken)
	}
	if _, ok := anon["keys"]; ok {
		t.Errorf("anonymous healthz disclosed the key inventory: %v", anon["keys"])
	}

	if _, authed := get(t, gwAuthToken); authed["keys"] == nil || authed["routes"] == nil {
		t.Errorf("authenticated healthz withheld the inventory: %v", authed)
	}
}

// TestIT_ForwardedHeadersCannotClaimTheLoopbackExemption is the spoofing case
// over a real socket. The client here IS on loopback, so to prove the header is
// ignored the exemption has to be off; what the test pins is that adding a
// forwarded-for header changes nothing in either direction — it is not an input.
func TestIT_ForwardedHeadersCannotClaimTheLoopbackExemption(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)
	gw := realGateway(t, srv)

	for _, h := range []struct{ name, value string }{
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Real-Ip", "127.0.0.1"},
		{"Forwarded", `for="127.0.0.1"`},
	} {
		t.Run(h.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, gw.URL+"/mm/v1/models", nil)
			req.Header.Set(h.name, h.value)
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401: %s must not be an input to the exemption", resp.StatusCode, h.name)
			}
		})
	}
	if hits, _ := probe.seen(); hits != 0 {
		t.Errorf("upstream hits = %d, want 0", hits)
	}
}
