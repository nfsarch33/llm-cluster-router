//go:build live_e2e

// Package channel live end-to-end suite.
//
// These tests run against a REAL deployed HelixChannel edge (the cloud pilot
// instance) rather than mocks, so they catch the failure classes unit tests
// structurally cannot: dead fan-out daemons behind a live TLS terminator,
// route-set drift between config and reality, upstream credential rot, and
// CONNECT allowlist regressions.
//
// Configuration (all via environment; every test SKIPs — never fails — when
// its inputs are absent, so the suite is safe in any CI lane):
//
//	HELIXCHANNEL_LIVE_BASE      e.g. https://channel.example.com   (required by all)
//	HELIXCHANNEL_LIVE_INSECURE  "1" while the edge serves a self-signed cert
//	HELIXCHANNEL_GATEWAY_TOKEN_FILE  path to the reverse-proxy gateway token; sent in the
//	                            X-HLXN-Token header. Required by every test that expects a
//	                            2xx from an inject route, because gateway_auth now gates that
//	                            leg. HELIXCHANNEL_GATEWAY_TOKEN is the env-value fallback.
//	HELIXCHANNEL_CONNECT_ADDR   host:port of the TLS CONNECT listener (optional)
//	HELIXCHANNEL_CONNECT_TOKEN_FILE  path to the CONNECT token (optional; enables the positive tunnel test)
//	HELIXCHANNEL_LIVE_CHAT      "1" to enable the paid chat-completion round trip (costs upstream tokens)
//
// Run locally:
//
//	go test -tags=live_e2e -count=1 -v -run TestLive_ ./internal/channel/
package channel

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func liveBase(t *testing.T) string {
	t.Helper()
	base := strings.TrimRight(os.Getenv("HELIXCHANNEL_LIVE_BASE"), "/")
	if base == "" {
		t.Skip("HELIXCHANNEL_LIVE_BASE unset — live suite skipped (this is a SKIP, not a pass)")
	}
	return base
}

func liveClient() *http.Client {
	tr := &http.Transport{TLSHandshakeTimeout: 10 * time.Second}
	if os.Getenv("HELIXCHANNEL_LIVE_INSECURE") == "1" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // pilot self-signed edge
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

// liveGatewayToken returns the reverse-proxy gateway token, or SKIPs. A file
// path is preferred over an env value so the secret stays off process listings;
// the env value exists for CI-secret injection.
func liveGatewayToken(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("HELIXCHANNEL_GATEWAY_TOKEN_FILE"); p != "" {
		raw, err := os.ReadFile(p) //nolint:gosec // operator-supplied path
		if err != nil {
			t.Fatalf("read gateway token file: %v", err)
		}
		return strings.TrimSpace(string(raw))
	}
	if v := os.Getenv("HELIXCHANNEL_GATEWAY_TOKEN"); v != "" {
		return strings.TrimSpace(v)
	}
	t.Skip("HELIXCHANNEL_GATEWAY_TOKEN_FILE / _TOKEN unset — gateway-auth live tests skipped (SKIP, not pass)")
	return ""
}

// withGatewayToken attaches the reverse-proxy gateway token to a request in the
// exported header constant, so a future rename of that header cannot leave this
// suite silently sending the wrong thing.
func withGatewayToken(req *http.Request, token string) {
	req.Header.Set(GatewayTokenHeader, token)
}

// TestLive_HealthzReportsRouteSet is the regression test for the
// static-health antipattern: /healthz must be answered by the gateway and
// carry the live route list, never a hardcoded literal.
//
// Since gateway_auth landed, the route list moved BEHIND the token — anonymous
// /healthz no longer carries it (see TestLive_HealthzHidesRouteTableFromAnonymous
// for that half). So this test now presents the gateway token to see routes.
func TestLive_HealthzReportsRouteSet(t *testing.T) {
	base := liveBase(t)
	token := liveGatewayToken(t)
	req, _ := http.NewRequest(http.MethodGet, base+"/healthz", nil)
	withGatewayToken(req, token)
	resp, err := liveClient().Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
	var got struct {
		Status  string   `json:"status"`
		Service string   `json:"service"`
		Routes  []string `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("healthz is not the gateway envelope (static literal regression?): %v", err)
	}
	if got.Service != "helixchannel-gateway" {
		t.Errorf("service = %q, want helixchannel-gateway (is nginx answering from a literal again?)", got.Service)
	}
	if len(got.Routes) == 0 {
		t.Error("routes is empty with a valid token — gateway is up but serving nothing")
	}
	t.Logf("live routes: %v", got.Routes)
}

// TestLive_PrimaryRouteModels proves the full chain edge→gateway→provider is
// alive: TLS termination, prefix routing, credential injection and upstream
// reachability, in one unauthenticated-from-our-side call.
func TestLive_PrimaryRouteModels(t *testing.T) {
	base := liveBase(t)
	token := liveGatewayToken(t)
	req, _ := http.NewRequest(http.MethodGet, base+"/minimax/v1/models", nil)
	// The Authorization bearer is the placeholder clients are told to send;
	// the forwarder strips it. Admission is the X-HLXN-Token below.
	req.Header.Set("Authorization", "Bearer live-e2e-placeholder")
	withGatewayToken(req, token)
	resp, err := liveClient().Do(req)
	if err != nil {
		t.Fatalf("GET /minimax/v1/models: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("models status = %d, want 200; body: %.200s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"object"`) {
		t.Errorf("models response does not look like an OpenAI list; body: %.200s", body)
	}
}

// TestLive_ChatCompletionRoundTrip exercises a real (paid) completion.
// Opt-in via HELIXCHANNEL_LIVE_CHAT=1 so scheduled runs control spend
// explicitly; cost per run is a few dozen tokens.
func TestLive_ChatCompletionRoundTrip(t *testing.T) {
	base := liveBase(t)
	if os.Getenv("HELIXCHANNEL_LIVE_CHAT") != "1" {
		t.Skip("HELIXCHANNEL_LIVE_CHAT != 1 — paid round trip skipped")
	}
	token := liveGatewayToken(t)
	payload := `{"model":"MiniMax-M3","messages":[{"role":"user","content":"Reply with the single word pong."}],"max_tokens":8}`
	req, _ := http.NewRequest(http.MethodPost, base+"/minimax/v1/chat/completions", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer live-e2e-placeholder")
	withGatewayToken(req, token)
	start := time.Now()
	resp, err := liveClient().Do(req)
	if err != nil {
		t.Fatalf("POST chat/completions: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chat status = %d; body: %.300s", resp.StatusCode, body)
	}
	var got struct {
		Object string `json:"object"`
		Model  string `json:"model"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.Object != "chat.completion" {
		t.Fatalf("not a chat.completion envelope (err=%v); body: %.300s", err, body)
	}
	t.Logf("live completion ok model=%s latency=%s", got.Model, time.Since(start).Round(time.Millisecond))
}

// TestLive_DisabledRouteStays404 is the feature-flag regression test: a route
// that is configured but disabled must 404 with the hint envelope. If this
// starts returning 200, a flag was flipped without a release note.
func TestLive_DisabledRouteStays404(t *testing.T) {
	base := liveBase(t)
	token := liveGatewayToken(t)
	// The token is required to reach route matching at all: authorizeProxy runs
	// BEFORE the route table is consulted, so an anonymous call to a disabled
	// route is refused 401 (and never told the route exists), not 404.
	req, _ := http.NewRequest(http.MethodGet, base+"/codex/v1/models", nil)
	withGatewayToken(req, token)
	resp, err := liveClient().Do(req)
	if err != nil {
		t.Fatalf("GET /codex/v1/models: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return // expected while codex is disabled
	}
	if resp.StatusCode == http.StatusOK {
		t.Log("NOTE: codex route is now enabled (200) — update this regression's expectation alongside the flag flip")
		return
	}
	t.Errorf("codex route status = %d, want 404 (disabled) or 200 (deliberately enabled)", resp.StatusCode)
}

// TestLive_ConnectAuthAndAllowlist regression-tests the CONNECT security
// boundary from the outside: no token → 407; valid token to an unlisted
// host → 403. Both are pure denials — no tunnel is established and no
// credential is needed for the first case.
func TestLive_ConnectAuthAndAllowlist(t *testing.T) {
	addr := os.Getenv("HELIXCHANNEL_CONNECT_ADDR")
	if addr == "" {
		t.Skip("HELIXCHANNEL_CONNECT_ADDR unset — CONNECT tests skipped")
	}
	dial := func(token, target string) (int, error) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: os.Getenv("HELIXCHANNEL_LIVE_INSECURE") == "1"}) //nolint:gosec
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		hdr := ""
		if token != "" {
			hdr = "Proxy-Authorization: Bearer " + token + "\r\n"
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, hdr)
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil {
			return 0, err
		}
		var code int
		_, err = fmt.Sscanf(string(buf[:n]), "HTTP/1.1 %d", &code)
		return code, err
	}

	if code, err := dial("", "api.anthropic.com:443"); err != nil || code != http.StatusProxyAuthRequired {
		t.Errorf("no-token CONNECT = (%d, %v), want 407", code, err)
	}

	tokenFile := os.Getenv("HELIXCHANNEL_CONNECT_TOKEN_FILE")
	if tokenFile == "" {
		t.Log("HELIXCHANNEL_CONNECT_TOKEN_FILE unset — allowlist + positive tunnel checks skipped")
		return
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	token := strings.TrimSpace(string(raw))

	if code, err := dial(token, "example.com:443"); err != nil || code != http.StatusForbidden {
		t.Errorf("unlisted-host CONNECT = (%d, %v), want 403", code, err)
	}
	if code, err := dial(token, "api.anthropic.com:443"); err != nil || code != http.StatusOK {
		t.Errorf("allowlisted CONNECT = (%d, %v), want 200", code, err)
	}
}
