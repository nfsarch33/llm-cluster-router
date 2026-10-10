package channel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestLoadConfig_ValidMultiRoute_ParsesAndDefaults(t *testing.T) {
	path := writeConfig(t, `
listen: "127.0.0.1:14443"
routes:
  - name: minimax
    prefix: /minimax/
    upstream: https://api.minimaxi.com
    auth: inject
    key_env: MINIMAX_KEY
    enabled: true
  - name: codex
    prefix: /codex/
    upstream: https://api.openai.com
    auth: inject
    key_env: OPENAI_KEY
    enabled: false
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got, want := len(cfg.Routes), 2; got != want {
		t.Fatalf("routes = %d, want %d", got, want)
	}
	if got, want := len(cfg.EnabledRoutes()), 1; got != want {
		t.Fatalf("enabled routes = %d, want %d (disabled route must not be served)", got, want)
	}
	if cfg.Routes[0].Timeout != DefaultTimeout {
		t.Errorf("route timeout = %v, want inherited default %v", cfg.Routes[0].Timeout, DefaultTimeout)
	}
}

func TestConfigValidate_RejectsMisconfiguration(t *testing.T) {
	cases := map[string]struct {
		cfg  Config
		want string
	}{
		"missing listen": {
			cfg:  Config{Routes: []Route{{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthPassthrough, Enabled: true}}},
			want: "listen",
		},
		"prefix without trailing slash": {
			cfg: Config{Listen: ":1", Routes: []Route{
				{Name: "a", Prefix: "/a", Upstream: "https://x", Auth: AuthPassthrough},
			}},
			want: "prefix must start and end",
		},
		"duplicate prefix": {
			cfg: Config{Listen: ":1", Routes: []Route{
				{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthPassthrough},
				{Name: "b", Prefix: "/a/", Upstream: "https://y", Auth: AuthPassthrough},
			}},
			want: "duplicate prefix",
		},
		"inject without credential source": {
			cfg: Config{Listen: ":1", Routes: []Route{
				{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthInject},
			}},
			want: "requires key_env or key_file",
		},
		"passthrough with credential source": {
			cfg: Config{Listen: ":1", Routes: []Route{
				{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthPassthrough, KeyEnv: "K"},
			}},
			want: "must not set key_env",
		},
		"unknown auth mode": {
			cfg: Config{Listen: ":1", Routes: []Route{
				{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: "magic"},
			}},
			want: "auth must be",
		},
		"connect enabled without allowlist": {
			cfg:  Config{Listen: ":1", Connect: ConnectConfig{Enabled: true, TokenEnv: "T"}},
			want: "allowed_hosts is required",
		},
		"connect enabled without token": {
			cfg:  Config{Listen: ":1", Connect: ConnectConfig{Enabled: true, AllowedHosts: []string{"h:443"}}},
			want: "token_env or token_file is required",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestInjectMode_ReplacesCallerCredential is the security-critical case: a
// caller must not be able to reach the upstream with its own Authorization
// header, and the placeholder it was told to configure must never be sent on.
func TestInjectMode_ReplacesCallerCredential(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"object":"list"}`)
	}))
	defer upstream.Close()

	t.Setenv("TEST_UPSTREAM_KEY", "real-server-side-key")
	srv := newTestServer(t, &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{{
			Name: "mm", Prefix: "/mm/", Upstream: upstream.URL,
			Auth: AuthInject, KeyEnv: "TEST_UPSTREAM_KEY", Enabled: true,
		}},
	})

	req := httptest.NewRequest(http.MethodGet, "/mm/v1/models", nil)
	req.Header.Set("Authorization", "Bearer placeholder-from-client")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotAuth != "Bearer real-server-side-key" {
		t.Errorf("upstream Authorization = %q, want the server-side key to replace the client's", gotAuth)
	}
	if strings.Contains(gotAuth, "placeholder-from-client") {
		t.Error("client-supplied credential leaked to the upstream")
	}
	if gotPath != "/v1/models" {
		t.Errorf("upstream path = %q, want route prefix stripped to %q", gotPath, "/v1/models")
	}
}

// TestPassthroughMode_PreservesCallerCredential covers the Claude Code shape:
// the client holds the session credential and the gateway must not touch it.
func TestPassthroughMode_PreservesCallerCredential(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer upstream.Close()

	srv := newTestServer(t, &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{{
			Name: "anthropic", Prefix: "/anthropic/", Upstream: upstream.URL,
			Auth: AuthPassthrough, Enabled: true,
		}},
	})

	req := httptest.NewRequest(http.MethodGet, "/anthropic/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer client-session-token")
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if gotAuth != "Bearer client-session-token" {
		t.Errorf("upstream Authorization = %q, want the caller's token forwarded unchanged", gotAuth)
	}
}

// TestDisabledRoute_IsNotServed proves the feature flag actually gates the
// route rather than merely annotating it.
func TestDisabledRoute_IsNotServed(t *testing.T) {
	t.Setenv("TEST_KEY", "k")
	srv := newTestServer(t, &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{
			{Name: "on", Prefix: "/on/", Upstream: "https://example.invalid", Auth: AuthInject, KeyEnv: "TEST_KEY", Enabled: true},
			{Name: "off", Prefix: "/off/", Upstream: "https://example.invalid", Auth: AuthInject, KeyEnv: "TEST_KEY", Enabled: false},
		},
	})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/off/v1/models", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled route status = %d, want 404", rec.Code)
	}
	var body struct {
		Routes []string `json:"routes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Routes) != 1 || body.Routes[0] != "on" {
		t.Errorf("404 hint routes = %v, want only the enabled route", body.Routes)
	}
}

// TestHealthz_ReportsLiveRouteSet guards against the static-health antipattern
// that hid a dead fan-out behind a literal 200 for a month.
func TestHealthz_ReportsLiveRouteSet(t *testing.T) {
	t.Setenv("TEST_KEY", "k")
	srv := newTestServer(t, &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{
			{Name: "minimax", Prefix: "/minimax/", Upstream: "https://example.invalid", Auth: AuthInject, KeyEnv: "TEST_KEY", Enabled: true},
			{Name: "codex", Prefix: "/codex/", Upstream: "https://example.invalid", Auth: AuthInject, KeyEnv: "TEST_KEY", Enabled: false},
		},
	})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	var got struct {
		Status string   `json:"status"`
		Routes []string `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("status = %q, want ok", got.Status)
	}
	if len(got.Routes) != 1 || got.Routes[0] != "minimax" {
		t.Errorf("healthz routes = %v, want exactly the enabled set", got.Routes)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	t.Setenv("TEST_KEY", "k")
	srv := newTestServer(t, &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{
			{Name: "broad", Prefix: "/openai/", Upstream: "https://example.invalid", Auth: AuthInject, KeyEnv: "TEST_KEY", Enabled: true},
			{Name: "specific", Prefix: "/openai/codex/", Upstream: "https://example.invalid", Auth: AuthInject, KeyEnv: "TEST_KEY", Enabled: true},
		},
	})
	if got := srv.match("/openai/codex/v1/models"); got == nil || got.Route.Name != "specific" {
		t.Fatalf("match returned %v, want the longer prefix route", got)
	}
	if got := srv.match("/openai/v1/models"); got == nil || got.Route.Name != "broad" {
		t.Fatalf("match returned %v, want the broad route", got)
	}
}

func TestAuditEvent_NeverCarriesCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	t.Setenv("TEST_UPSTREAM_KEY", "super-secret-key-value")
	var buf bytes.Buffer
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: upstream.URL,
		Auth: AuthInject, KeyEnv: "TEST_UPSTREAM_KEY", Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(&buf))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mm/v1/chat/completions", strings.NewReader(`{"model":"x"}`))
	req.Header.Set("Authorization", "Bearer client-token")
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	for _, forbidden := range []string{"super-secret-key-value", "client-token", "Authorization"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("audit log leaked %q; line = %s", forbidden, out)
		}
	}
	if !strings.Contains(out, `"route":"mm"`) {
		t.Errorf("audit log missing route attribution; line = %s", out)
	}
}

// TestConnectTunnel_EndToEnd exercises the full Claude Code path: a local
// client proxy accepts a plain CONNECT, tunnels it through a TLS hop to the
// gateway, and the gateway pipes bytes to the target. The payload must arrive
// unmodified, which is what makes an end-to-end TLS session survive the trip.
func TestConnectTunnel_EndToEnd(t *testing.T) {
	// Target the tunnel will carry: an echo server standing in for the
	// provider's TLS endpoint.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer func() { _ = target.Close() }()
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()

	t.Setenv("TEST_CONNECT_TOKEN", "tunnel-token")
	cfg := &Config{
		Listen: "127.0.0.1:0",
		Connect: ConnectConfig{
			Enabled: true, TokenEnv: "TEST_CONNECT_TOKEN",
			AllowedHosts: []string{target.Addr().String()},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	gateway := httptest.NewTLSServer(srv.Handler())
	defer gateway.Close()

	proxy := &ClientProxy{
		Listen:             "127.0.0.1:0",
		Gateway:            strings.TrimPrefix(gateway.URL, "https://"),
		Token:              "tunnel-token",
		InsecureSkipVerify: true,
	}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer func() { _ = proxyLn.Close() }()
	go func() { _ = http.Serve(proxyLn, http.HandlerFunc(proxy.handle)) }()

	// Drive the proxy exactly as an agent would: HTTPS_PROXY semantics.
	transportProxy := func(*http.Request) (*neturl, error) { return nil, nil }
	_ = transportProxy

	conn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr().String(), target.Addr().String())

	buf := make([]byte, 39)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if !strings.Contains(string(buf), "200") {
		t.Fatalf("CONNECT reply = %q, want 200", string(buf))
	}

	payload := "end-to-end-through-the-channel"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != payload {
		t.Errorf("payload round trip = %q, want %q (tunnel must not alter bytes)", echo, payload)
	}
}

func TestConnect_RejectsBadTokenAndUnlistedHost(t *testing.T) {
	t.Setenv("TEST_CONNECT_TOKEN", "good-token")
	cfg := &Config{
		Listen:  "127.0.0.1:0",
		Connect: ConnectConfig{Enabled: true, TokenEnv: "TEST_CONNECT_TOKEN", AllowedHosts: []string{"allowed.example:443"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cases := []struct {
		name, token, host string
		want              int
	}{
		{"missing token", "", "allowed.example:443", http.StatusProxyAuthRequired},
		{"wrong token", "Bearer nope", "allowed.example:443", http.StatusProxyAuthRequired},
		{"host not allowlisted", "Bearer good-token", "evil.example:443", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodConnect, "http://"+tc.host, nil)
			req.Host = tc.host
			if tc.token != "" {
				req.Header.Set("Proxy-Authorization", tc.token)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestProxyEnv_ContractForAgents(t *testing.T) {
	env := ProxyEnv(":47820")
	if env["HTTPS_PROXY"] != "http://127.0.0.1:47820" {
		t.Errorf("HTTPS_PROXY = %q, want a loopback endpoint with the bind port", env["HTTPS_PROXY"])
	}
	if env["NO_PROXY"] == "" {
		t.Error("NO_PROXY must be set, or a proxy asked to reach itself can deadlock")
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if env[k] == "" {
			t.Errorf("%s missing: agents differ on which casing they read", k)
		}
	}
}

// neturl exists only so the unused-proxy helper above compiles without
// importing net/url into the test's public surface.
type neturl = struct{ _ int }

func newTestServer(t *testing.T, cfg *Config) *Server {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

var _ = tls.VersionTLS12
var _ = context.Background
