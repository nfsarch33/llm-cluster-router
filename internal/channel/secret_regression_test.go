package channel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// THE CANONICAL EMPTY-CREDENTIAL REGRESSION SET.
//
// All three v18770 workstreams found the same defect independently and each
// wrote its own regression suite against its own patch of readSecret. readSecret
// no longer exists: the whitespace contract is enforced in exactly one place —
// envProvider.Resolve and fileProvider.Resolve trim BEFORE testing emptiness —
// and every credential in the package now flows through that seam.
//
// This file is the ONE place that pins the defect. It is deliberately the whole
// story, at every layer that can still close it independently:
//
//	L1  the provider          — "   " is a MISS, never an empty value
//	L2  NewServer             — a blank resolution refuses to construct a Server
//	L3  authorizeConnect      — an empty configured token authorises nobody
//	L4  authorizeConnect      — an empty PRESENTED token matches nothing
//	L5  the served handler    — the guard is on the request path, not a helper
//	L6  resolveKeyPool        — a pooled slot obeys the same contract
//
// Layers 3 and 4 are unreachable from a valid configuration precisely because
// layers 1 and 2 hold. They stay because the failure they prevent —
// subtle.ConstantTimeCompare([]byte(""), []byte("")) returning 1, turning the
// gateway into an allowlisted open relay — is severe enough that it must not
// depend on a single upstream check staying correct.
// -----------------------------------------------------------------------------

func connectConfig(tokenEnv, tokenFile string) *Config {
	return &Config{
		Listen: "127.0.0.1:0",
		Connect: ConnectConfig{
			Enabled:      true,
			AllowedHosts: []string{"example.invalid:443"},
			TokenEnv:     tokenEnv,
			TokenFile:    tokenFile,
		},
	}
}

// -----------------------------------------------------------------------------
// L1 + L2 through the REAL default provider and the live process environment.
// These use t.Setenv, so they must not call t.Parallel.
// -----------------------------------------------------------------------------

// TestConnectToken_WhitespaceEnvNoLongerAuthorisesAnEmptyBearer is the confirmed
// defect, end to end. The predecessor tested os.Getenv(name) != "" BEFORE
// trimming, so an env var of "   " passed as present and then collapsed to "".
// NewServer stored that as connToken and the header
// "Proxy-Authorization: Bearer " was AUTHORISED.
func TestConnectToken_WhitespaceEnvNoLongerAuthorisesAnEmptyBearer(t *testing.T) {
	t.Setenv("TEST_CONNECT_TOKEN", "   ")
	cfg := connectConfig("TEST_CONNECT_TOKEN", "")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err == nil {
		t.Fatalf("NewServer accepted a whitespace-only token env; the empty bearer %q would be authorised", "Bearer ")
	}
	if srv != nil {
		t.Errorf("NewServer returned a server alongside the error; it must not be constructed")
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
	}
	if !strings.HasPrefix(err.Error(), "connect:") {
		t.Errorf("error %q is not prefixed %q", err, "connect:")
	}
}

// TestConnectToken_WhitespaceEnvFallsThroughToTheFile: the fix must not turn a
// blank env var into a hard failure when a token file is also configured. A
// blank source is a MISS, and a miss falls through to the next candidate.
func TestConnectToken_WhitespaceEnvFallsThroughToTheFile(t *testing.T) {
	t.Setenv("TEST_CONNECT_TOKEN", "\t \n")
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("test-token-not-real\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	cfg := connectConfig("TEST_CONNECT_TOKEN", path)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.connToken != "test-token-not-real" {
		t.Fatalf("resolved token did not come from the file")
	}
	if !srv.authorizeConnect("Bearer test-token-not-real") {
		t.Error("authorizeConnect = false for the token resolved from the file")
	}
	if srv.authorizeConnect("Bearer ") {
		t.Error("authorizeConnect = true for an empty bearer")
	}
}

// TestInjectRoute_WhitespaceKeyEnvFailsAtStartup: a blank credential must be
// caught while the process is starting, not surface as 502s later.
func TestInjectRoute_WhitespaceKeyEnvFailsAtStartup(t *testing.T) {
	t.Setenv("TEST_UPSTREAM_KEY", "  ")
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnv: "TEST_UPSTREAM_KEY", Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	_, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err == nil {
		t.Fatal(`NewServer accepted a whitespace-only key_env; the route would inject "Bearer "`)
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
	}
}

// -----------------------------------------------------------------------------
// L2 with an injected provider, so the assertions can run in parallel and no
// test mutates global process state.
// -----------------------------------------------------------------------------

func TestNewServer_RejectsWhitespaceConnectToken(t *testing.T) {
	t.Parallel()
	cfg := connectConfig("TEST_CONNECT_TOKEN", "")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sp := envOnlyProvider(map[string]string{"TEST_CONNECT_TOKEN": "   "})

	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
	if err == nil {
		t.Fatal(`NewServer accepted a whitespace CONNECT token; the gateway would authorise "Proxy-Authorization: Bearer "`)
	}
	if srv != nil {
		t.Errorf("NewServer returned a non-nil *Server alongside an error: %v", srv)
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
	}
	if !strings.HasPrefix(err.Error(), "connect:") {
		t.Errorf("error %q is not prefixed %q", err, "connect:")
	}
}

// TestNewServer_RejectsWhitespaceRouteKey is the same defect's second face: an
// inject route whose credential resolves to whitespace used to build a
// bearerInjector with an empty key and 502 on every request.
func TestNewServer_RejectsWhitespaceRouteKey(t *testing.T) {
	t.Parallel()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnv: "TEST_ROUTE_KEY", Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sp := envOnlyProvider(map[string]string{"TEST_ROUTE_KEY": "  \t "})

	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
	if err == nil {
		t.Fatal("startup accepted an empty upstream credential; every request would 502 at Apply time instead of failing at boot")
	}
	if srv != nil {
		t.Errorf("NewServer returned a non-nil *Server alongside an error: %v", srv)
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), `"mm"`) {
		t.Errorf("error %q does not name the route", err)
	}
}

// -----------------------------------------------------------------------------
// L3 + L4: the guards inside authorizeConnect, reached by forcing the state a
// regression would produce.
// -----------------------------------------------------------------------------

// TestAuthorizeConnect_EmptyTokenAuthorisesNobody covers L3. Without the
// explicit guard, subtle.ConstantTimeCompare([]byte(""), []byte("")) returns 1
// and an empty connToken authorises an empty bearer.
func TestAuthorizeConnect_EmptyTokenAuthorisesNobody(t *testing.T) {
	t.Parallel()
	s := &Server{
		cfg:       &Config{Listen: "127.0.0.1:0", Connect: ConnectConfig{Enabled: true}},
		allowed:   map[string]bool{},
		connToken: "",
	}
	cases := []struct{ name, header string }{
		{"the exact bypass", "Bearer "},
		{"trailing spaces after Bearer", "Bearer     "},
		{"a wrong token", "Bearer x"},
		{"no header at all", ""},
		{"wrong scheme", "Basic zzz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if s.authorizeConnect(tc.header) {
				t.Errorf("empty connToken authorised %q", tc.header)
			}
		})
	}
}

// TestAuthorizeConnect_EmptyPresentedTokenMatchesNothing covers L4, which is a
// different guard from L3: here the server holds a real token and the CLIENT
// presents an empty one. It must be rejected on its own merits, so the property
// survives even if the server-side emptiness guard is ever relaxed.
func TestAuthorizeConnect_EmptyPresentedTokenMatchesNothing(t *testing.T) {
	t.Parallel()
	s := &Server{
		cfg:       &Config{Listen: "127.0.0.1:0", Connect: ConnectConfig{Enabled: true}},
		allowed:   map[string]bool{},
		connToken: "test-token-not-real",
	}
	for _, header := range []string{"Bearer ", "Bearer    ", "Bearer \t"} {
		if s.authorizeConnect(header) {
			t.Errorf("authorizeConnect(%q) = true against a real configured token", header)
		}
	}
	if !s.authorizeConnect("Bearer test-token-not-real") {
		t.Error("authorizeConnect = false for the correct token; the guard rejected a valid client")
	}
}

// -----------------------------------------------------------------------------
// L5: the guard is wired into the SERVED path, not merely into a helper — and
// the target is never dialled.
// -----------------------------------------------------------------------------

func TestConnect_EmptyToken_Returns407OverTheRealHandler(t *testing.T) {
	t.Parallel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer func() { _ = target.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = conn.Close()
	}()

	var audit bytes.Buffer
	cfg := &Config{
		Listen: "127.0.0.1:0",
		Connect: ConnectConfig{
			Enabled:      true,
			AllowedHosts: []string{target.Addr().String()},
			TokenEnv:     "TEST_CONNECT_TOKEN",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sp := envOnlyProvider(map[string]string{"TEST_CONNECT_TOKEN": "test-token-not-real"})
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(&audit), WithSecretProvider(sp))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Force the state the defect produced, to prove the handler still denies.
	srv.connToken = ""

	req := httptest.NewRequest(http.MethodConnect, "http://"+target.Addr().String(), nil)
	req.Host = target.Addr().String()
	req.Header.Set("Proxy-Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusProxyAuthRequired)
	}
	if rec.Header().Get("Proxy-Authenticate") == "" {
		t.Error("Proxy-Authenticate header is unset on a 407")
	}
	line := audit.String()
	if !strings.Contains(line, `"event":"connect_denied"`) || !strings.Contains(line, `"error":"bad_token"`) {
		t.Errorf("audit line = %s, want connect_denied / bad_token", line)
	}
	select {
	case <-accepted:
		t.Error("the gateway dialled the target despite refusing the token")
	default:
	}
}

// -----------------------------------------------------------------------------
// L6: the pooled path obeys the same contract. A pool that silently accepted a
// blank slot would carry a dead account at a fixed key_index and report a
// healthy rotation.
// -----------------------------------------------------------------------------

func TestResolveKeyPool_WhitespaceOnlySlotIsRejected(t *testing.T) {
	t.Parallel()
	sp := envOnlyProvider(map[string]string{"E1": "env-1-not-real", "E2": "   \t "})
	_, err := resolveKeyPool(Route{Name: "mm", KeyEnvs: []string{"E1", "E2"}}, sp)
	if err == nil {
		t.Fatal("resolveKeyPool accepted a whitespace-only key; a blank slot is a dead account, not a credential")
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("error = %v, want ErrSecretEmpty", err)
	}
	if !strings.Contains(err.Error(), "key_envs[1]") {
		t.Errorf("error = %q, want it to name the blank slot", err)
	}
}
