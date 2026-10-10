package channel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// envOnlyProvider builds a Resolver that answers env: references from a map
// and nothing else. Used wherever a test needs to control a credential without
// t.Setenv (which forbids t.Parallel).
func envOnlyProvider(vals map[string]string) *Resolver {
	return newResolver(map[string]SecretProvider{
		SchemeEnv: &envProvider{lookup: mapEnv(vals)},
	})
}

// countingProvider wraps a SecretProvider and counts Resolve calls atomically.
type countingProvider struct {
	calls atomic.Int64
	inner SecretProvider
}

func (c *countingProvider) Resolve(ref string) (string, error) {
	c.calls.Add(1)
	return c.inner.Resolve(ref)
}

// -----------------------------------------------------------------------------
// Startup shape: disabled routes, eagerness, no shared global.
// -----------------------------------------------------------------------------

func TestNewServer_DisabledRouteCredentialIsNeverResolved(t *testing.T) {
	t.Parallel()
	op := &fakeProvider{fn: func(ref string) (string, error) {
		return "", secretErr(ref, ErrSecretUnavailable, "vault is locked")
	}}
	sp := &countingProvider{inner: newResolver(map[string]SecretProvider{SchemeOP: op})}

	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{
		{Name: "anthropic", Prefix: "/anthropic/", Upstream: "https://example.invalid", Auth: AuthPassthrough, Enabled: true},
		{Name: "off", Prefix: "/off/", Upstream: "https://example.invalid", Auth: AuthInject,
			KeyRef: "op://example-vault/example-item/credential", Enabled: false},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
	if err != nil {
		t.Fatalf("a switched-off route took the gateway down: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned a nil *Server with a nil error")
	}
	if n := op.calls.Load(); n != 0 {
		t.Errorf("op fake invoked %d times for a disabled route, want 0", n)
	}
	if n := sp.calls.Load(); n != 0 {
		t.Errorf("provider consulted %d times, want 0 (passthrough needs no credential)", n)
	}
}

// TestNewServer_ResolvesEveryCredentialEagerly pins credential resolution to
// construction. Anything lazier would write Server.connToken while a handler
// reads it.
func TestNewServer_ResolvesEveryCredentialEagerly(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	sp := &countingProvider{inner: envOnlyProvider(map[string]string{
		"K1": "test-key-not-real-1",
		"K2": "test-key-not-real-2",
		"K3": "test-key-not-real-3",
		"CT": "test-token-not-real",
	})}
	cfg := &Config{Listen: "127.0.0.1:0",
		Routes: []Route{
			{Name: "r1", Prefix: "/r1/", Upstream: upstream.URL, Auth: AuthInject, KeyEnv: "K1", Enabled: true},
			{Name: "r2", Prefix: "/r2/", Upstream: upstream.URL, Auth: AuthInject, KeyEnv: "K2", Enabled: true},
			{Name: "r3", Prefix: "/r3/", Upstream: upstream.URL, Auth: AuthInject, KeyEnv: "K3", Enabled: true},
		},
		Connect: ConnectConfig{Enabled: true, AllowedHosts: []string{"example.invalid:443"}, TokenEnv: "CT"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if n := sp.calls.Load(); n != 4 {
		t.Fatalf("Resolve calls after NewServer = %d, want 4 (three routes plus the CONNECT token)", n)
	}

	h := srv.Handler()
	var wg sync.WaitGroup
	wg.Add(32)
	for i := range 32 {
		go func() {
			defer wg.Done()
			path := []string{"/r1/v1/models", "/r2/v1/models", "/r3/v1/models"}[i%3]
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		}()
	}
	wg.Wait()

	if n := sp.calls.Load(); n != 4 {
		t.Errorf("Resolve calls after serving = %d, want 4: credentials are being resolved per request", n)
	}
}

// TestNoPackageLevelSecretProvider proves each Server carries its own resolver.
// A package-level 'var defaultSecrets SecretProvider' assigned inside NewServer
// would be a write racing with every concurrent construction and would let one
// Server serve another's cached value.
func TestNoPackageLevelSecretProvider(t *testing.T) {
	t.Parallel()
	const servers = 8
	var wg sync.WaitGroup
	wg.Add(servers)
	tokens := make([]string, servers)
	errs := make([]error, servers)
	for i := range servers {
		go func() {
			defer wg.Done()
			want := "test-token-not-real-" + string(rune('0'+i))
			sp := envOnlyProvider(map[string]string{"CT": want})
			cfg := &Config{Listen: "127.0.0.1:0", Connect: ConnectConfig{
				Enabled: true, AllowedHosts: []string{"example.invalid:443"}, TokenEnv: "CT",
			}}
			if err := cfg.Validate(); err != nil {
				errs[i] = err
				return
			}
			srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
			if err != nil {
				errs[i] = err
				return
			}
			tokens[i] = srv.connToken
		}()
	}
	wg.Wait()

	for i := range servers {
		if errs[i] != nil {
			t.Fatalf("server %d: %v", i, errs[i])
		}
		want := "test-token-not-real-" + string(rune('0'+i))
		if tokens[i] != want {
			t.Errorf("server %d resolved %q, want %q (a shared global leaked another Server's credential)", i, tokens[i], want)
		}
	}
}

// -----------------------------------------------------------------------------
// The refactor must not change a single byte on the wire.
// -----------------------------------------------------------------------------

// baselineOutboundHeaderKeys is the exact header key set a single-key inject
// route produced on baseline 6e32801 for the request below. Recorded by running
// this scenario against the unmodified tree.
var baselineOutboundHeaderKeys = []string{
	"Accept-Encoding", "Authorization", "Content-Length", "Content-Type", "User-Agent",
}

func TestOutboundRequest_IsByteIdenticalToBaseline(t *testing.T) {
	t.Parallel()
	type capture struct {
		method, path, rawQuery, auth, userAgent string
		headerKeys                              []string
		contentLength                           int64
	}
	got := make(chan capture, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys := make([]string, 0, len(r.Header))
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		got <- capture{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
			auth: r.Header.Get("Authorization"), userAgent: r.Header.Get("User-Agent"),
			headerKeys: keys, contentLength: r.ContentLength,
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: upstream.URL,
		Auth: AuthInject, KeyEnv: "TEST_UPSTREAM_KEY", Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sp := envOnlyProvider(map[string]string{"TEST_UPSTREAM_KEY": "test-key-not-real"})
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	body := `{"model":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/mm/v1/chat/completions?stream=true", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer placeholder-from-client")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	c := <-got
	if c.method != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", c.method)
	}
	if c.path != "/v1/chat/completions" {
		t.Errorf("upstream path = %q, want %q", c.path, "/v1/chat/completions")
	}
	if c.rawQuery != "stream=true" {
		t.Errorf("upstream raw query = %q, want %q", c.rawQuery, "stream=true")
	}
	if c.auth != "Bearer test-key-not-real" {
		t.Errorf("upstream Authorization = %q, want exactly the injected key (appended rather than replaced?)", c.auth)
	}
	if c.userAgent != "helixchannel-gateway/1" {
		t.Errorf("upstream User-Agent = %q, want %q", c.userAgent, "helixchannel-gateway/1")
	}
	if c.contentLength != int64(len(body)) {
		t.Errorf("upstream ContentLength = %d, want %d (a fallback to chunked encoding)", c.contentLength, len(body))
	}
	if strings.Join(c.headerKeys, "|") != strings.Join(baselineOutboundHeaderKeys, "|") {
		t.Errorf("outbound header key set = %v, want the baseline 6e32801 set %v", c.headerKeys, baselineOutboundHeaderKeys)
	}
}

// -----------------------------------------------------------------------------
// Config surface.
// -----------------------------------------------------------------------------

func TestConfigValidate_KeyRefIsAFirstClassCredentialSource(t *testing.T) {
	t.Parallel()
	base := func(r Route) *Config { return &Config{Listen: "127.0.0.1:0", Routes: []Route{r}} }
	cases := []struct {
		name       string
		cfg        *Config
		wantErr    string
		wantIsRef  bool
		wantNilErr bool
	}{
		{
			name:       "inject with only an op reference",
			cfg:        base(Route{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthInject, KeyRef: "op://v/i/f"}),
			wantNilErr: true,
		},
		{
			name:       "inject with only an env reference",
			cfg:        base(Route{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthInject, KeyRef: "env:NAME"}),
			wantNilErr: true,
		},
		{
			name:    "inject with no credential source at all",
			cfg:     base(Route{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthInject}),
			wantErr: "requires key_env or key_file or key_ref",
		},
		{
			name:    "passthrough must not name a reference",
			cfg:     base(Route{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthPassthrough, KeyRef: "op://v/i/f"}),
			wantErr: "must not set key_env/key_file/key_ref",
		},
		{
			name:      "malformed op reference",
			cfg:       base(Route{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthInject, KeyRef: "op://v/i"}),
			wantErr:   `route "a"`,
			wantIsRef: true,
		},
		{
			name:      "reference without a scheme",
			cfg:       base(Route{Name: "a", Prefix: "/a/", Upstream: "https://x", Auth: AuthInject, KeyRef: "MINIMAX_KEY"}),
			wantErr:   `route "a"`,
			wantIsRef: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if tc.wantNilErr {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() = nil, want an error: a malformed reference survived config load and would only fail at resolve time")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() error = %q, want it to contain %q", err, tc.wantErr)
			}
			if tc.wantIsRef && !errors.Is(err, ErrSecretRefInvalid) {
				t.Errorf("errors.Is(err, ErrSecretRefInvalid) = false, err = %v", err)
			}
		})
	}
}

func TestConfigValidate_ConnectTokenRefMirrorsKeyRef(t *testing.T) {
	t.Parallel()
	base := func(c ConnectConfig) *Config {
		c.Enabled = true
		c.AllowedHosts = []string{"example.invalid:443"}
		return &Config{Listen: "127.0.0.1:0", Connect: c}
	}
	cases := []struct {
		name      string
		cfg       *Config
		wantNil   bool
		wantErr   string
		wantIsRef bool
	}{
		{"token_ref only", base(ConnectConfig{TokenRef: "op://v/i/f"}), true, "", false},
		{"token_env only", base(ConnectConfig{TokenEnv: "T"}), true, "", false},
		{"token_file only", base(ConnectConfig{TokenFile: "/run/secrets/t"}), true, "", false},
		{"no source", base(ConnectConfig{}), false, "token_env or token_file is required", false},
		{"malformed token_ref", base(ConnectConfig{TokenRef: "op://v"}), false, "connect:", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if tc.wantNil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() error = %q, want it to contain %q", err, tc.wantErr)
			}
			if tc.wantIsRef && !errors.Is(err, ErrSecretRefInvalid) {
				t.Errorf("errors.Is(err, ErrSecretRefInvalid) = false, err = %v", err)
			}
		})
	}
}

// TestExampleConfig_IsTheOneShippedSchema guards the committed deployment
// contract. deploy/helixchannel/gateway.example.yml is the ONLY example config
// in the tree: configs/helixchannel.rotation.example.yml is gone, and a second
// example in a second directory is how a node gets deployed from the one that
// was not updated.
//
// Every reconciled decision has to survive a real parse of that file, not just
// a hand-built Config in a test.
func TestExampleConfig_IsTheOneShippedSchema(t *testing.T) {
	t.Parallel()
	const path = "../../deploy/helixchannel/gateway.example.yml"
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", path, err)
	}

	byName := map[string]Route{}
	for _, r := range cfg.Routes {
		byName[r.Name] = r
	}

	// The pre-existing routes keep their shape, so an operator upgrading in
	// place sees no behavioural change on anything already deployed.
	legacy := map[string]struct {
		prefix, upstream string
		auth             AuthMode
		enabled          bool
	}{
		"minimax":   {"/minimax/", "https://api.minimaxi.com", AuthInject, true},
		"qwen":      {"/qwen/", "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1", AuthInject, true},
		"anthropic": {"/anthropic/", "https://api.anthropic.com", AuthPassthrough, false},
	}
	for name, w := range legacy {
		r, ok := byName[name]
		if !ok {
			t.Fatalf("route %q disappeared from the example config", name)
		}
		if r.Prefix != w.prefix || r.Upstream != w.upstream || r.Auth != w.auth || r.Enabled != w.enabled {
			t.Errorf("route %q = %+v, want prefix %q upstream %q auth %q enabled %v",
				name, r, w.prefix, w.upstream, w.auth, w.enabled)
		}
		if r.Timeout != 90*time.Second {
			t.Errorf("route %q timeout = %v, want the inherited default", name, r.Timeout)
		}
		if hasPluralKeys(r) || r.Rotation != nil {
			t.Errorf("route %q gained a pool or a rotation block it did not have", name)
		}
	}

	// key_ref on a single-key route: the secret seam, reachable from config.
	if got := byName["codex"].KeyRef; !strings.HasPrefix(got, SchemeOP) {
		t.Errorf("codex key_ref = %q, want an %s reference", got, SchemeOP)
	}

	// The full rotation block, with a REQUEST budget.
	//
	// It used to carry a token budget. Every shipped config now budgets by
	// requests: a request cap is exact under concurrency, whereas a token cap
	// bounds only the ESTIMATE and is overspendable by tokens/estimate_tokens —
	// measured 50x at cap 1000 / estimate 100 against a real 5000-token
	// response. An example that budgets by tokens is a default an operator
	// inherits without ever making the decision.
	//
	// The policy assertion stays exactly as it was, and now carries a second
	// meaning: selection and budget denomination are INDEPENDENT. This route
	// balances by the upstream's reported token totals while being capped by
	// requests.
	mmPool := byName["minimax-pool"]
	if declaredKeyCount(mmPool) != 3 {
		t.Errorf("minimax-pool declares %d slots, want 3", declaredKeyCount(mmPool))
	}
	if mmPool.Rotation == nil || mmPool.Rotation.Policy != PolicyLeastTokens {
		t.Fatalf("minimax-pool rotation = %+v, want least_tokens", mmPool.Rotation)
	}
	if mmPool.Rotation.Budget.Requests == 0 {
		t.Error("minimax-pool ships no request budget; the example must SHOW the cap an operator should copy, not merely omit the one they should not")
	}
	if got := mmPool.Rotation.Budget.Tokens; got != 0 {
		t.Errorf("minimax-pool budgets by tokens (%d); token caps are advisory and no shipped example may configure one", got)
	}

	// The scalar shorthand the pooledauth branch shipped must still parse.
	qwenPool := byName["qwen-pool"]
	if qwenPool.Rotation == nil || qwenPool.Rotation.Policy != PolicyRoundRobin {
		t.Errorf("qwen-pool rotation = %+v, want the scalar shorthand to mean round_robin", qwenPool.Rotation)
	}

	// auth: header, pooled, with a REQUEST budget — the composition no source
	// branch supported.
	exa := byName["exa-pool"]
	if exa.Auth != AuthHeaderInject || exa.KeyHeader != "x-api-key" {
		t.Errorf("exa-pool = %+v, want a header route on x-api-key", exa)
	}
	if exa.Rotation == nil || exa.Rotation.Budget.Requests == 0 {
		t.Errorf("exa-pool rotation = %+v, want a request budget", exa.Rotation)
	}
	if exa.Rotation != nil && exa.Rotation.Policy == PolicyLeastTokens {
		t.Error("exa-pool uses least_tokens on a header route; Validate should have refused it")
	}

	// auth: header, single key.
	if tav := byName["tavily"]; tav.Auth != AuthHeaderInject || hasPluralKeys(tav) || tav.KeyPrefix == "" {
		t.Errorf("tavily = %+v, want a single-key header route with a key_prefix", tav)
	}

	// Nothing enabled by default may depend on an unmounted new-style source:
	// a fresh node must come up on exactly the routes it came up on before.
	for _, r := range cfg.EnabledRoutes() {
		if _, ok := legacy[r.Name]; !ok {
			t.Errorf("route %q is enabled by default in the example config; only the pre-existing routes may be", r.Name)
		}
	}

	if !cfg.Connect.Enabled || cfg.Connect.TokenFile == "" {
		t.Error("connect stanza changed shape")
	}
	if cfg.Connect.TokenRef != "" {
		t.Errorf("connect carries token_ref %q; the committed example must not depend on a vault being reachable", cfg.Connect.TokenRef)
	}
}

// TestOldBinaryContract_KeyRefOnlyConfigRefusesToStart documents the reverse
// version-skew direction: a build that does not know key_ref drops the field
// on unmarshal and must refuse to start rather than serve an empty credential.
func TestOldBinaryContract_KeyRefOnlyConfigRefusesToStart(t *testing.T) {
	t.Parallel()
	// Simulate the old binary by taking the config a new one would accept and
	// clearing the field yaml.Unmarshal would have dropped.
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyRef: "op://example-vault/example-item/credential", Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("new binary must accept a key_ref-only route: %v", err)
	}
	cfg.Routes[0].KeyRef = "" // the field an old yaml.Unmarshal never sets
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; an old binary would start and serve an empty credential")
	}
	if !strings.Contains(err.Error(), "requires key_env or key_file") {
		t.Errorf("Validate() error = %q, want it to contain %q", err, "requires key_env or key_file")
	}
}

// -----------------------------------------------------------------------------
// The unit suite must never touch a real vault.
// -----------------------------------------------------------------------------

func TestUnitSuite_NeverRunsTheRealOPBinary(t *testing.T) {
	t.Parallel()
	// The default provider is the only thing wired to execOPRead. Every test
	// in this package injects its own OPRunner instead; this asserts the
	// default construction is the sole exec path, so a missing `op` on PATH
	// cannot make any other test behave differently.
	p := newOnePasswordProvider()
	if p.timeout != DefaultOPTimeout {
		t.Errorf("default op timeout = %v, want %v", p.timeout, DefaultOPTimeout)
	}
	if p.run == nil {
		t.Error("default onepasswordProvider has no runner")
	}
}

func TestNewDefaultSecretProvider_ReturnsAFreshInstanceEveryCall(t *testing.T) {
	t.Parallel()
	a, b := NewDefaultSecretProvider(), NewDefaultSecretProvider()
	if a == b {
		t.Fatal("NewDefaultSecretProvider returned the same instance twice; one test's cache would leak into another's")
	}
	a.store("env:SHARED", "test-key-not-real")
	if _, ok := b.cached("env:SHARED"); ok {
		t.Error("two providers share a cache")
	}
}

// -----------------------------------------------------------------------------
// Adapter sanity across the whole seam, using the real file provider.
// -----------------------------------------------------------------------------

func TestNewAuthenticatorFor_InjectResolvesThroughTheProvider(t *testing.T) {
	t.Parallel()
	sp := newResolver(map[string]SecretProvider{
		SchemeFile: &fileProvider{read: func(name string) ([]byte, error) {
			if name == "/run/secrets/example.key" {
				return []byte("test-key-not-real\n"), nil
			}
			return nil, fs.ErrNotExist
		}},
	})
	auth, err := newAuthenticatorFor(Route{
		Name: "mm", Auth: AuthInject, KeyFile: "/run/secrets/example.key",
	}, sp, nil)
	if err != nil {
		t.Fatalf("newAuthenticatorFor: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.invalid/", nil)
	if err := auth.Apply(req); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-key-not-real" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-key-not-real")
	}
	if auth.Mode() != AuthInject {
		t.Errorf("Mode() = %q, want %q", auth.Mode(), AuthInject)
	}
}

func TestNewAuthenticatorFor_PassthroughNeedsNoCredential(t *testing.T) {
	t.Parallel()
	sp := &fakeProvider{fn: func(ref string) (string, error) {
		return "", secretErr(ref, ErrSecretUnavailable, "must not be consulted")
	}}
	auth, err := newAuthenticatorFor(Route{Name: "anthropic", Auth: AuthPassthrough}, sp, nil)
	if err != nil {
		t.Fatalf("newAuthenticatorFor: %v", err)
	}
	if auth.Mode() != AuthPassthrough {
		t.Errorf("Mode() = %q, want %q", auth.Mode(), AuthPassthrough)
	}
	if n := sp.calls.Load(); n != 0 {
		t.Errorf("provider consulted %d times for a passthrough route, want 0", n)
	}
}

func TestNewAuthenticatorFor_UnknownModeIsRejected(t *testing.T) {
	t.Parallel()
	if _, err := newAuthenticatorFor(Route{Name: "x", Auth: "magic"}, NewDefaultSecretProvider(), nil); err == nil {
		t.Fatal("newAuthenticatorFor accepted an unsupported auth mode")
	}
}

// jsonRoutes is a small helper keeping the healthz decode in one place.
func jsonRoutes(t *testing.T, b []byte) []string {
	t.Helper()
	var got struct {
		Routes []string `json:"routes"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got.Routes
}

func TestNewServer_WithoutOptionsStillUsesTheDefaultProvider(t *testing.T) {
	// Not parallel: uses t.Setenv to prove the default path still reads the
	// live process environment exactly as it did on baseline.
	t.Setenv("TEST_DEFAULT_PATH_KEY", "test-key-not-real")
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnv: "TEST_DEFAULT_PATH_KEY", Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if routes := jsonRoutes(t, rec.Body.Bytes()); len(routes) != 1 || routes[0] != "mm" {
		t.Errorf("healthz routes = %v, want [mm]", routes)
	}
}
