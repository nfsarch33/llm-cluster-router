package channel

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// testProvider is a Resolver over controllable env and op:// backends plus the
// real file provider, so a pooled route can be built without t.Setenv (which
// forbids t.Parallel) and without ever shelling out to the 1Password CLI.
func testProvider(env, op map[string]string) *Resolver {
	return newResolver(map[string]SecretProvider{
		SchemeEnv:  &envProvider{lookup: mapEnv(env)},
		SchemeFile: newFileProvider(),
		SchemeOP: &fakeProvider{fn: func(ref string) (string, error) {
			if v, ok := op[ref]; ok {
				return v, nil
			}
			return "", secretErr(ref, ErrSecretNotFound, "no such item")
		}},
	})
}

// upstreamRecorder records what an httptest upstream actually received.
type upstreamRecorder struct {
	mu      sync.Mutex
	auths   []string
	headers []http.Header
}

func newUpstreamRecorder() *upstreamRecorder { return &upstreamRecorder{} }

func (u *upstreamRecorder) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.auths = append(u.auths, r.Header.Get("Authorization"))
	u.headers = append(u.headers, r.Header.Clone())
}

func (u *upstreamRecorder) seq() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.auths...)
}

func (u *upstreamRecorder) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.auths)
}

func (u *upstreamRecorder) headerAt(i int) http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.headers[i]
}

func (u *upstreamRecorder) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		_, _ = io.WriteString(w, "ok")
	}))
}

func writeKeyFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return p
}

// buildServer validates then constructs, returning the construction error so a
// test can assert on a startup failure.
func buildServer(t *testing.T, cfg *Config, w io.Writer, opts ...ServerOption) (*Server, error) {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	return NewServer(cfg, NewHTTPForwarder(), NewAuditor(w), opts...)
}

func mustBuildServer(t *testing.T, cfg *Config, w io.Writer, opts ...ServerOption) *Server {
	t.Helper()
	srv, err := buildServer(t, cfg, w, opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func serve(srv *Server, method, path string, hdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// assertNoKeyMaterial fails if subject contains any value, or any prefix or
// suffix of a value longer than three characters. A partial match is enough to
// build a correlation oracle, so the assertion is deliberately stricter than
// "does not contain the whole key".
func assertNoKeyMaterial(t *testing.T, what, subject string, values ...string) {
	t.Helper()
	for _, v := range values {
		if len(v) < 4 {
			continue
		}
		for n := 4; n <= len(v); n++ {
			if strings.Contains(subject, v[:n]) {
				t.Errorf("%s leaked a %d-char prefix of a credential (%q); subject = %s", what, n, v[:n], subject)
				break
			}
			if strings.Contains(subject, v[len(v)-n:]) {
				t.Errorf("%s leaked a %d-char suffix of a credential (%q); subject = %s", what, n, v[len(v)-n:], subject)
				break
			}
		}
	}
}

func auditLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode audit line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func keyIndexOf(t *testing.T, m map[string]any) (int, bool) {
	t.Helper()
	v, ok := m["key_index"]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("key_index = %#v, want a JSON number", v)
	}
	return int(f), true
}

func inventoryFrom(t *testing.T, b []byte) map[string]KeyInventory {
	t.Helper()
	var got struct {
		Keys map[string]KeyInventory `json:"keys"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	return got.Keys
}

// -----------------------------------------------------------------------------
// Config: the ONE multi-key spelling
// -----------------------------------------------------------------------------

// TestLoadConfig_PooledRoute_ParsesEverySpellingInFrozenOrder pins the schema:
// key_envs / key_files / key_refs, never keys_env / keys_file.
func TestLoadConfig_PooledRoute_ParsesEverySpellingInFrozenOrder(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
listen: "127.0.0.1:0"
routes:
  - name: mm
    prefix: /mm/
    upstream: https://api.example.invalid
    auth: inject
    key_envs: [MM_A, MM_B]
    key_files: ["/run/secrets/mm-c.key"]
    key_refs: ["op://vault/item/field"]
    rotation: least_used
    enabled: false
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	r := cfg.Routes[0]
	if got, want := r.KeyEnvs, []string{"MM_A", "MM_B"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("key_envs = %v, want %v in declaration order", got, want)
	}
	if len(r.KeyFiles) != 1 || len(r.KeyRefs) != 1 {
		t.Errorf("key_files/key_refs = %v/%v, want one entry each", r.KeyFiles, r.KeyRefs)
	}
	if !hasPluralKeys(r) || hasSingularKeys(r) {
		t.Errorf("route classified as pooled=%v singular=%v, want pooled only", hasPluralKeys(r), hasSingularKeys(r))
	}
	if declaredKeyCount(r) != 4 {
		t.Errorf("declaredKeyCount = %d, want 4", declaredKeyCount(r))
	}
	if r.Rotation == nil || r.Rotation.Policy != PolicyLeastUsed {
		t.Errorf("rotation = %+v, want the scalar shorthand to select least_used", r.Rotation)
	}
}

// TestLoadConfig_RetiredMultiKeySpellingIsNotHonoured: keys_env / keys_file are
// gone. A config still using them names no credential source at all, and must
// fail loudly rather than start with a route that serves nothing.
func TestLoadConfig_RetiredMultiKeySpellingIsNotHonoured(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `
listen: "127.0.0.1:0"
routes:
  - name: mm
    prefix: /mm/
    upstream: https://api.example.invalid
    auth: inject
    keys_env: MM_KEYS
    enabled: false
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted the retired keys_env spelling; the route would hold no credential")
	}
	if !strings.Contains(err.Error(), "requires key_env or key_file") {
		t.Errorf("error = %q, want the missing-credential message", err)
	}
}

func TestConfigValidate_HeaderModeRules(t *testing.T) {
	t.Parallel()
	base := func(mutate func(r *Route)) Config {
		r := Route{
			Name: "exa", Prefix: "/exa/", Upstream: "https://example.invalid",
			Auth: AuthHeaderInject, KeyHeader: "x-api-key", KeyEnv: "EXA_KEY", Enabled: true,
		}
		mutate(&r)
		return Config{Listen: "127.0.0.1:0", Routes: []Route{r}}
	}
	cases := map[string]struct {
		cfg  Config
		want string
	}{
		"missing key_header": {
			cfg:  base(func(r *Route) { r.KeyHeader = "" }),
			want: "key_header is required",
		},
		"invalid header name": {
			cfg:  base(func(r *Route) { r.KeyHeader = "bad header" }),
			want: "is not a valid header name",
		},
		"hop-by-hop header name": {
			cfg:  base(func(r *Route) { r.KeyHeader = "Connection" }),
			want: "hop-by-hop",
		},
		"Host header": {
			cfg:  base(func(r *Route) { r.KeyHeader = "Host" }),
			want: "cannot be injected",
		},
		"key_header on an inject route": {
			cfg:  base(func(r *Route) { r.Auth = AuthInject }),
			want: "key_header is only valid with auth: header",
		},
		"key_prefix on a passthrough route": {
			cfg: Config{Listen: "127.0.0.1:0", Routes: []Route{{
				Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
				Auth: AuthPassthrough, KeyPrefix: "Token ", Enabled: true,
			}}},
			want: "key_prefix is only valid with auth: header",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := tc.cfg
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestConfigValidate_AuthEnumNamesAllThreeModes: the legacy substring
// "auth must be" is preserved, and the message now names the third mode.
func TestConfigValidate_AuthEnumNamesAllThreeModes(t *testing.T) {
	t.Parallel()
	cfg := Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "a", Prefix: "/a/", Upstream: "https://example.invalid", Auth: "magic",
	}}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil for an unknown auth mode")
	}
	for _, want := range []string{"auth must be", `"inject"`, `"header"`, `"passthrough"`, `"magic"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// TestConfigValidate_DisabledPooledRouteIsStillValidated: a typo in a route that
// is switched off today must not become an outage the day it is switched on.
func TestConfigValidate_DisabledPooledRouteIsStillValidated(t *testing.T) {
	t.Parallel()
	cfg := Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "off", Prefix: "/off/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnvs: []string{"A", "A"}, Enabled: false,
	}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil for a disabled route with a duplicated source")
	}
}

// -----------------------------------------------------------------------------
// Startup: pools resolve through the ONE seam, or the gateway does not start
// -----------------------------------------------------------------------------

func pooledConfig(t *testing.T, upstream string, mutate func(r *Route)) *Config {
	t.Helper()
	r := Route{
		Name: "mm", Prefix: "/mm/", Upstream: upstream,
		Auth: AuthInject, KeyEnvs: []string{"MM_A", "MM_B", "MM_C"}, Enabled: true,
	}
	if mutate != nil {
		mutate(&r)
	}
	return &Config{Listen: "127.0.0.1:0", Routes: []Route{r}}
}

func TestNewServer_MixedSourcesFormOneOrderedPool(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fileB := writeKeyFile(t, dir, "b.key", "key-file-b-not-real\n")
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	cfg := pooledConfig(t, upstream.URL, func(r *Route) {
		r.KeyEnvs = []string{"MM_A"}
		r.KeyFiles = []string{fileB}
		r.KeyRefs = []string{"op://vault/mm/key-c"}
	})
	sp := testProvider(
		map[string]string{"MM_A": "key-env-a-not-real"},
		map[string]string{"op://vault/mm/key-c": "key-op-c-not-real"},
	)
	srv := mustBuildServer(t, cfg, io.Discard, WithSecretProvider(sp))

	for range 3 {
		if got := serve(srv, http.MethodGet, "/mm/v1/models", nil).Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	}
	want := []string{
		"Bearer key-env-a-not-real",
		"Bearer key-file-b-not-real",
		"Bearer key-op-c-not-real",
	}
	if got := rec.seq(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("outbound sequence = %v, want %v (slot order key_envs, key_files, key_refs)", got, want)
	}
}

func TestNewServer_UnresolvableSlotFailsStartupWithoutKeyMaterial(t *testing.T) {
	t.Parallel()
	cfg := pooledConfig(t, "https://example.invalid", func(r *Route) {
		r.KeyEnvs = []string{"MM_A", "MM_MISSING"}
	})
	sp := testProvider(map[string]string{"MM_A": "key-env-a-not-real"}, nil)

	srv, err := buildServer(t, cfg, io.Discard, WithSecretProvider(sp))
	if err == nil {
		t.Fatal("NewServer accepted a pool with an unresolvable slot; the pool would silently shrink")
	}
	if srv != nil {
		t.Errorf("NewServer returned a server alongside the error")
	}
	if !strings.Contains(err.Error(), "key_envs[1]") {
		t.Errorf("error = %q, want it to name the failing slot", err)
	}
	assertNoKeyMaterial(t, "startup error", err.Error(), "key-env-a-not-real")
}

func TestNewServer_DuplicateResolvedCredentialIsRejected(t *testing.T) {
	t.Parallel()
	cfg := pooledConfig(t, "https://example.invalid", func(r *Route) {
		r.KeyEnvs = []string{"MM_A", "MM_B"}
	})
	sp := testProvider(map[string]string{
		"MM_A": "shared-plan-not-real",
		"MM_B": "shared-plan-not-real",
	}, nil)

	_, err := buildServer(t, cfg, io.Discard, WithSecretProvider(sp))
	if err == nil {
		t.Fatal("NewServer accepted two slots backed by one account")
	}
	if !strings.Contains(err.Error(), "over-reports capacity") {
		t.Errorf("error = %q, want it to explain the capacity lie", err)
	}
	assertNoKeyMaterial(t, "duplicate error", err.Error(), "shared-plan-not-real")
}

// TestNewAuthenticator_RefusesAPooledRoute: a pool without a Store is not a
// functioning Authenticator. Returning one anyway would hand the caller an
// object that looks constructed and fails closed on every request.
func TestNewAuthenticator_RefusesAPooledRoute(t *testing.T) {
	t.Parallel()
	_, err := NewAuthenticator(Route{
		Name: "mm", Auth: AuthInject, KeyEnvs: []string{"A", "B"},
	})
	if err == nil {
		t.Fatal("NewAuthenticator built a pooled route without a Store")
	}
	if !strings.Contains(err.Error(), "must be built by NewServer") {
		t.Errorf("error = %q, want it to point at NewServer", err)
	}
}

// TestRotatingInjector_ApplyWithoutALeaseFailsClosed pins the deleted
// size-1 shortcut. A one-key pool that quietly served keys[0] would emit no
// key_index and charge no budget while reporting a healthy rotation.
func TestRotatingInjector_ApplyWithoutALeaseFailsClosed(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 3} {
		keys := make([]string, n)
		for i := range keys {
			keys[i] = "key-not-real-" + string(rune('a'+i))
		}
		ri := &rotatingInjector{keys: keys, route: "mm", mode: AuthInject, header: "Authorization", prefix: "Bearer "}
		req := httptest.NewRequest(http.MethodGet, "/mm/v1/models", nil)
		err := ri.Apply(req)
		if err == nil {
			t.Fatalf("pool of %d: Apply succeeded without a lease", n)
		}
		if !strings.Contains(err.Error(), "requires a key lease") {
			t.Errorf("pool of %d: error = %q, want it to name the missing lease", n, err)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("pool of %d: Apply wrote %q despite failing", n, got)
		}
	}
}

// -----------------------------------------------------------------------------
// The single-key path must be untouched
// -----------------------------------------------------------------------------

// TestSingleKeyRoute_StaysBearerInjectorAndUnchangedOnTheWire is the
// compatibility anchor for the whole reconciliation.
func TestSingleKeyRoute_StaysBearerInjectorAndUnchangedOnTheWire(t *testing.T) {
	t.Parallel()
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	var audit bytes.Buffer
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: upstream.URL,
		Auth: AuthInject, KeyEnv: "MM_ONE", Enabled: true,
	}}}
	sp := testProvider(map[string]string{"MM_ONE": "single-key-not-real"}, nil)
	srv := mustBuildServer(t, cfg, &audit, WithSecretProvider(sp))

	bound := srv.routes[0]
	if _, ok := bound.Auth.(*bearerInjector); !ok {
		t.Fatalf("single-key inject route built a %T, want *bearerInjector", bound.Auth)
	}
	if _, ok := bound.Auth.(keyLeaser); ok {
		t.Error("single-key route advertises keyLeaser; it must take the untouched, non-leasing path")
	}

	serve(srv, http.MethodGet, "/mm/v1/models", http.Header{"Authorization": {"Bearer placeholder"}})
	if got := rec.seq(); len(got) != 1 || got[0] != "Bearer single-key-not-real" {
		t.Errorf("upstream Authorization = %v, want the server-side key to replace the client's", got)
	}
	lines := auditLines(t, &audit)
	if len(lines) != 1 {
		t.Fatalf("audit lines = %d, want 1", len(lines))
	}
	if _, ok := keyIndexOf(t, lines[0]); ok {
		t.Error("a single-key route emitted key_index; legacy lines must stay byte-identical")
	}
}

// TestPluralListOfOne_IsStillAPool: pooled is a property of the SPELLING, not of
// the count. A one-entry pool leases, reports key_index 0 and charges its
// budget.
func TestPluralListOfOne_IsStillAPool(t *testing.T) {
	t.Parallel()
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	var audit bytes.Buffer
	cfg := pooledConfig(t, upstream.URL, func(r *Route) { r.KeyEnvs = []string{"MM_A"} })
	sp := testProvider(map[string]string{"MM_A": "only-key-not-real"}, nil)
	srv := mustBuildServer(t, cfg, &audit, WithSecretProvider(sp))

	if _, ok := srv.routes[0].Auth.(keyLeaser); !ok {
		t.Fatalf("one-entry pool built a %T, want a leasing authenticator", srv.routes[0].Auth)
	}
	serve(srv, http.MethodGet, "/mm/v1/models", nil)

	if got := rec.seq(); len(got) != 1 || got[0] != "Bearer only-key-not-real" {
		t.Errorf("upstream Authorization = %v", got)
	}
	lines := auditLines(t, &audit)
	idx, ok := keyIndexOf(t, lines[0])
	if !ok {
		t.Fatal("a one-key pool emitted no key_index; it would report a healthy rotation while spending one plan")
	}
	if idx != 0 {
		t.Errorf("key_index = %d, want 0", idx)
	}
}

// -----------------------------------------------------------------------------
// Pooled inject
// -----------------------------------------------------------------------------

func TestPooledInject_ReplacesCallerCredentialAndRotatesRoundRobin(t *testing.T) {
	t.Parallel()
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	cfg := pooledConfig(t, upstream.URL, nil)
	sp := testProvider(map[string]string{
		"MM_A": "key-a-not-real", "MM_B": "key-b-not-real", "MM_C": "key-c-not-real",
	}, nil)
	srv := mustBuildServer(t, cfg, io.Discard, WithSecretProvider(sp))

	for range 4 {
		serve(srv, http.MethodGet, "/mm/v1/models", http.Header{"Authorization": {"Bearer placeholder-from-client"}})
	}
	want := []string{
		"Bearer key-a-not-real", "Bearer key-b-not-real",
		"Bearer key-c-not-real", "Bearer key-a-not-real",
	}
	got := rec.seq()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("outbound sequence = %v, want round-robin %v", got, want)
	}
	for _, a := range got {
		if strings.Contains(a, "placeholder-from-client") {
			t.Error("client-supplied credential leaked to the upstream")
		}
	}
}

// -----------------------------------------------------------------------------
// Header mode
// -----------------------------------------------------------------------------

func TestHeaderMode_WritesConfiguredHeaderAndStripsInboundAuthorization(t *testing.T) {
	t.Parallel()
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "tavily", Prefix: "/tavily/", Upstream: upstream.URL,
		Auth: AuthHeaderInject, KeyHeader: "x-api-key", KeyPrefix: "tvly-",
		KeyRef: "env:TAVILY_KEY", Enabled: true,
	}}}
	sp := testProvider(map[string]string{"TAVILY_KEY": "tavily-secret-not-real"}, nil)
	srv := mustBuildServer(t, cfg, io.Discard, WithSecretProvider(sp))

	if _, ok := srv.routes[0].Auth.(leasedInjector); !ok {
		t.Fatalf("single-key header route built a %T, want leasedInjector", srv.routes[0].Auth)
	}
	serve(srv, http.MethodGet, "/tavily/search", http.Header{"Authorization": {"Bearer caller-token"}})

	h := rec.headerAt(0)
	if got := h.Get("x-api-key"); got != "tvly-tavily-secret-not-real" {
		t.Errorf("x-api-key = %q, want the prefix applied verbatim to the key", got)
	}
	if got := h.Get("Authorization"); got != "" {
		t.Errorf("inbound Authorization survived as %q; a header-mode route must strip it or the caller reaches the upstream as itself", got)
	}
}

// TestHeaderMode_TargetingAuthorizationDoesNotDeleteItsOwnWrite guards the
// order of the Del/Set pair: deleting unconditionally would erase the
// credential this route just wrote.
func TestHeaderMode_TargetingAuthorizationDoesNotDeleteItsOwnWrite(t *testing.T) {
	t.Parallel()
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "odd", Prefix: "/odd/", Upstream: upstream.URL,
		Auth: AuthHeaderInject, KeyHeader: "Authorization", KeyPrefix: "Token ",
		KeyEnv: "ODD_KEY", Enabled: true,
	}}}
	sp := testProvider(map[string]string{"ODD_KEY": "odd-key-not-real"}, nil)
	srv := mustBuildServer(t, cfg, io.Discard, WithSecretProvider(sp))

	serve(srv, http.MethodGet, "/odd/v1", http.Header{"Authorization": {"Bearer caller-token"}})
	if got := rec.seq(); len(got) != 1 || got[0] != "Token odd-key-not-real" {
		t.Errorf("Authorization = %v, want the configured prefix and key", got)
	}
}

// TestHeaderMode_PooledCarriesAuthModeAndKeyIndex is the composition neither
// source branch built: pooling is mode-agnostic because it operates on the key
// INDEX, so a header route pools exactly as an inject route does.
func TestHeaderMode_PooledCarriesAuthModeAndKeyIndex(t *testing.T) {
	t.Parallel()
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	dir := t.TempDir()
	var audit bytes.Buffer
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "exa", Prefix: "/exa/", Upstream: upstream.URL,
		Auth: AuthHeaderInject, KeyHeader: "x-api-key",
		KeyFiles: []string{
			writeKeyFile(t, dir, "exa-1.key", "exa-one-not-real\n"),
			writeKeyFile(t, dir, "exa-2.key", "exa-two-not-real\n"),
		},
		Rotation: &RotationConfig{Policy: PolicyLeastUsed},
		Enabled:  true,
	}}}
	srv := mustBuildServer(t, cfg, &audit, WithSecretProvider(NewDefaultSecretProvider()))

	for range 2 {
		serve(srv, http.MethodGet, "/exa/search", nil)
	}
	got := []string{rec.headerAt(0).Get("x-api-key"), rec.headerAt(1).Get("x-api-key")}
	if got[0] == got[1] {
		t.Errorf("both requests used %q; a pooled header route must rotate", got[0])
	}

	lines := auditLines(t, &audit)
	seen := map[int]bool{}
	for _, l := range lines {
		if l["auth_mode"] != string(AuthHeaderInject) {
			t.Errorf("auth_mode = %v, want %q", l["auth_mode"], AuthHeaderInject)
		}
		idx, ok := keyIndexOf(t, l)
		if !ok {
			t.Fatal("a pooled header route emitted no key_index")
		}
		seen[idx] = true
	}
	if len(seen) != 2 {
		t.Errorf("key indices seen = %v, want both slots", seen)
	}
	assertNoKeyMaterial(t, "audit", audit.String(), "exa-one-not-real", "exa-two-not-real")
}

// -----------------------------------------------------------------------------
// Header mode + budget: the combination no branch supported
// -----------------------------------------------------------------------------

// TestHeaderMode_RequestBudgetRetiresAndThen503s exercises the whole composed
// path: a header-auth upstream reports no usage.total_tokens, so the budget is
// by REQUESTS, every sample is an estimate, and exhaustion is a 503 with a
// Retry-After rather than a 502.
func TestHeaderMode_RequestBudgetRetiresAndThen503s(t *testing.T) {
	t.Parallel()
	rec := newUpstreamRecorder()
	upstream := rec.server()
	defer upstream.Close()

	dir := t.TempDir()
	var audit bytes.Buffer
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "exa", Prefix: "/exa/", Upstream: upstream.URL,
		Auth: AuthHeaderInject, KeyHeader: "x-api-key",
		KeyFiles: []string{
			writeKeyFile(t, dir, "exa-1.key", "exa-one-not-real\n"),
			writeKeyFile(t, dir, "exa-2.key", "exa-two-not-real\n"),
		},
		Rotation: &RotationConfig{
			Policy:        PolicyLeastUsed,
			MaxRetryAfter: 15 * time.Minute,
			// SoftRatio 1 makes the hard cap the only cap, so the arithmetic
			// under test is "one request each", not the default 80% rounding.
			Budget: Budget{Window: 24 * time.Hour, Requests: 1, SoftRatio: 1},
		},
		Enabled: true,
	}}}
	obs := newCountingObserver()
	srv := mustBuildServer(t, cfg, &audit,
		WithSecretProvider(NewDefaultSecretProvider()),
		WithRotationRetireObserver(obs))

	for i := range 2 {
		if got := serve(srv, http.MethodGet, "/exa/search", nil).Code; got != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, got)
		}
	}
	if n := rec.count(); n != 2 {
		t.Fatalf("upstream saw %d requests, want 2", n)
	}

	third := serve(srv, http.MethodGet, "/exa/search", nil)
	if third.Code != http.StatusServiceUnavailable {
		t.Fatalf("exhausted route status = %d, want 503 (502 would page an operator to hunt a broken upstream)", third.Code)
	}
	if rec.count() != 2 {
		t.Error("the gateway contacted the upstream despite every key being drained")
	}
	if ra := third.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("Retry-After = %q, want a positive number of seconds", ra)
	}
	if body := third.Body.String(); !strings.Contains(body, "keys_exhausted") {
		t.Errorf("503 body = %s, want it to name the reason", body)
	}
	assertNoKeyMaterial(t, "503 body", third.Body.String(), "exa-one-not-real", "exa-two-not-real")

	if n := obs.count(ReasonCap); n != 2 {
		t.Errorf("cap retirements = %d, want one per key", n)
	}

	inv := srv.KeyInventory()["exa"]
	want := KeyInventory{Mode: AuthHeaderInject, Pooled: true, Keys: 2, Available: 0, Degraded: true}
	if inv != want {
		t.Errorf("KeyInventory = %+v, want %+v", inv, want)
	}

	// Every sample on a header route is an estimate: the upstream reports no
	// usage object, so a token figure would be invented.
	for _, l := range auditLines(t, &audit) {
		if l["status"] == float64(http.StatusServiceUnavailable) {
			continue
		}
		if l["tokens_estimated"] != true {
			t.Errorf("audit line %v: tokens_estimated = %v, want true on a header route", l, l["tokens_estimated"])
		}
		if _, present := l["tokens"]; present {
			t.Errorf("audit line %v carries a token figure the upstream never reported", l)
		}
	}
}

// -----------------------------------------------------------------------------
// Audit
// -----------------------------------------------------------------------------

// TestAudit_KeyIndexZeroSurvivesEncoding is why AuditEvent.KeyIndex is *int:
// a plain int with omitempty drops slot 0, the most common slot of all.
func TestAudit_KeyIndexZeroSurvivesEncoding(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	zero := 0
	NewAuditor(&buf).Log(AuditEvent{Event: "proxy_request", Route: "mm", KeyIndex: &zero})
	if !strings.Contains(buf.String(), `"key_index":0`) {
		t.Errorf("audit line = %s, want key_index:0 to survive omitempty", buf.String())
	}

	buf.Reset()
	NewAuditor(&buf).Log(AuditEvent{Event: "proxy_request", Route: "mm"})
	if strings.Contains(buf.String(), "key_index") {
		t.Errorf("audit line = %s, want no key_index field at all when none was leased", buf.String())
	}
}

// TestAudit_PassthroughAndBadGatewayLines covers the two lines most easily
// broken by adding a field: a passthrough route (no credential at all) and the
// 502 path (which must still carry the failing slot).
func TestAudit_PassthroughAndBadGatewayLines(t *testing.T) {
	t.Parallel()
	var audit bytes.Buffer
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{
		{Name: "anthropic", Prefix: "/anthropic/", Upstream: "https://example.invalid",
			Auth: AuthPassthrough, Enabled: true},
		{Name: "mm", Prefix: "/mm/", Upstream: "http://127.0.0.1:1", // refused
			Auth: AuthInject, KeyEnvs: []string{"MM_A", "MM_B"}, Enabled: true},
	}}
	sp := testProvider(map[string]string{"MM_A": "key-a-not-real", "MM_B": "key-b-not-real"}, nil)
	srv := mustBuildServer(t, cfg, &audit, WithSecretProvider(sp))

	serve(srv, http.MethodGet, "/anthropic/v1/messages", nil)
	serve(srv, http.MethodGet, "/mm/v1/models", nil)

	lines := auditLines(t, &audit)
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d, want 2", len(lines))
	}
	if _, ok := keyIndexOf(t, lines[0]); ok {
		t.Error("a passthrough line carries key_index; the gateway holds no key there")
	}
	if lines[1]["status"] != float64(http.StatusBadGateway) {
		t.Fatalf("second line status = %v, want 502", lines[1]["status"])
	}
	if _, ok := keyIndexOf(t, lines[1]); !ok {
		t.Error("the 502 line carries no key_index; during a per-key outage that is exactly what an operator needs")
	}
	assertNoKeyMaterial(t, "audit", audit.String(), "key-a-not-real", "key-b-not-real")
}

// -----------------------------------------------------------------------------
// /healthz key inventory
// -----------------------------------------------------------------------------

// TestHealthz_InventorySeparatesByDesignFromByAccident is the reason
// PoolSizes map[string]int was replaced: both a passthrough route and a
// credential-less pool rendered as 0 under the old shape.
func TestHealthz_InventorySeparatesByDesignFromByAccident(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{
		{Name: "legacy", Prefix: "/legacy/", Upstream: "https://example.invalid",
			Auth: AuthInject, KeyEnv: "MM_ONE", Enabled: true},
		{Name: "anthropic", Prefix: "/anthropic/", Upstream: "https://example.invalid",
			Auth: AuthPassthrough, Enabled: true},
		{Name: "pool", Prefix: "/pool/", Upstream: "https://example.invalid",
			Auth: AuthInject, KeyFiles: []string{
				writeKeyFile(t, dir, "p1.key", "slot-one-not-real\n"),
				writeKeyFile(t, dir, "p2.key", "slot-two-not-real\n"),
			}, Enabled: true},
		{Name: "off", Prefix: "/off/", Upstream: "https://example.invalid",
			Auth: AuthInject, KeyEnv: "MM_ONE", Enabled: false},
	}}
	sp := testProvider(map[string]string{"MM_ONE": "single-key-not-real"}, nil)
	srv := mustBuildServer(t, cfg, io.Discard, WithSecretProvider(sp))

	rec := serve(srv, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rec.Code)
	}
	inv := inventoryFrom(t, rec.Body.Bytes())
	want := map[string]KeyInventory{
		"legacy":    {Mode: AuthInject, Pooled: false, Keys: 1, Available: 1},
		"anthropic": {Mode: AuthPassthrough, Pooled: false, Keys: 0, Available: 0},
		"pool":      {Mode: AuthInject, Pooled: true, Keys: 2, Available: 2},
	}
	if len(inv) != len(want) {
		t.Fatalf("inventory = %+v, want exactly the enabled routes %+v", inv, want)
	}
	for name, w := range want {
		if got := inv[name]; got != w {
			t.Errorf("inventory[%q] = %+v, want %+v", name, got, w)
		}
	}
	if _, ok := inv["off"]; ok {
		t.Error("a disabled route appears in the key inventory")
	}
	assertNoKeyMaterial(t, "healthz", rec.Body.String(),
		"single-key-not-real", "slot-one-not-real", "slot-two-not-real")
}

// TestHealthz_EnvelopeShapeIsUnchanged: the existing fields keep their names and
// meanings, so a probe written against baseline still works.
func TestHealthz_EnvelopeShapeIsUnchanged(t *testing.T) {
	t.Parallel()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "mm", Prefix: "/mm/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnv: "MM_ONE", Enabled: true,
	}}}
	sp := testProvider(map[string]string{"MM_ONE": "single-key-not-real"}, nil)
	srv := mustBuildServer(t, cfg, io.Discard, WithSecretProvider(sp))

	rec := serve(srv, http.MethodGet, "/healthz", nil)
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	for _, k := range []string{"status", "service", "routes", "connect", "keys"} {
		if _, ok := env[k]; !ok {
			t.Errorf("healthz envelope is missing %q; got %v", k, env)
		}
	}
	if _, ok := env["pools"]; ok {
		t.Error(`healthz still reports "pools"; the reconciled surface is "keys"`)
	}
	if env["status"] != "ok" || env["service"] != "helixchannel-gateway" {
		t.Errorf("healthz status/service changed: %v", env)
	}
}

// -----------------------------------------------------------------------------
// Concurrency
// -----------------------------------------------------------------------------

// TestConcurrency_PooledRouteAttributesEveryRequestToItsOwnKey: one slot per
// request is race-free by construction. A LastKeyIndex() accessor on the
// Authenticator would misattribute one concurrent request's index to another.
func TestConcurrency_PooledRouteAttributesEveryRequestToItsOwnKey(t *testing.T) {
	t.Parallel()
	keys := map[string]string{"MM_A": "key-a-not-real", "MM_B": "key-b-not-real", "MM_C": "key-c-not-real"}
	byKey := map[string]int{"Bearer key-a-not-real": 0, "Bearer key-b-not-real": 1, "Bearer key-c-not-real": 2}

	// Each request carries its own path segment, because the audit line records
	// the path and not the query — that is what lets the upstream's view and
	// the audit trail be joined per request rather than in aggregate.
	seen := make(chan [2]string, 128)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- [2]string{r.URL.Path, r.Header.Get("Authorization")}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	var audit bytes.Buffer
	cfg := pooledConfig(t, upstream.URL, nil)
	srv := mustBuildServer(t, cfg, &audit, WithSecretProvider(testProvider(keys, nil)))

	const n = 48
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			rec := serve(srv, http.MethodGet, "/mm/req/"+strconv.Itoa(i), nil)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
		}()
	}
	wg.Wait()
	close(seen)

	usedByPath := map[string]int{}
	for got := range seen {
		idx, ok := byKey[got[1]]
		if !ok {
			t.Fatalf("upstream saw an unknown credential %q", got[1])
		}
		usedByPath[got[0]] = idx
	}
	if len(usedByPath) != n {
		t.Fatalf("upstream saw %d distinct requests, want %d", len(usedByPath), n)
	}

	lines := auditLines(t, &audit)
	if len(lines) != n {
		t.Fatalf("audit lines = %d, want %d", len(lines), n)
	}
	for _, l := range lines {
		inbound, _ := l["path"].(string)
		upstreamPath := strings.TrimPrefix(inbound, "/mm")
		idx, ok := keyIndexOf(t, l)
		if !ok {
			t.Fatalf("pooled audit line %v carries no key_index", l)
		}
		want, present := usedByPath[upstreamPath]
		if !present {
			t.Fatalf("audit line for %q has no matching upstream request", inbound)
		}
		if want != idx {
			t.Errorf("%s: audit key_index = %d, upstream saw slot %d", inbound, idx, want)
		}
	}
	assertNoKeyMaterial(t, "audit", audit.String(), "key-a-not-real", "key-b-not-real", "key-c-not-real")
}
