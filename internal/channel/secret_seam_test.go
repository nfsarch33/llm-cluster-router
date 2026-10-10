package channel

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// M6 — the blank-credential guards on the EXPORTED SecretProvider seam.
//
// THE FALSE GREEN THIS FILE EXISTS TO CLOSE.
//
// The canonical regression set (secret_regression_test.go) injects every blank
// credential through a *Resolver built over envProvider. envProvider.Resolve
// trims BEFORE it tests emptiness, so it answers ErrSecretEmpty and the blank
// value never travels one line further. Every guard DOWNSTREAM of it was
// therefore asserted by nothing: each could be deleted with the whole unit
// suite still green, and three of them were, independently, twice.
//
// WithSecretProvider is exported and SecretProvider is an interface. A
// third-party implementation — Vault, systemd-creds, a wrapper around either —
// is the case the downstream guards were written for, and it is precisely the
// case no test reached. These tests inject through THAT seam: a provider that
// is not a Resolver, contains no envProvider, and hands back exactly what it
// was told to. Whatever it returns arrives at the next guard as written.
//
// WHICH GUARDS THIS FILE CAN KILL, MEASURED RATHER THAN ASSUMED:
//
//	resolveKeyPool  (secret.go)  — REACHABLE. It calls sp.Resolve itself, so a
//	                               blank arrives at the guard untouched. It is
//	                               also the ONLY guard on the pooled path.
//	resolveFirst    (secret.go)  — REACHABLE. Same: it calls sp.Resolve itself.
//	newAuthenticatorFor (auth.go) — NOT independently reachable.
//	NewServer connect  (server.go) — NOT independently reachable.
//
// The last two both read resolveFirst's RESULT, and resolveFirst returns either
// an error or a value that is already trimmed and non-empty. So no provider,
// however hostile, can put a blank in front of them while resolveFirst's own
// guard stands: they are backstops against a future edit to resolveFirst, not
// against a contract-breaking provider, and no test can kill them one at a
// time. Rather than leave them looking covered, their preconditions are pinned
// instead — by TestResolveFirst_NeverHandsBackAValueThatStillNeedsTrimming,
// which fails the moment resolveFirst can return something they would have to
// catch — and their doc comments now say which of the two they are.
// -----------------------------------------------------------------------------

// blankProvider is a SecretProvider that breaks the interface contract on
// purpose: it answers EVERY reference with the same blank value and no error.
//
// It is deliberately a bare fakeProvider rather than a Resolver. A Resolver
// would route the reference to envProvider or fileProvider, either of which
// would trim-and-reject first, and the guard under test would never run — which
// is the exact shape of the false green this file exists to close.
func blankProvider(v string) *fakeProvider {
	return &fakeProvider{fn: func(string) (string, error) { return v, nil }}
}

// refProvider answers per reference, so a pooled route can be given one good
// slot and one blank one and the error can be checked for naming the right
// slot. An unknown reference is a miss, not a blank.
func refProvider(m map[string]string) *fakeProvider {
	return &fakeProvider{fn: func(ref string) (string, error) {
		v, ok := m[ref]
		if !ok {
			return "", secretErr(ref, ErrSecretNotFound, "no such reference")
		}
		return v, nil
	}}
}

// blankCredentials is every shape of "resolved to nothing usable". "" is the
// result the SecretProvider contract calls illegal outright; the rest are the
// whitespace family that shipped as an authorised empty bearer.
var blankCredentials = []struct{ name, val string }{
	{"empty", ""},
	{"one space", " "},
	{"spaces", "   "},
	{"tab", "\t"},
	{"newline", "\n"},
	{"carriage return and tabs", " \t\r\n "},
}

// -----------------------------------------------------------------------------
// THE IMPACT, pinned first, so the guards below have a stated blast radius.
// -----------------------------------------------------------------------------

// TestInjectors_TreatABlankKeyAsACredential is why every guard above them
// matters. bearerInjector and leasedInjector both test key == "" and nothing
// else, so " " is a perfectly good credential as far as they are concerned:
// they are not a layer, and the guards in secret.go are the only thing between
// a contract-breaking provider and "Authorization: Bearer   " on the wire.
//
// This asserts CURRENT behaviour deliberately. bearerInjector and passthrough
// are frozen for this workstream, and moving the check into them would put a
// per-request string scan on the hot path to catch a startup-time condition.
func TestInjectors_TreatABlankKeyAsACredential(t *testing.T) {
	t.Parallel()
	for _, tc := range blankCredentials {
		if tc.val == "" {
			continue // the one case the injectors do catch
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			if err := (&bearerInjector{key: tc.val}).Apply(req); err != nil {
				t.Fatalf("bearerInjector.Apply(%q) = %v; if this now fails, the guards in secret.go "+
					"are no longer the last line and this test should be rewritten, not deleted", tc.val, err)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer "+tc.val {
				t.Errorf("Authorization = %q, want %q", got, "Bearer "+tc.val)
			}

			req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			li := leasedInjector{key: tc.val, header: "X-Api-Key", mode: AuthHeaderInject}
			if err := li.Apply(req); err != nil {
				t.Fatalf("leasedInjector.Apply(%q) = %v", tc.val, err)
			}
			if got := req.Header.Get("X-Api-Key"); got != tc.val {
				t.Errorf("X-Api-Key = %q, want %q", got, tc.val)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// resolveKeyPool — the pooled path's only guard, and independently killable.
// -----------------------------------------------------------------------------

// TestResolveKeyPool_BlankFromACustomProviderIsRejected drives the guard at its
// own layer, one slot only.
//
// One slot, not two: two blank slots would ALSO be caught by
// rejectDuplicateCredentials, so a two-slot case still errors with the guard
// deleted and proves nothing about the guard.
func TestResolveKeyPool_BlankFromACustomProviderIsRejected(t *testing.T) {
	t.Parallel()
	for _, tc := range blankCredentials {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sp := blankProvider(tc.val)
			keys, err := resolveKeyPool(Route{Name: "mm", KeyEnvs: []string{"A"}}, sp)
			if sp.calls.Load() == 0 {
				t.Fatal("the custom provider was never consulted, so this test proves nothing about it")
			}
			if err == nil {
				t.Fatalf("resolveKeyPool accepted %q from a custom provider and built a pool of %d key(s); "+
					"that slot would sign every request routed to it with a blank credential", tc.val, len(keys))
			}
			if !errors.Is(err, ErrSecretEmpty) {
				t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
			}
			if !strings.Contains(err.Error(), "key_envs[0]") {
				t.Errorf("error = %q, want it to name the offending slot", err)
			}
		})
	}
}

// TestResolveKeyPool_NamesTheBlankSlotAndNotTheGoodOne is the same guard with a
// good slot alongside, so the failure cannot come from the pool being empty and
// the slot label is pinned to the right index.
func TestResolveKeyPool_NamesTheBlankSlotAndNotTheGoodOne(t *testing.T) {
	t.Parallel()
	sp := refProvider(map[string]string{
		"env:GOOD":  "pool-key-0-not-real",
		"env:BLANK": " \t ",
	})
	_, err := resolveKeyPool(Route{Name: "mm", KeyEnvs: []string{"GOOD", "BLANK"}}, sp)
	if err == nil {
		t.Fatal("a pool with one blank slot was accepted; it would carry a dead account at a fixed key_index " +
			"while /healthz reported a healthy rotation")
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "key_envs[1]") {
		t.Errorf("error = %q, want it to name key_envs[1]", err)
	}
	if strings.Contains(err.Error(), "key_envs[0]") {
		t.Errorf("error = %q, want it to leave the good slot out of the diagnosis", err)
	}
	if strings.Contains(err.Error(), "pool-key-0-not-real") {
		t.Errorf("error = %q carries a resolved credential", err)
	}
}

// TestNewServer_PooledRouteRefusesABlankCredentialFromACustomProvider is the
// same guard reached the way an operator would reach it: NewServer, through the
// exported WithSecretProvider option, with a pooled route.
//
// This is an INDEPENDENT kill, not a composite one. resolveKeyPool is the only
// blank check on the pooled path — there is no resolveFirst in front of it, and
// leasedInjector accepts any non-empty key — so deleting it lets this server
// build and put the blank on the wire.
func TestNewServer_PooledRouteRefusesABlankCredentialFromACustomProvider(t *testing.T) {
	t.Parallel()
	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "pooled", Prefix: "/p/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnvs: []string{"A"}, Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sp := blankProvider("   ")

	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
	if err == nil {
		t.Fatal(`NewServer built a pooled route on a blank credential from a custom provider; ` +
			`every leased request would carry "Authorization: Bearer   "`)
	}
	if srv != nil {
		t.Errorf("NewServer returned a non-nil *Server alongside an error: %v", srv)
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), `"pooled"`) {
		t.Errorf("error %q does not name the route", err)
	}
}

// TestNewServer_PooledRouteUsesExactlyWhatACustomProviderReturns is the
// positive control for the test above.
//
// Without it, that refusal could come from any mis-wiring — a config the seam
// never reaches, a provider never consulted — and would still look like a pass.
// This proves the same wiring, with a usable value, resolves THROUGH the custom
// provider and puts that exact value on the wire: so but for the guard, the
// blank would have gone there instead.
func TestNewServer_PooledRouteUsesExactlyWhatACustomProviderReturns(t *testing.T) {
	t.Parallel()
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get("Authorization"):
		default:
		}
		_, _ = io.WriteString(w, "{}")
	}))
	defer upstream.Close()

	cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "pooled", Prefix: "/p/", Upstream: upstream.URL,
		Auth: AuthInject, KeyEnvs: []string{"A"}, Enabled: true,
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sp := refProvider(map[string]string{"env:A": "custom-provider-key-not-real"})

	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
	if err != nil {
		t.Fatalf("NewServer with a usable custom-provider value: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/p/v1/models", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("gateway status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	select {
	case got := <-seen:
		if got != "Bearer custom-provider-key-not-real" {
			t.Errorf("upstream Authorization = %q, want the custom provider's value; "+
				"the seam under test is not the one carrying the credential", got)
		}
	default:
		t.Fatal("the upstream was never reached")
	}
}

// -----------------------------------------------------------------------------
// resolveFirst — the single-key and CONNECT paths' only reachable guard.
// -----------------------------------------------------------------------------

// TestResolveFirst_BlankFromACustomProviderIsAMissNotACredential drives the
// guard at its own layer. Reaching it through NewServer would not do: the trims
// in newAuthenticatorFor and NewServer sit behind it and would catch the same
// value, so the end-to-end refusal survives deleting any one of the three.
func TestResolveFirst_BlankFromACustomProviderIsAMissNotACredential(t *testing.T) {
	t.Parallel()
	for _, tc := range blankCredentials {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sp := blankProvider(tc.val)
			got, err := resolveFirst(sp, secretRefs("", "ONLY", ""))
			if sp.calls.Load() == 0 {
				t.Fatal("the custom provider was never consulted, so this test proves nothing about it")
			}
			if err == nil {
				t.Fatalf("resolveFirst returned (%q, nil) for a provider that answered %q; "+
					"its contract is that it never hands back a value that is not a credential", got, tc.val)
			}
			if got != "" {
				t.Errorf("resolveFirst returned value %q alongside an error", got)
			}
			if !errors.Is(err, ErrSecretEmpty) {
				t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
			}
			if !strings.Contains(err.Error(), "env:ONLY") {
				t.Errorf("error = %q, want it to name the reference that came back blank", err)
			}
		})
	}
}

// TestResolveFirst_ABlankCandidateFallsThroughToTheNextSource pins the guard's
// SEMANTIC as well as its existence: a blank source is a MISS, so the next
// candidate is tried, exactly as it is for a blank env var. A guard that turned
// it into a hard failure would break a config that legitimately keeps an empty
// placeholder env var alongside a real key file.
func TestResolveFirst_ABlankCandidateFallsThroughToTheNextSource(t *testing.T) {
	t.Parallel()
	sp := refProvider(map[string]string{
		"env:BLANK":      "   ",
		"file:/real.key": "fallthrough-key-not-real",
	})
	got, err := resolveFirst(sp, secretRefs("", "BLANK", "/real.key"))
	if err != nil {
		t.Fatalf("resolveFirst = %v, want the file candidate to be reached", err)
	}
	if got != "fallthrough-key-not-real" {
		t.Errorf("resolveFirst = %q, want the second candidate; a blank first source was treated as a credential", got)
	}
}

// TestResolveFirst_NeverHandsBackAValueThatStillNeedsTrimming is the PRECONDITION
// TEST for the two guards that cannot be killed independently: the trim in
// newAuthenticatorFor and the trim in NewServer's CONNECT block.
//
// Both read resolveFirst's result and both are unreachable while this property
// holds, because a value that is non-empty and equal to its own TrimSpace is
// one neither of them can reject. That makes them backstops, not layers — and
// makes this the test that has to fail first if an edit to resolveFirst ever
// promotes them to layers. If it does, they need independent tests of their own
// and this comment is the notice to write them.
func TestResolveFirst_NeverHandsBackAValueThatStillNeedsTrimming(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sp   SecretProvider
		refs []string
	}{
		{"blank only", blankProvider("   "), secretRefs("", "A", "")},
		{"empty only", blankProvider(""), secretRefs("", "A", "")},
		{"newline only", blankProvider("\n"), secretRefs("", "A", "")},
		{"padded value", blankProvider("  padded-key-not-real \n"), secretRefs("", "A", "")},
		{"no candidates", blankProvider("x"), nil},
		{"every candidate blank", blankProvider(" "), secretRefs("op://v/i/f", "A", "/k")},
		{"blank then padded", refProvider(map[string]string{
			"env:A": " ", "file:/k": "\ttabbed-key-not-real\t",
		}), secretRefs("", "A", "/k")},
		{"error then blank", refProvider(map[string]string{"file:/k": "  "}), secretRefs("", "A", "/k")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveFirst(tc.sp, tc.refs)
			if err != nil {
				if got != "" {
					t.Errorf("resolveFirst = (%q, %v); an error result must carry no value", got, err)
				}
				return
			}
			if got == "" {
				t.Fatal(`resolveFirst returned ("", nil); the trims in newAuthenticatorFor and NewServer ` +
					`are now REACHABLE and need independent tests — see this test's doc comment`)
			}
			if got != strings.TrimSpace(got) {
				t.Fatalf("resolveFirst returned %q, which still needs trimming; the trims in "+
					"newAuthenticatorFor and NewServer are now REACHABLE and need independent tests", got)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// End to end through the seam. COMPOSITE assertions, labelled as such: each
// survives the deletion of any ONE of the three layers behind it, which is
// exactly why the layer tests above exist as well.
// -----------------------------------------------------------------------------

func TestNewServer_RefusesABlankCredentialFromACustomProvider(t *testing.T) {
	t.Parallel()
	singleKey := &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name: "single", Prefix: "/s/", Upstream: "https://example.invalid",
		Auth: AuthInject, KeyEnv: "K", Enabled: true,
	}}}
	cases := []struct {
		name string
		cfg  *Config
		want string // substring the operator needs to see
	}{
		{"single-key inject route", singleKey, `"single"`},
		{"connect token", connectConfig("K", ""), "connect:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.cfg.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			sp := blankProvider(" \t ")
			srv, err := NewServer(tc.cfg, NewHTTPForwarder(), NewAuditor(io.Discard), WithSecretProvider(sp))
			if sp.calls.Load() == 0 {
				t.Fatal("the custom provider was never consulted, so this test proves nothing about it")
			}
			if err == nil {
				t.Fatal("NewServer accepted a blank credential from a custom provider")
			}
			if srv != nil {
				t.Errorf("NewServer returned a non-nil *Server alongside an error: %v", srv)
			}
			if !errors.Is(err, ErrSecretEmpty) {
				t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}
