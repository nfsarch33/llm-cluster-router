package channel

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Test doubles.
//
// Every counter is an atomic: these fakes are read by assertions while being
// written by concurrent Resolve calls, and a plain int would fail -race for a
// reason that has nothing to do with the production code.
// -----------------------------------------------------------------------------

// fakeProvider is a SecretProvider whose behaviour is supplied per test.
type fakeProvider struct {
	calls atomic.Int64
	fn    func(ref string) (string, error)
}

func (f *fakeProvider) Resolve(ref string) (string, error) {
	f.calls.Add(1)
	if f.fn == nil {
		return "fake-value-not-real", nil
	}
	return f.fn(ref)
}

// staticEnv builds an env lookup that answers every name with the same result.
func staticEnv(val string, ok bool) func(string) (string, bool) {
	return func(string) (string, bool) { return val, ok }
}

// mapEnv builds an env lookup backed by a map; absent keys report not-set.
func mapEnv(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// countingOPRunner counts invocations atomically and returns a fixed result.
type countingOPRunner struct {
	calls atomic.Int64
	refs  chan string
	out   []byte
	err   error
}

func (c *countingOPRunner) run(_ context.Context, ref string) ([]byte, error) {
	c.calls.Add(1)
	if c.refs != nil {
		select {
		case c.refs <- ref:
		default:
		}
	}
	return c.out, c.err
}

// -----------------------------------------------------------------------------
// envProvider
// -----------------------------------------------------------------------------

func TestEnvProvider_Resolve_ReturnsTrimmedValue(t *testing.T) {
	t.Parallel()
	p := &envProvider{lookup: mapEnv(map[string]string{"MINIMAX_KEY": "  test-key-not-real\n"})}

	got, err := p.Resolve("env:MINIMAX_KEY")
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	if got != "test-key-not-real" {
		t.Errorf("Resolve() = %q, want %q (value still carries surrounding whitespace)", got, "test-key-not-real")
	}
	if got != strings.TrimSpace(got) {
		t.Errorf("Resolve() = %q, which has leading or trailing whitespace", got)
	}
}

// TestEnvProvider_Resolve_WhitespaceOnlyIsAMissNotAnEmptyCredential is THE
// confirmed defect. On 6e32801 readSecret tested os.Getenv(name) != "" BEFORE
// trimming, so "   " passed the check and returned ("", nil). NewServer stored
// that as connToken and subtle.ConstantTimeCompare([]byte(""), []byte("")) == 1
// authorised "Proxy-Authorization: Bearer ".
func TestEnvProvider_Resolve_WhitespaceOnlyIsAMissNotAnEmptyCredential(t *testing.T) {
	t.Parallel()
	p := &envProvider{lookup: mapEnv(map[string]string{"CONNECT_TOKEN": "   "})}

	got, err := p.Resolve("env:CONNECT_TOKEN")
	if err == nil {
		t.Fatalf(`Resolve returned (%q, nil): an empty credential was accepted as success`, got)
	}
	if got != "" {
		t.Errorf("Resolve() value = %q, want empty on failure", got)
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Errorf("errors.Is(err, ErrSecretEmpty) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "env:CONNECT_TOKEN") {
		t.Errorf("error %q does not name the reference %q", err, "env:CONNECT_TOKEN")
	}
}

func TestEnvProvider_Resolve_ErrorPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		ref    string
		lookup func(string) (string, bool)
		want   error
	}{
		{"empty name", "env:", staticEnv("irrelevant", true), ErrSecretRefInvalid},
		{"not set", "env:MISSING", staticEnv("", false), ErrSecretNotFound},
		{"blank", "env:BLANK", staticEnv("", true), ErrSecretEmpty},
		{"tabs and newlines", "env:TABS", staticEnv("\t\n", true), ErrSecretEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &envProvider{lookup: tc.lookup}
			got, err := p.Resolve(tc.ref)
			if err == nil {
				t.Fatalf("Resolve(%q) = (%q, nil), want error %v", tc.ref, got, tc.want)
			}
			if got != "" {
				t.Errorf("Resolve(%q) value = %q, want empty", tc.ref, got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("errors.Is(err, %v) = false, err = %v", tc.want, err)
			}
		})
	}
}

func TestNewEnvProvider_ReadsTheLiveEnvironmentAtResolveTime(t *testing.T) {
	// Not parallel: t.Setenv panics in a parallel test. This proves the
	// default lookup is os.LookupEnv called at Resolve time and never a
	// snapshot taken at construction, which is what keeps the pre-existing
	// t.Setenv-based tests working.
	p := newEnvProvider()
	t.Setenv("TEST_LIVE_LOOKUP_KEY", "test-key-not-real")
	got, err := p.Resolve("env:TEST_LIVE_LOOKUP_KEY")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "test-key-not-real" {
		t.Errorf("Resolve() = %q, want the value set after construction", got)
	}
}

// -----------------------------------------------------------------------------
// fileProvider
// -----------------------------------------------------------------------------

func TestFileProvider_Resolve_StripsTrailingNewline(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "minimax.key")
	if err := os.WriteFile(path, []byte("test-key-not-real\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	p := newFileProvider()

	got, err := p.Resolve("file:" + path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "test-key-not-real" {
		t.Errorf("Resolve() = %q, want %q (a surviving newline would send \"Bearer key\\n\" upstream)", got, "test-key-not-real")
	}
}

func TestFileProvider_Resolve_ErrorPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ref  string
		read func(string) ([]byte, error)
		want error
	}{
		{"empty path", "file:", func(string) ([]byte, error) { return []byte("unused"), nil }, ErrSecretRefInvalid},
		{"absent", "file:/absent", func(string) ([]byte, error) { return nil, fs.ErrNotExist }, ErrSecretNotFound},
		{"unreadable", "file:/locked", func(string) ([]byte, error) { return nil, fs.ErrPermission }, ErrSecretUnavailable},
		{"empty file", "file:/empty", func(string) ([]byte, error) { return []byte{}, nil }, ErrSecretEmpty},
		{"blank file", "file:/blank", func(string) ([]byte, error) { return []byte(" \n"), nil }, ErrSecretEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &fileProvider{read: tc.read}
			got, err := p.Resolve(tc.ref)
			if err == nil {
				t.Fatalf("Resolve(%q) = (%q, nil), want error %v", tc.ref, got, tc.want)
			}
			if got != "" {
				t.Errorf("Resolve(%q) value = %q, want empty", tc.ref, got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("errors.Is(err, %v) = false, err = %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), tc.ref) {
				t.Errorf("error %q does not name the reference %q", err, tc.ref)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// No provider leaks the credential into its error string.
// -----------------------------------------------------------------------------

func TestSecretProviders_ErrorsNeverCarryTheSecret(t *testing.T) {
	t.Parallel()
	const secret = "super-secret-key-value"

	cases := []struct {
		name string
		p    SecretProvider
		ref  string
	}{
		{
			name: "envProvider",
			// The lookup holds the secret; the reference is unusable, so the
			// error must be built from the reference alone.
			p:   &envProvider{lookup: staticEnv(secret, true)},
			ref: "env:",
		},
		{
			name: "fileProvider",
			// The read returns the secret bytes AND an error: an
			// implementation that echoed what it read would leak.
			p:   &fileProvider{read: func(string) ([]byte, error) { return []byte(secret), errors.New("i/o error") }},
			ref: "file:/run/secrets/example.key",
		},
		{
			name: "onepasswordProvider",
			// op's stdout IS the credential. It must never reach the error.
			p: &onepasswordProvider{
				timeout: time.Second,
				run: func(context.Context, string) ([]byte, error) {
					return []byte(secret), &exec.ExitError{Stderr: []byte("not signed in")}
				},
			},
			ref: "op://example-vault/example-item/credential",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.p.Resolve(tc.ref)
			if err == nil {
				t.Fatalf("Resolve(%q) = nil error, want a failure to inspect", tc.ref)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaked the secret %q: %v", secret, err)
			}
			if !strings.Contains(err.Error(), tc.ref) {
				t.Errorf("error %q omits the reference %q (committed config, not secret)", err, tc.ref)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// onepasswordProvider
// -----------------------------------------------------------------------------

func TestOnePasswordProvider_Resolve_UsesTheInjectedRunner(t *testing.T) {
	t.Parallel()
	runner := &countingOPRunner{out: []byte("test-key-not-real\n"), refs: make(chan string, 1)}
	p := &onepasswordProvider{run: runner.run, timeout: time.Second}
	const ref = "op://example-vault/example-item/credential"

	got, err := p.Resolve(ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "test-key-not-real" {
		t.Errorf("Resolve() = %q, want %q", got, "test-key-not-real")
	}
	if n := runner.calls.Load(); n != 1 {
		t.Errorf("runner invocations = %d, want 1", n)
	}
	select {
	case gotRef := <-runner.refs:
		if gotRef != ref {
			t.Errorf("runner received ref %q, want the reference verbatim %q", gotRef, ref)
		}
	default:
		t.Error("runner was never handed a reference")
	}
}

func TestOnePasswordProvider_MalformedRefIsRejectedBeforeAnyProcessStarts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		why string
		ref string
	}{
		{"two segments", "op://example-vault/example-item"},
		{"four segments", "op://example-vault/example-item/cred/extra"},
		{"empty middle segment", "op://example-vault//credential"},
		{"empty vault", "op:///example-item/credential"},
		{"empty field", "op://example-vault/example-item/"},
		{"embedded space", "op://example vault/example-item/credential"},
		{"embedded newline", "op://example-vault/item\n--help/credential"},
		{"no segments", "op://"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			t.Parallel()
			runner := &countingOPRunner{out: []byte("test-key-not-real")}
			p := &onepasswordProvider{run: runner.run, timeout: time.Second}

			got, err := p.Resolve(tc.ref)
			if err == nil {
				t.Fatalf("Resolve(%q) = (%q, nil), want ErrSecretRefInvalid", tc.ref, got)
			}
			if !errors.Is(err, ErrSecretRefInvalid) {
				t.Errorf("errors.Is(err, ErrSecretRefInvalid) = false, err = %v", err)
			}
			if n := runner.calls.Load(); n != 0 {
				t.Errorf("op CLI was invoked for a malformed reference: invocations = %d, want 0", n)
			}
		})
	}
}

func TestOnePasswordProvider_BackendErrorPaths(t *testing.T) {
	t.Parallel()
	const stdout = "super-secret-key-value"
	cases := []struct {
		name string
		out  []byte
		err  error
		want error
	}{
		{"cli absent", []byte(stdout), exec.ErrNotFound, ErrSecretUnavailable},
		{"not signed in", []byte(stdout), &exec.ExitError{Stderr: []byte("not signed in")}, ErrSecretUnavailable},
		{"item not found", []byte(stdout), &exec.ExitError{Stderr: []byte("item not found")}, ErrSecretUnavailable},
		{"empty stdout", []byte(""), nil, ErrSecretEmpty},
		{"blank stdout", []byte(" \n"), nil, ErrSecretEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &onepasswordProvider{
				timeout: time.Second,
				run:     func(context.Context, string) ([]byte, error) { return tc.out, tc.err },
			}
			got, err := p.Resolve("op://example-vault/example-item/credential")
			if err == nil {
				t.Fatalf("Resolve() = (%q, nil), want %v", got, tc.want)
			}
			if got != "" {
				t.Errorf("Resolve() value = %q, want empty", got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("errors.Is(err, %v) = false, err = %v", tc.want, err)
			}
			if len(tc.out) > 0 && strings.Contains(err.Error(), stdout) {
				t.Errorf("error carries the runner's stdout (the credential): %v", err)
			}
		})
	}
}

func TestOnePasswordProvider_MissingCLIMessageNamesTheBinaryAndPath(t *testing.T) {
	t.Parallel()
	p := &onepasswordProvider{
		timeout: time.Second,
		run:     func(context.Context, string) ([]byte, error) { return nil, exec.ErrNotFound },
	}
	_, err := p.Resolve("op://example-vault/example-item/credential")
	if err == nil {
		t.Fatal("Resolve() = nil error, want ErrSecretUnavailable")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"op"`) || !strings.Contains(msg, "PATH") {
		t.Errorf("error %q must name the %q binary and PATH so an operator can fix it without reading source", msg, "op")
	}
}

func TestOnePasswordProvider_StderrIsBounded(t *testing.T) {
	t.Parallel()
	flood := strings.Repeat("x", 100*1024)
	p := &onepasswordProvider{
		timeout: time.Second,
		run: func(context.Context, string) ([]byte, error) {
			return nil, &exec.ExitError{Stderr: []byte(flood)}
		},
	}
	_, err := p.Resolve("op://example-vault/example-item/credential")
	if err == nil {
		t.Fatal("Resolve() = nil error, want a bounded failure")
	}
	if n := len(err.Error()); n >= 512 {
		t.Errorf("error length = %d bytes, want < 512 (a backend must not flood the startup log)", n)
	}
}

func TestOnePasswordProvider_StderrKeepsOnlyTheFirstLine(t *testing.T) {
	t.Parallel()
	p := &onepasswordProvider{
		timeout: time.Second,
		run: func(context.Context, string) ([]byte, error) {
			return nil, &exec.ExitError{Stderr: []byte("first line matters\nsecond line must not appear")}
		},
	}
	_, err := p.Resolve("op://example-vault/example-item/credential")
	if err == nil {
		t.Fatal("Resolve() = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), "first line matters") {
		t.Errorf("error %q dropped the first stderr line", err)
	}
	if strings.Contains(err.Error(), "second line must not appear") {
		t.Errorf("error %q carries more than the first stderr line", err)
	}
}

// TestOnePasswordProvider_HungCLIFailsInsteadOfHangingStartup proves the call
// is bounded by a context deadline. There is no time.Sleep: the fake runner
// blocks on ctx.Done(), so the only thing that can release it is the timeout.
func TestOnePasswordProvider_HungCLIFailsInsteadOfHangingStartup(t *testing.T) {
	t.Parallel()
	p := &onepasswordProvider{
		timeout: time.Millisecond,
		run: func(ctx context.Context, _ string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	got, err := p.Resolve("op://example-vault/example-item/credential")
	if err == nil {
		t.Fatalf("Resolve() = (%q, nil), want a timeout failure", got)
	}
	if !errors.Is(err, ErrSecretUnavailable) {
		t.Errorf("errors.Is(err, ErrSecretUnavailable) = false, err = %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "locked") && !strings.Contains(msg, "biometric") {
		t.Errorf("error %q should hint that the vault may be locked or awaiting biometric approval", err)
	}
}

// -----------------------------------------------------------------------------
// Resolver
// -----------------------------------------------------------------------------

func TestResolver_UnknownSchemeIsRejectedBeforeAnyProviderIsConsulted(t *testing.T) {
	t.Parallel()
	refs := []string{"", "MINIMAX_KEY", "vault:foo/bar", "/run/secrets/k", "op:/vault/i/f", "ENV:NAME"}
	for _, ref := range refs {
		t.Run("ref="+ref, func(t *testing.T) {
			t.Parallel()
			env, file, op := &fakeProvider{}, &fakeProvider{}, &fakeProvider{}
			r := newResolver(map[string]SecretProvider{SchemeEnv: env, SchemeFile: file, SchemeOP: op})

			got, err := r.Resolve(ref)
			if err == nil {
				t.Fatalf("Resolve(%q) = (%q, nil), want ErrSecretRefInvalid", ref, got)
			}
			if !errors.Is(err, ErrSecretRefInvalid) {
				t.Errorf("errors.Is(err, ErrSecretRefInvalid) = false, err = %v", err)
			}
			for name, p := range map[string]*fakeProvider{"env": env, "file": file, "op": op} {
				if n := p.calls.Load(); n != 0 {
					t.Errorf("%s provider consulted %d times for an unrecognised reference, want 0", name, n)
				}
			}
			for _, scheme := range []string{SchemeEnv, SchemeFile, SchemeOP} {
				if !strings.Contains(err.Error(), scheme) {
					t.Errorf("error %q does not list the accepted scheme %q", err, scheme)
				}
			}
		})
	}
}

func TestResolver_RoutesEachSchemeToItsOwnProvider(t *testing.T) {
	t.Parallel()
	env := &fakeProvider{fn: func(string) (string, error) { return "from-env", nil }}
	file := &fakeProvider{fn: func(string) (string, error) { return "from-file", nil }}
	op := &fakeProvider{fn: func(string) (string, error) { return "from-op", nil }}
	r := newResolver(map[string]SecretProvider{SchemeEnv: env, SchemeFile: file, SchemeOP: op})

	cases := []struct{ ref, want string }{
		{"env:A", "from-env"},
		{"file:/b", "from-file"},
		{"op://v/i/f", "from-op"},
	}
	for _, tc := range cases {
		got, err := r.Resolve(tc.ref)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.ref, err)
		}
		if got != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q (a reference reached the wrong provider)", tc.ref, got, tc.want)
		}
	}
	for name, p := range map[string]*fakeProvider{"env": env, "file": file, "op": op} {
		if n := p.calls.Load(); n != 1 {
			t.Errorf("%s provider invoked %d times, want exactly 1", name, n)
		}
	}
}

func TestResolver_CachesSuccessfulResolutions(t *testing.T) {
	t.Parallel()
	op := &fakeProvider{fn: func(string) (string, error) { return "test-key-not-real", nil }}
	r := newResolver(map[string]SecretProvider{SchemeOP: op})
	const ref = "op://example-vault/shared/credential"

	first, err := r.Resolve(ref)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	second, err := r.Resolve(ref)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if first != second {
		t.Errorf("Resolve returned %q then %q, want identical values", first, second)
	}
	if n := op.calls.Load(); n != 1 {
		t.Errorf("op CLI invoked %d times for one reference (a second biometric prompt at startup), want 1", n)
	}
}

func TestResolver_DoesNotCacheFailures(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int64
	op := &fakeProvider{fn: func(string) (string, error) {
		if attempts.Add(1) == 1 {
			return "", secretErr("op://example-vault/example-item/credential", ErrSecretUnavailable, "transient")
		}
		return "test-key-not-real", nil
	}}
	r := newResolver(map[string]SecretProvider{SchemeOP: op})
	const ref = "op://example-vault/example-item/credential"

	if _, err := r.Resolve(ref); err == nil {
		t.Fatal("first Resolve = nil error, want the transient backend failure")
	}
	got, err := r.Resolve(ref)
	if err != nil {
		t.Fatalf("second Resolve: %v (a transient failure poisoned the reference for the process lifetime)", err)
	}
	if got != "test-key-not-real" {
		t.Fatalf("second Resolve = %q, want %q: a cached failure was served as a valid empty credential", got, "test-key-not-real")
	}
	if cached, ok := r.cached(ref); !ok || cached != "test-key-not-real" {
		t.Errorf("cache holds (%q, %v), want the successful value", cached, ok)
	}
}

func TestResolver_ConcurrentDuplicateLookupsCollapseToOneBackendCall(t *testing.T) {
	t.Parallel()
	const goroutines = 16
	release := make(chan struct{})
	op := &fakeProvider{fn: func(string) (string, error) {
		<-release
		return "test-key-not-real", nil
	}}
	r := newResolver(map[string]SecretProvider{SchemeOP: op})
	const ref = "op://example-vault/shared/credential"

	var started, done sync.WaitGroup
	started.Add(goroutines)
	done.Add(goroutines)
	values := make([]string, goroutines)
	errs := make([]error, goroutines)
	for i := range goroutines {
		go func() {
			defer done.Done()
			started.Done()
			values[i], errs[i] = r.Resolve(ref)
		}()
	}
	started.Wait()
	close(release)
	done.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: Resolve error %v", i, errs[i])
		}
		if values[i] != "test-key-not-real" {
			t.Errorf("goroutine %d: Resolve = %q, want %q", i, values[i], "test-key-not-real")
		}
	}
	if n := op.calls.Load(); n != 1 {
		t.Errorf("duplicate concurrent op invocations: backend called %d times, want 1", n)
	}
}

func TestResolver_ConcurrentDistinctRefsNeverCrossContaminate(t *testing.T) {
	t.Parallel()
	const goroutines = 64
	const distinct = 8
	// The fake echoes the reference it was given, so any cross-contamination
	// in the cache shows up immediately as a mismatched value.
	env := &fakeProvider{fn: func(ref string) (string, error) { return "value-for-" + ref, nil }}
	r := newResolver(map[string]SecretProvider{SchemeEnv: env})

	var wg sync.WaitGroup
	wg.Add(goroutines)
	type result struct{ ref, val string }
	results := make([]result, goroutines)
	errs := make([]error, goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			ref := "env:K" + string(rune('0'+i%distinct))
			v, err := r.Resolve(ref)
			results[i] = result{ref: ref, val: v}
			errs[i] = err
		}()
	}
	wg.Wait()

	for i, res := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: Resolve(%q) error %v", i, res.ref, errs[i])
		}
		if want := "value-for-" + res.ref; res.val != want {
			t.Errorf("goroutine %d: Resolve(%q) = %q, want %q (another reference's value was served)", i, res.ref, res.val, want)
		}
	}
}

// -----------------------------------------------------------------------------
// Legacy-field adapter: secretRefs / resolveFirst
// -----------------------------------------------------------------------------

// testResolver builds a Resolver over the real providers with injected
// backends, so the precedence table exercises the production trim-then-check
// logic rather than a fake's approximation.
func testResolver(env map[string]string, files map[string]string, opVal string) *Resolver {
	return newResolver(map[string]SecretProvider{
		SchemeEnv: &envProvider{lookup: mapEnv(env)},
		SchemeFile: &fileProvider{read: func(name string) ([]byte, error) {
			v, ok := files[name]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(v), nil
		}},
		SchemeOP: &onepasswordProvider{
			timeout: time.Second,
			run:     func(context.Context, string) ([]byte, error) { return []byte(opVal), nil },
		},
	})
}

func TestResolveFirst_OrderedFallThroughPreservesTodaysPrecedence(t *testing.T) {
	t.Parallel()
	const keyFile = "/run/secrets/example.key"
	cases := []struct {
		name    string
		keyRef  string
		keyEnv  string
		env     map[string]string
		keyFile string
		want    string
	}{
		{
			name:   "env wins over file (unchanged from today)",
			keyEnv: "K", env: map[string]string{"K": "from-env"}, keyFile: keyFile, want: "from-env",
		},
		{
			name:   "unset env falls through to file (unchanged from today)",
			keyEnv: "K", env: map[string]string{}, keyFile: keyFile, want: "from-file",
		},
		{
			name:   "explicit ref wins over both",
			keyRef: "op://example-vault/example-item/credential",
			keyEnv: "K", env: map[string]string{"K": "from-env"}, keyFile: keyFile, want: "from-op",
		},
		{
			name:   "blank env falls through to file (CHANGED: was a silent empty credential)",
			keyEnv: "K", env: map[string]string{"K": "   "}, keyFile: keyFile, want: "from-file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sp := testResolver(tc.env, map[string]string{keyFile: "from-file"}, "from-op")
			got, err := resolveFirst(sp, secretRefs(tc.keyRef, tc.keyEnv, tc.keyFile))
			if err != nil {
				t.Fatalf("resolveFirst: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveFirst = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveFirst_NothingConfiguredIsAnErrorNotAnEmptyString(t *testing.T) {
	t.Parallel()
	refs := secretRefs("", "", "")
	if len(refs) != 0 {
		t.Fatalf("secretRefs(\"\",\"\",\"\") = %v, want an empty slice", refs)
	}
	got, err := resolveFirst(testResolver(nil, nil, ""), refs)
	if err == nil {
		t.Fatalf("resolveFirst = (%q, nil), want ErrNoSecretSource", got)
	}
	if got != "" {
		t.Errorf("resolveFirst value = %q, want empty", got)
	}
	if !errors.Is(err, ErrNoSecretSource) {
		t.Errorf("errors.Is(err, ErrNoSecretSource) = false, err = %v", err)
	}
}

func TestResolveFirst_ExhaustedCandidatesReportEveryReason(t *testing.T) {
	t.Parallel()
	const keyFile = "/run/secrets/absent.key"
	sp := testResolver(map[string]string{"BLANK": "   "}, map[string]string{}, "")

	got, err := resolveFirst(sp, secretRefs("", "BLANK", keyFile))
	if err == nil {
		t.Fatalf("resolveFirst = (%q, nil), want a combined failure", got)
	}
	if !strings.Contains(err.Error(), "env:BLANK") {
		t.Errorf("error %q does not name the env candidate", err)
	}
	if !strings.Contains(err.Error(), "file:"+keyFile) {
		t.Errorf("error %q does not name the file candidate", err)
	}
	if !errors.Is(err, ErrSecretEmpty) {
		t.Error("the blank env var was silently dropped from the diagnosis: errors.Is(err, ErrSecretEmpty) = false")
	}
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("errors.Is(err, ErrSecretNotFound) = false for the missing file, err = %v", err)
	}
	if strings.Contains(err.Error(), "   ") {
		t.Errorf("error %q carries a source value", err)
	}
}

func TestSecretRefs_SkipsUnsetFieldsAndKeepsOrder(t *testing.T) {
	t.Parallel()
	got := secretRefs("op://v/i/f", "NAME", "/path")
	want := []string{"op://v/i/f", "env:NAME", "file:/path"}
	if len(got) != len(want) {
		t.Fatalf("secretRefs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("secretRefs = %v, want %v", got, want)
		}
	}
	if n := len(secretRefs("", "NAME", "")); n != 1 {
		t.Errorf("secretRefs with only an env name produced %d candidates, want 1", n)
	}
	// An unset field must be ABSENT, not present as a bare scheme: "env:"
	// would reach the resolver as a malformed reference and turn a perfectly
	// valid file-only route into a startup failure.
	if got := secretRefs("", "", "/path"); len(got) != 1 || got[0] != "file:/path" {
		t.Errorf("secretRefs with only a file path produced %v, want [file:/path]", got)
	}
	if got := secretRefs("op://v/i/f", "", ""); len(got) != 1 || got[0] != "op://v/i/f" {
		t.Errorf("secretRefs with only a ref produced %v, want [op://v/i/f]", got)
	}
}
