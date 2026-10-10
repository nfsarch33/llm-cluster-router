package channel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// S1/S2 — a hung 1Password CLI must fail startup, not hang it.
//
// The predecessor test for this property asserted the deadline against an
// INJECTED runner that voluntarily returned on <-ctx.Done(). It was green in a
// tree where the production path blocked forever, because it never reached
// execOPRead. The tests below split the property across the two layers that
// actually own it, so each is provable on its own:
//
//	execOPRead                     — must return after the deadline even when a
//	                                 child process it did not create is still
//	                                 holding the inherited stdout pipe.
//	onepasswordProvider.Resolve    — must return at the deadline even when the
//	                                 injected OPRunner never returns at all.
//	                                 OPRunner is an EXPORTED seam, so runner
//	                                 cooperation cannot be assumed.
// -----------------------------------------------------------------------------

// hangBound is how long a test waits before declaring a startup hang. The
// measured defect blocked for 45s against a 15s DefaultOPTimeout; every test
// here drives a sub-second deadline, so anything past this bound is a hang and
// not slowness.
const hangBound = 20 * time.Second

// requirePOSIXShell skips a test that needs a #!/bin/sh stub executable.
func requirePOSIXShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("stub executable relies on a POSIX shebang; GOOS = %s", runtime.GOOS)
	}
}

// writeHungOPStub writes a fake `op` into dir that reproduces the exact shape
// of the hang: the DIRECT child exits immediately and successfully, leaving a
// grandchild that inherited stdout and refuses to exit for holdSeconds.
//
// That is failure mode (b) in the exec.Cmd.WaitDelay documentation — the
// process is gone, the pipe is not — and it is why cancelling the context is
// not by itself enough: cmd.Output() reads until an EOF that never comes.
func writeHungOPStub(t *testing.T, dir string, holdSeconds int) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\nsleep %d &\nexit 0\n", holdSeconds)
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte(script), 0o700); err != nil {
		t.Fatalf("write hung op stub: %v", err)
	}
}

// prependToPATH puts dir first on PATH for the duration of the test. It uses
// t.Setenv, so no caller may declare t.Parallel.
func prependToPATH(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestExecOPRead_ReturnsWhenAChildHoldsStdoutPastTheDeadline(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	writeHungOPStub(t, dir, 30)
	prependToPATH(t, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := execOPRead(ctx, "op://example-vault/example-item/credential")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("execOPRead returned a nil error after %v; a CLI that never closes stdout must fail", time.Since(start))
		}
		// Naming the mechanism, not just "an error": the context deadline
		// alone cannot end this read, because the process it would cancel has
		// already exited. Only WaitDelay closes the pipe the grandchild holds.
		if !errors.Is(err, exec.ErrWaitDelay) {
			t.Errorf("execOPRead err = %v (errors.Is ErrWaitDelay = false); "+
				"something other than exec.Cmd.WaitDelay released this read", err)
		}
	case <-time.After(hangBound):
		t.Fatalf("execOPRead still blocked %v after a 300ms context deadline: "+
			"a grandchild holding the inherited stdout pipe hangs cmd.Output() forever. "+
			"exec.Cmd.WaitDelay is unset, so nothing ever closes that pipe", hangBound)
	}
}

func TestOnePasswordProvider_ResolveHonoursTheDeadlineWhenTheRunnerNeverReturns(t *testing.T) {
	t.Parallel()
	// The runner deliberately does NOT select on ctx.Done(). OPRunner is an
	// exported seam: a third-party runner that ignores its context must not be
	// able to hang NewServer.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p := &onepasswordProvider{
		timeout: 50 * time.Millisecond,
		run: func(context.Context, string) ([]byte, error) {
			<-release
			return []byte("test-key-not-real"), nil
		},
	}

	done := make(chan error, 1)
	go func() {
		_, err := p.Resolve("op://example-vault/example-item/credential")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Resolve() = nil error, want a timeout failure")
		}
		if !errors.Is(err, ErrSecretUnavailable) {
			t.Errorf("errors.Is(err, ErrSecretUnavailable) = false, err = %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
		}
	case <-time.After(hangBound):
		t.Fatalf("Resolve still blocked %v after a 50ms timeout: the deadline is honoured "+
			"only when the injected runner volunteers to return, so an uncooperative "+
			"OPRunner hangs startup", hangBound)
	}
}

// -----------------------------------------------------------------------------
// S3 — a credential pasted into key_ref/token_ref must not reach an error
// string. Ref was interpolated verbatim and unbounded; maxCLIErrDetail bounds
// stderr only.
// -----------------------------------------------------------------------------

// disclosureSentinel stands in for a real key pasted into the new key_ref /
// token_ref field. It is obvious junk, it is not a credential for anything, and
// no test here ever sends it anywhere.
const disclosureSentinel = "sk-live-DO-NOT-LOG-4f9a2c7e1b8d6053-not-a-real-key"

func TestSecretError_UnrecognisedReferenceIsRedacted(t *testing.T) {
	t.Parallel()
	e := &SecretError{Ref: disclosureSentinel, Err: ErrSecretRefInvalid}

	msg := e.Error()
	if strings.Contains(msg, disclosureSentinel) {
		t.Fatalf("SecretError.Error() = %q; it echoed a value that carries no known scheme "+
			"verbatim, which is exactly the shape a pasted credential takes", msg)
	}
	// Redaction must not cost the operator the diagnosis.
	if !strings.Contains(msg, ErrSecretRefInvalid.Error()) {
		t.Errorf("SecretError.Error() = %q, want it to still name the cause %q", msg, ErrSecretRefInvalid)
	}
}

func TestSecretError_RecognisedReferenceSurvivesButIsBounded(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ref  string
		want string // must appear verbatim
	}{
		{"short env ref", "env:MINIMAX_KEY", "env:MINIMAX_KEY"},
		{"bare scheme", "env:", "env:"},
		{"file ref", "file:/run/secrets/example.key", "file:/run/secrets/example.key"},
		{"op ref", "op://example-vault/example-item/credential", "op://example-vault/example-item/credential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := (&SecretError{Ref: tc.ref, Err: ErrSecretNotFound}).Error()
			if !strings.Contains(got, tc.want) {
				t.Errorf("SecretError.Error() = %q, want it to contain the reference %q", got, tc.want)
			}
		})
	}

	t.Run("pathological length is clipped", func(t *testing.T) {
		t.Parallel()
		long := SchemeEnv + strings.Repeat("A", 4096)
		got := (&SecretError{Ref: long, Err: ErrSecretNotFound}).Error()
		if len(got) > 512 {
			t.Errorf("SecretError.Error() is %d bytes for a 4KiB reference; an unbounded "+
				"reference floods the startup log just as unbounded stderr would", len(got))
		}
		if !strings.HasPrefix(strings.TrimPrefix(got, `secret "`), SchemeEnv) {
			t.Errorf("SecretError.Error() = %q, want the scheme %q kept so the operator can still tell which backend failed", got, SchemeEnv)
		}
	})
}

// TestSecretDisclosure_SentinelNeverReachesAnyErrorString walks the whole
// startup surface that accepts the new *_ref fields and proves the sentinel
// reaches none of the resulting error strings.
func TestSecretDisclosure_SentinelNeverReachesAnyErrorString(t *testing.T) {
	t.Parallel()

	route := func() Route {
		return Route{
			Name: "mm", Prefix: "/mm/", Upstream: "https://upstream.invalid",
			Auth: AuthInject, Enabled: true, KeyRef: disclosureSentinel,
		}
	}

	cases := []struct {
		name string
		fn   func() error
	}{
		{"validateSecretRef", func() error { return validateSecretRef(disclosureSentinel) }},
		{"Resolver.Resolve", func() error {
			_, err := NewDefaultSecretProvider().Resolve(disclosureSentinel)
			return err
		}},
		{"resolveFirst", func() error {
			_, err := resolveFirst(NewDefaultSecretProvider(), secretRefs(disclosureSentinel, "", ""))
			return err
		}},
		{"Config.Validate route key_ref", func() error {
			cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{route()}}
			return cfg.Validate()
		}},
		{"Config.Validate connect token_ref", func() error {
			r := route()
			r.KeyRef = ""
			r.KeyEnv = "EXAMPLE_KEY"
			cfg := &Config{
				Listen: "127.0.0.1:0", Routes: []Route{r},
				Connect: ConnectConfig{
					Enabled:      true,
					AllowedHosts: []string{"api.example.invalid:443"},
					TokenRef:     disclosureSentinel,
				},
			}
			return cfg.Validate()
		}},
		{"NewServer route key_ref", func() error {
			cfg := &Config{Listen: "127.0.0.1:0", Routes: []Route{route()}}
			_, err := NewServer(cfg, nil, nil)
			return err
		}},
		{"NewServer connect token_ref", func() error {
			cfg := &Config{
				Listen: "127.0.0.1:0",
				Connect: ConnectConfig{
					Enabled:      true,
					AllowedHosts: []string{"api.example.invalid:443"},
					TokenRef:     disclosureSentinel,
				},
			}
			_, err := NewServer(cfg, nil, nil)
			return err
		}},
		{"resolveKeyPool key_refs", func() error {
			r := route()
			r.KeyRef = ""
			r.KeyRefs = []string{disclosureSentinel, "env:EXAMPLE_KEY_ABSENT"}
			_, err := resolveKeyPool(r, NewDefaultSecretProvider())
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.fn()
			if err == nil {
				t.Fatalf("%s accepted %q; a value with no scheme is not a reference", tc.name, "<sentinel>")
			}
			if strings.Contains(err.Error(), disclosureSentinel) {
				t.Errorf("%s echoed the pasted credential into its error string: %v", tc.name, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// S5 — a world-writable credential file is accepted in silence, while the
// key_file documentation sells "root-owned files ... keeps them off the wire".
// -----------------------------------------------------------------------------

// fakeFileInfo is the minimum fs.FileInfo a permission check can read.
type fakeFileInfo struct{ mode fs.FileMode }

func (f fakeFileInfo) Name() string       { return "example.key" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// warnSink collects warnings. It is mutex-guarded because Resolve is
// documented as safe for concurrent use.
type warnSink struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnSink) warn(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, fmt.Sprintf(format, args...))
}

func (w *warnSink) all() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.msgs...)
}

func TestFileProvider_WarnsLoudlyAboutAGroupOrWorldAccessibleCredentialFile(t *testing.T) {
	t.Parallel()
	const secret = "test-key-not-real"
	cases := []struct {
		name     string
		mode     fs.FileMode
		wantWarn bool
	}{
		{"owner only", 0o600, false},
		{"owner read only", 0o400, false},
		{"group readable", 0o640, true},
		{"world readable", 0o644, true},
		{"world writable", 0o666, true},
		{"wide open", 0o777, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := &warnSink{}
			p := &fileProvider{
				read: func(string) ([]byte, error) { return []byte(secret + "\n"), nil },
				stat: func(string) (fs.FileInfo, error) { return fakeFileInfo{mode: tc.mode}, nil },
				warn: sink.warn,
			}

			got, err := p.Resolve("file:/run/secrets/example.key")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != secret {
				t.Fatalf("Resolve() = %q, want %q; the permission check must not change the value", got, secret)
			}

			msgs := sink.all()
			switch {
			case tc.wantWarn && len(msgs) == 0:
				t.Fatalf("mode %04o was accepted in silence; group or other can reach the credential", tc.mode.Perm())
			case !tc.wantWarn && len(msgs) != 0:
				t.Fatalf("mode %04o warned needlessly: %q", tc.mode.Perm(), msgs)
			}
			if !tc.wantWarn {
				return
			}
			msg := msgs[0]
			if strings.Contains(msg, secret) {
				t.Errorf("the permission warning leaked the credential: %q", msg)
			}
			for _, want := range []string{fmt.Sprintf("%04o", tc.mode.Perm()), "chmod"} {
				if !strings.Contains(msg, want) {
					t.Errorf("warning %q omits %q; a warning an operator cannot act on is not loud", msg, want)
				}
			}
		})
	}
}

func TestNewFileProvider_ChecksPermissionsByDefault(t *testing.T) {
	t.Parallel()
	p := newFileProvider()
	if p.stat == nil {
		t.Error("the default fileProvider cannot see a file's mode, so it can never warn about one")
	}
	if p.warn == nil {
		t.Error("the default fileProvider has nowhere to send a warning")
	}
}

// TestFileProvider_RealWorldWritableFileIsWarnedAbout exercises the default
// os.Stat wiring against a real file rather than an injected fake.
func TestFileProvider_RealWorldWritableFileIsWarnedAbout(t *testing.T) {
	requirePOSIXShell(t)
	path := filepath.Join(t.TempDir(), "example.key")
	if err := os.WriteFile(path, []byte("test-key-not-real\n"), 0o600); err != nil {
		t.Fatalf("write credential file: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	sink := &warnSink{}
	p := newFileProvider()
	p.warn = sink.warn

	if _, err := p.Resolve(SchemeFile + path); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(sink.all()) == 0 {
		t.Fatal("a real 0666 credential file was accepted in silence")
	}
}
