package channel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sync/singleflight"
)

// SecretProvider resolves an opaque reference to a credential value.
//
// This is the OCP seam that replaced readSecret. A new credential backend
// (Vault, AWS Secrets Manager, systemd-creds) is a new implementation plus one
// map entry in NewDefaultSecretProvider — never an edit to auth.go or server.go.
//
// Contract, binding on every implementation:
//
//   - A successful Resolve returns a whitespace-TRIMMED, NON-EMPTY value.
//     ("", nil) is never a legal result. That exact shape is what let a blank
//     environment variable become an authorised empty CONNECT token.
//   - Errors never contain the secret value, and never contain the backend's
//     stdout (which IS the secret for the op CLI). References may appear: they
//     live in committed config and are not secret.
//   - Resolve is safe for concurrent use by multiple goroutines.
type SecretProvider interface {
	Resolve(ref string) (string, error)
}

// Reference schemes understood by the default Resolver.
const (
	SchemeEnv  = "env:"
	SchemeFile = "file:"
	SchemeOP   = "op://"
)

// DefaultOPTimeout bounds one `op read` invocation. A locked vault waiting on
// biometric approval must fail startup, not hang it forever.
const DefaultOPTimeout = 15 * time.Second

// opRefSegments is the segment count required after "op://": vault/item/field.
const opRefSegments = 3

// opWaitDelay is the grace `op` gets, after its context is done or it has
// exited, before exec force-kills it and closes its I/O pipes. It bounds the
// second half of the hang execOPRead documents: a well-behaved CLI never
// reaches it, because its pipes close when it exits.
const opWaitDelay = 2 * time.Second

// maxCLIErrDetail caps how much CLI stderr is echoed into an error, so a
// pathological backend cannot flood the startup log.
const maxCLIErrDetail = 200

// maxRefDetail caps how much of a REFERENCE is echoed into an error. Bounding
// stderr alone left key_ref/token_ref as an unbounded second channel into the
// same log.
const maxRefDetail = 96

// Sentinel causes. Callers assert with errors.Is; messages stay free to change.
var (
	// ErrNoSecretSource means the configuration named no credential source.
	ErrNoSecretSource = errors.New("no credential source configured")
	// ErrSecretRefInvalid means the reference is syntactically unusable.
	ErrSecretRefInvalid = errors.New("malformed secret reference")
	// ErrSecretNotFound means the named source does not exist.
	ErrSecretNotFound = errors.New("secret source absent")
	// ErrSecretEmpty means the source exists but holds nothing usable. This is
	// the sentinel for the whitespace-credential defect.
	ErrSecretEmpty = errors.New("secret resolved to an empty value")
	// ErrSecretUnavailable means the backend could not be consulted at all.
	ErrSecretUnavailable = errors.New("secret backend unavailable")
)

// SecretError attributes a resolution failure to a reference.
//
// The resolved value is deliberately absent from the struct so it cannot be
// logged by accident. Ref is rendered through safeRef rather than printed
// verbatim: see there for why a well-formed reference is safe and an
// unrecognised one is not.
type SecretError struct {
	Ref    string // e.g. "env:MINIMAX_KEY" — never the value
	Detail string // bounded, non-secret diagnostic (exit code, stderr line)
	Err    error  // one of the sentinels above
}

func (e *SecretError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("secret %q: %v", safeRef(e.Ref), e.Err)
	}
	return fmt.Sprintf("secret %q: %v: %s", safeRef(e.Ref), e.Err, e.Detail)
}

// safeRef renders a reference for an operator-visible message.
//
// A well-formed reference is committed configuration, not a secret, so its
// scheme and payload are printed: "env:MINIMAX_KEY" is exactly what the
// operator needs to fix the problem.
//
// A string carrying NO known scheme is not a reference at all, and the
// commonest way one arrives is an operator pasting the KEY ITSELF into key_ref
// or token_ref instead of a pointer to it. Interpolating that verbatim puts a
// live credential into the startup error, the operator's terminal and every
// log that carries it — a disclosure surface that arrived with the *_ref
// fields. Nothing of such a value is printed but its length.
//
// Recognised references are clipped too. maxCLIErrDetail already refuses to let
// a backend flood the startup log through stderr; a 4KiB key_ref must not be
// the way around it.
func safeRef(ref string) string {
	scheme, ok := refScheme(ref)
	if !ok {
		return fmt.Sprintf("<unrecognised reference, %d bytes, redacted>", len(ref))
	}
	rest := strings.TrimPrefix(ref, scheme)
	if len(rest) > maxRefDetail {
		// Clip on a rune boundary so a multi-byte reference cannot be turned
		// into invalid UTF-8 by the truncation itself.
		cut := maxRefDetail
		for cut > 0 && !utf8.RuneStart(rest[cut]) {
			cut--
		}
		rest = rest[:cut] + "..."
	}
	return scheme + rest
}

// refScheme reports which registered scheme a reference carries. It returns no
// error, so it is safe to call from Error() without building an error to
// describe a failure to build an error.
func refScheme(ref string) (string, bool) {
	for _, s := range []string{SchemeEnv, SchemeFile, SchemeOP} {
		if strings.HasPrefix(ref, s) {
			return s, true
		}
	}
	return "", false
}

func (e *SecretError) Unwrap() error { return e.Err }

func secretErr(ref string, cause error, detail string) error {
	return &SecretError{Ref: ref, Detail: detail, Err: cause}
}

// -----------------------------------------------------------------------------
// envProvider — "env:NAME"
// -----------------------------------------------------------------------------

// envProvider resolves a reference against the process environment.
//
// lookup is injectable so tests never need t.Setenv (which forbids t.Parallel)
// and never mutate global process state. It is called at Resolve time, never
// snapshotted at construction, so a value exported after the provider is built
// is still seen.
type envProvider struct {
	lookup func(key string) (string, bool)
}

func newEnvProvider() *envProvider { return &envProvider{lookup: os.LookupEnv} }

// Resolve trims FIRST and tests emptiness SECOND.
//
// That ordering is the whole fix. The predecessor tested os.Getenv(name) != ""
// before trimming, so an environment variable holding "   " passed the
// non-empty check and then trimmed to "" — a silent empty credential that
// authorised an empty bearer token on the CONNECT leg.
func (p *envProvider) Resolve(ref string) (string, error) {
	name := strings.TrimPrefix(ref, SchemeEnv)
	if name == "" {
		return "", secretErr(ref, ErrSecretRefInvalid, "environment variable name is empty")
	}
	raw, ok := p.lookup(name)
	if !ok {
		return "", secretErr(ref, ErrSecretNotFound, "environment variable is not set")
	}
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", secretErr(ref, ErrSecretEmpty, "environment variable holds only whitespace")
	}
	return v, nil
}

// -----------------------------------------------------------------------------
// fileProvider — "file:/path/to/secret"
// -----------------------------------------------------------------------------

type fileProvider struct {
	read func(name string) ([]byte, error)
	stat func(name string) (fs.FileInfo, error)
	warn func(format string, args ...any)
}

func newFileProvider() *fileProvider {
	return &fileProvider{read: os.ReadFile, stat: os.Stat, warn: warnf}
}

// warnf is the package's only log sink. It exists so a security warning has
// somewhere to go that is not an error return: a loose-permission credential
// file must be shouted about, but refusing to start would break every operator
// whose file is 0644 today.
func warnf(format string, args ...any) {
	log.Printf("helixchannel: "+format, args...)
}

// Resolve reads the file and trims. The file's bytes never enter the returned
// error: the detail strings below are fixed text, so a key file whose contents
// happen to look like a diagnostic cannot be echoed into a log.
func (p *fileProvider) Resolve(ref string) (string, error) {
	path := strings.TrimPrefix(ref, SchemeFile)
	if path == "" {
		return "", secretErr(ref, ErrSecretRefInvalid, "file path is empty")
	}
	b, err := p.read(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", secretErr(ref, ErrSecretNotFound, "file does not exist")
	case errors.Is(err, fs.ErrPermission):
		return "", secretErr(ref, ErrSecretUnavailable, "file is not readable")
	case err != nil:
		return "", secretErr(ref, ErrSecretUnavailable, "file could not be read")
	}
	p.warnOnLoosePermissions(ref, path)
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", secretErr(ref, ErrSecretEmpty, "file holds only whitespace")
	}
	return v, nil
}

// nonOwnerPerm is every permission bit outside the file owner's.
const nonOwnerPerm fs.FileMode = 0o077

// warnOnLoosePermissions shouts about a credential file that group or other can
// reach.
//
// config.go sells key_file on "root-owned files ... is what keeps them off the
// wire": that guarantee is made by the FILESYSTEM, and a 0666 key file silently
// voids it while the configuration still looks correct. Nothing checked it.
//
// This warns rather than refuses on purpose. Turning an existing 0644 key file
// into a startup failure would take a gateway down at upgrade time, mid-
// incident, over a condition that was already true yesterday. The warning names
// the mode and the remedy so it is actionable on sight; the value never appears.
func (p *fileProvider) warnOnLoosePermissions(ref, path string) {
	if p.stat == nil || p.warn == nil {
		return
	}
	fi, err := p.stat(path)
	if err != nil {
		// The read already succeeded. A stat that does not is not worth
		// failing a resolution that otherwise worked.
		return
	}
	mode := fi.Mode().Perm()
	if mode&nonOwnerPerm == 0 {
		return
	}
	p.warn("SECURITY: credential file for %s is mode %04o - group or other can read or write it, "+
		"so the filesystem is no longer protecting this key; chmod 600 it and rotate the key if the host is shared",
		safeRef(ref), mode)
}

// -----------------------------------------------------------------------------
// onepasswordProvider — "op://<vault>/<item>/<field>"
// -----------------------------------------------------------------------------

// OPRunner executes one `op read` and returns its STDOUT.
//
// This is the injectable seam that guarantees no unit test ever executes the
// real CLI or contacts a real vault. The returned bytes are the secret and
// must never be placed in an error.
type OPRunner func(ctx context.Context, ref string) (stdout []byte, err error)

type onepasswordProvider struct {
	run     OPRunner
	timeout time.Duration
}

func newOnePasswordProvider() *onepasswordProvider {
	return &onepasswordProvider{run: execOPRead, timeout: DefaultOPTimeout}
}

// opResult is one runner outcome handed back across the timeout boundary.
type opResult struct {
	out []byte
	err error
}

// Resolve validates the reference shape BEFORE calling p.run, so a malformed
// reference can never reach argv, then bounds the call with p.timeout.
//
// The deadline is enforced HERE, not merely handed to the runner. OPRunner is
// an exported seam and the default runner shells out to a third-party binary;
// neither can be assumed to notice a cancelled context. Before this select the
// timeout was honoured only by a cooperative runner, so a hung `op` did not
// fail startup — it suspended it, with no deadline in sight.
//
// The cost of an uncooperative runner is now one parked goroutine, which is the
// right trade against a gateway that never finishes NewServer.
func (p *onepasswordProvider) Resolve(ref string) (string, error) {
	if _, _, _, err := parseOPRef(ref); err != nil {
		return "", err
	}
	timeout := p.timeout
	if timeout <= 0 {
		timeout = DefaultOPTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Buffered: an abandoned runner must always be able to finish its send and
	// exit rather than block on a receiver that has already given up.
	done := make(chan opResult, 1)
	go func() {
		out, err := p.run(ctx, ref)
		done <- opResult{out: out, err: err}
	}()

	var res opResult
	select {
	case res = <-done:
	case <-ctx.Done():
		return "", opExecError(ref, ctx.Err())
	}
	if res.err != nil {
		return "", opExecError(ref, res.err)
	}
	v := strings.TrimSpace(string(res.out))
	if v == "" {
		return "", secretErr(ref, ErrSecretEmpty, "op read returned no value")
	}
	return v, nil
}

// execOPRead is the only place in package channel that starts a process.
//
// cmd.Output() is used rather than CombinedOutput(): stdout is the secret and
// must stay separate from stderr. Output() captures stderr into
// (*exec.ExitError).Stderr, so cmd.Stderr is left nil deliberately.
//
// WaitDelay is not optional here. Cancelling the context kills `op` itself, but
// it does nothing about a process `op` left behind that inherited the stdout
// pipe: Output() reads on until EOF, and EOF arrives only when the LAST holder
// of the write end goes away. So the direct child can exit, the deadline can
// pass, and Output() still blocks — the observed shape was a startup still
// wedged at 45s against a 15s DefaultOPTimeout. WaitDelay is the only mechanism
// that closes those pipes and lets Wait return.
func execOPRead(ctx context.Context, ref string) ([]byte, error) {
	// ref has already passed parseOPRef: it is exactly
	// "op://<vault>/<item>/<field>", contains no whitespace or control
	// characters, and cannot begin with "-". No shell is involved.
	cmd := exec.CommandContext(ctx, "op", "read", "--no-newline", ref)
	cmd.WaitDelay = opWaitDelay
	return cmd.Output()
}

// parseOPRef splits and validates an op:// reference. It returns
// ErrSecretRefInvalid for anything that is not exactly three non-empty,
// whitespace-free, control-character-free segments.
func parseOPRef(ref string) (vault, item, field string, err error) {
	bad := func(detail string) (string, string, string, error) {
		return "", "", "", secretErr(ref, ErrSecretRefInvalid, detail)
	}
	if !strings.HasPrefix(ref, SchemeOP) {
		return bad(`reference must begin with "` + SchemeOP + `"`)
	}
	parts := strings.Split(strings.TrimPrefix(ref, SchemeOP), "/")
	if len(parts) != opRefSegments {
		return bad(fmt.Sprintf("expected %s<vault>/<item>/<field> with %d segments, got %d",
			SchemeOP, opRefSegments, len(parts)))
	}
	for _, seg := range parts {
		if seg == "" {
			return bad("vault, item and field must all be non-empty")
		}
		if strings.ContainsFunc(seg, unusableRefRune) {
			return bad("vault, item and field must not contain whitespace or control characters")
		}
	}
	return parts[0], parts[1], parts[2], nil
}

// unusableRefRune reports runes that must never reach an argv element.
func unusableRefRune(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

// opExecError classifies an exec failure and extracts a bounded, non-secret
// detail from (*exec.ExitError).Stderr. It never touches stdout.
func opExecError(ref string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		// Both sentinels are reachable through errors.Is: callers classify on
		// ErrSecretUnavailable, operators want the deadline named.
		return secretErr(ref, fmt.Errorf("%w: %w", ErrSecretUnavailable, context.DeadlineExceeded),
			"op read timed out; the vault may be locked or awaiting biometric approval")
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// The CLI exited, but something it spawned kept the stdout pipe open
		// past the shutdown grace. Naming that precisely matters: the operator
		// otherwise sees a healthy `op read` on the command line and an
		// unexplained startup failure from the gateway.
		return secretErr(ref, ErrSecretUnavailable,
			"op left a child process holding its output pipe; the read was abandoned after "+
				opWaitDelay.String()+" rather than blocking startup")
	}
	if errors.Is(err, exec.ErrNotFound) {
		return secretErr(ref, ErrSecretUnavailable,
			`the "op" 1Password CLI was not found on PATH`)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return secretErr(ref, ErrSecretUnavailable,
			fmt.Sprintf("op exited %d: %s", exit.ExitCode(), boundedDetail(exit.Stderr)))
	}
	return secretErr(ref, ErrSecretUnavailable, "op read could not be executed")
}

// boundedDetail reduces a CLI's stderr to its first line, capped at
// maxCLIErrDetail bytes.
func boundedDetail(stderr []byte) string {
	s := strings.TrimSpace(string(stderr))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > maxCLIErrDetail {
		s = s[:maxCLIErrDetail] + "..."
	}
	return s
}

// -----------------------------------------------------------------------------
// Resolver — scheme-dispatching composite, with cache + in-flight dedup
// -----------------------------------------------------------------------------

// Resolver is itself a SecretProvider (composite pattern), so every call site
// depends on exactly one interface.
//
// It caches SUCCESSFUL resolutions only — a transient backend failure must not
// poison a reference for the process lifetime — and collapses concurrent
// duplicate lookups with singleflight, so two routes naming the same 1Password
// item cause one CLI invocation and one biometric prompt, not two.
type Resolver struct {
	providers map[string]SecretProvider // keyed by scheme constant

	group singleflight.Group
	mu    sync.RWMutex
	cache map[string]string
}

// Compile-time proof the composite satisfies the seam.
var _ SecretProvider = (*Resolver)(nil)

func newResolver(providers map[string]SecretProvider) *Resolver {
	return &Resolver{providers: providers, cache: make(map[string]string)}
}

// NewDefaultSecretProvider returns a Resolver over the three built-in backends.
//
// It returns a FRESH instance on every call. There is deliberately no
// package-level mutable provider: a shared global would be a data race between
// a test swapping it and a Server reading it, and would let one caller's cache
// leak into another's.
func NewDefaultSecretProvider() *Resolver {
	return newResolver(map[string]SecretProvider{
		SchemeEnv:  newEnvProvider(),
		SchemeFile: newFileProvider(),
		SchemeOP:   newOnePasswordProvider(),
	})
}

// Resolve dispatches on scheme, serving from cache when possible.
func (r *Resolver) Resolve(ref string) (string, error) {
	if v, ok := r.cached(ref); ok {
		return v, nil
	}
	p, err := r.providerFor(ref)
	if err != nil {
		return "", err
	}
	v, err, _ := r.group.Do(ref, func() (any, error) { return r.resolveOnce(ref, p) })
	if err != nil {
		return "", err
	}
	s, _ := v.(string)
	return s, nil
}

// providerFor selects the backend for a reference, rejecting unknown schemes
// before any provider is consulted.
func (r *Resolver) providerFor(ref string) (SecretProvider, error) {
	scheme, err := schemeOf(ref)
	if err != nil {
		return nil, err
	}
	p, ok := r.providers[scheme]
	if !ok {
		return nil, secretErr(ref, ErrSecretRefInvalid, "no provider registered for scheme "+scheme)
	}
	return p, nil
}

// resolveOnce runs inside the singleflight closure. It re-checks the cache so
// a goroutine that arrives just after a winner stored its value is served from
// the cache rather than triggering a second backend call, and it stores only
// successful, non-empty results.
func (r *Resolver) resolveOnce(ref string, p SecretProvider) (any, error) {
	if v, ok := r.cached(ref); ok {
		return v, nil
	}
	v, err := p.Resolve(ref)
	if err != nil {
		return "", err
	}
	if v == "" {
		// Defence in depth: a third-party provider that breaks the
		// non-empty contract must not become a cached empty credential.
		return "", secretErr(ref, ErrSecretEmpty, "provider returned an empty value")
	}
	r.store(ref, v)
	return v, nil
}

func (r *Resolver) cached(ref string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.cache[ref]
	return v, ok
}

func (r *Resolver) store(ref, val string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[ref] = val
}

// schemeOf reports which registered scheme a reference belongs to, or the
// typed rejection for one that belongs to none.
func schemeOf(ref string) (string, error) {
	if s, ok := refScheme(ref); ok {
		return s, nil
	}
	return "", secretErr(ref, ErrSecretRefInvalid,
		"expected one of "+SchemeEnv+", "+SchemeFile+" or "+SchemeOP)
}

// -----------------------------------------------------------------------------
// Legacy-field adapter — this is what preserves zero behaviour change
// -----------------------------------------------------------------------------

// secretRefs converts a route's or CONNECT's credential fields into ordered
// candidate references. Order is ref, then env, then file — which reproduces
// the historical env-before-file precedence exactly for configs that set no
// ref. Empty fields are skipped, so an unset key_env is simply absent.
func secretRefs(ref, envName, filePath string) []string {
	// Capacity 3: the ref, env and file fields are the only candidate sources.
	out := make([]string, 0, 3)
	if ref != "" {
		out = append(out, ref)
	}
	if envName != "" {
		out = append(out, SchemeEnv+envName)
	}
	if filePath != "" {
		out = append(out, SchemeFile+filePath)
	}
	return out
}

// resolveFirst returns the first candidate that yields a secret.
//
// An empty refs slice yields ErrNoSecretSource. When every candidate fails the
// per-candidate errors are combined with errors.Join, so errors.Is finds each
// distinct cause and the operator sees every source that was tried and why.
// It never returns ("", nil).
func resolveFirst(sp SecretProvider, refs []string) (string, error) {
	if len(refs) == 0 {
		return "", ErrNoSecretSource
	}
	errs := make([]error, 0, len(refs))
	for _, ref := range refs {
		v, err := sp.Resolve(ref)
		switch {
		case err == nil && strings.TrimSpace(v) != "":
			return strings.TrimSpace(v), nil
		case err == nil:
			errs = append(errs, secretErr(ref, ErrSecretEmpty, "provider returned an empty value"))
		default:
			errs = append(errs, err)
		}
	}
	return "", errors.Join(errs...)
}

// validateSecretRef reports whether ref is syntactically resolvable. It is
// called from Config.Validate so a malformed reference fails at config load
// rather than at resolution time. An empty ref means "not configured" and is
// the caller's business, not this function's.
func validateSecretRef(ref string) error {
	if ref == "" {
		return nil
	}
	scheme, err := schemeOf(ref)
	if err != nil {
		return err
	}
	switch scheme {
	case SchemeOP:
		_, _, _, err = parseOPRef(ref)
		return err
	case SchemeEnv:
		if strings.TrimPrefix(ref, SchemeEnv) == "" {
			return secretErr(ref, ErrSecretRefInvalid, "environment variable name is empty")
		}
	case SchemeFile:
		if strings.TrimPrefix(ref, SchemeFile) == "" {
			return secretErr(ref, ErrSecretRefInvalid, "file path is empty")
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Key pools — the PLURAL sources, resolved through the same seam
// -----------------------------------------------------------------------------

// keySlots is the FROZEN slot order of a pooled route: key_envs, then
// key_files, then key_refs, each in declaration order.
//
// Freezing the order is what makes the key_index in an audit line mean the same
// account on every node running the same config. Each entry carries the scheme
// prefix that turns a bare field value into a reference the Resolver
// understands; key_refs are already scheme-qualified, so their prefix is empty.
func keySlots(r Route) []struct {
	field  string
	scheme string
	items  []string
} {
	return []struct {
		field  string
		scheme string
		items  []string
	}{
		{"key_envs", SchemeEnv, r.KeyEnvs},
		{"key_files", SchemeFile, r.KeyFiles},
		{"key_refs", "", r.KeyRefs},
	}
}

// declaredKeyCount is the pool size a route's configuration promises.
//
// It is knowable WITHOUT resolving anything, because resolveKeyPool yields
// exactly one key per declared slot — it never splits a source into several
// keys. That is what lets NewServer size a rotation Store before it holds any
// credential, and it is why a pool can never silently shrink at boot: a slot
// that will not resolve is a startup error, not a shorter pool.
func declaredKeyCount(r Route) int {
	return len(r.KeyEnvs) + len(r.KeyFiles) + len(r.KeyRefs)
}

// resolveKeyPool resolves a route's plural sources in frozen slot order through
// sp, then rejects duplicates by index.
//
// Every source goes through the SecretProvider seam rather than os.Getenv /
// os.ReadFile / the op CLI directly, so a pooled route gets the same
// trim-then-test emptiness contract, the same typed errors and the same
// one-prompt-per-vault-item caching as a single-key route — and there is
// exactly one code path that can read a credential.
//
// Errors name the SLOT (key_files[1]) and, through SecretError, the REFERENCE.
// Neither is secret; the resolved value never appears.
func resolveKeyPool(r Route, sp SecretProvider) ([]string, error) {
	n := declaredKeyCount(r)
	keys := make([]string, 0, n)
	labels := make([]string, 0, n)

	for _, slot := range keySlots(r) {
		for i, item := range slot.items {
			ref := slot.scheme + item
			label := fmt.Sprintf("%s[%d]", slot.field, i)
			v, err := sp.Resolve(ref)
			if err != nil {
				return nil, fmt.Errorf("route %q: %s: %w", r.Name, label, err)
			}
			if v = strings.TrimSpace(v); v == "" {
				// Defence in depth: a provider that breaks the non-empty
				// contract must not put a blank key in a pool slot.
				return nil, fmt.Errorf("route %q: %s: %w", r.Name, label,
					secretErr(ref, ErrSecretEmpty, "provider returned an empty value"))
			}
			keys = append(keys, v)
			labels = append(labels, label)
		}
	}
	if len(keys) == 0 {
		// Unreachable from a validated config (a declared list must not be
		// empty), and kept so KeyInventory{Pooled: true, Keys: 0} — a pool
		// with no credential BY ACCIDENT — cannot reach a running server.
		return nil, fmt.Errorf("route %q: resolved key pool is empty", r.Name)
	}
	if err := rejectDuplicateCredentials(r.Name, keys, labels); err != nil {
		return nil, err
	}
	return keys, nil
}

// rejectDuplicateCredentials refuses a pool whose slots are backed by fewer
// accounts than slots. It reports SLOT LABELS only: printing the shared value
// would put a live credential in a startup log.
func rejectDuplicateCredentials(route string, keys, labels []string) error {
	firstAt := make(map[string]int, len(keys))
	for i, k := range keys {
		if j, dup := firstAt[k]; dup {
			return fmt.Errorf("route %q: %s resolves to the same credential as %s; a pool with fewer accounts than slots over-reports capacity and makes per-key quota attribution meaningless", route, labels[i], labels[j])
		}
		firstAt[k] = i
	}
	return nil
}
