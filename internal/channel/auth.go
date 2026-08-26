package channel

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Authenticator applies upstream credentials to an outbound request.
//
// Implementations are substitutable: the forwarder calls Apply without
// knowing which strategy is in play. A new provider whose auth differs from
// both existing modes is a new Authenticator, not a change to the forwarder.
type Authenticator interface {
	// Apply mutates the outbound request so the upstream will accept it.
	Apply(req *http.Request) error
	// Mode reports the configured mode, for audit events and metrics.
	Mode() AuthMode
}

// bearerInjector replaces the caller's Authorization header with a
// server-held API key.
//
// Replacing rather than appending is deliberate: a caller must not be able to
// impersonate a different upstream account by presenting its own Authorization
// header, and the placeholder token that clients are told to configure must
// never reach the provider.
type bearerInjector struct {
	key string
}

func (b *bearerInjector) Apply(req *http.Request) error {
	if b.key == "" {
		return fmt.Errorf("upstream credential is empty")
	}
	req.Header.Set("Authorization", "Bearer "+b.key)
	return nil
}

func (b *bearerInjector) Mode() AuthMode { return AuthInject }

// passthrough leaves the caller's Authorization header untouched.
//
// This is the mode for upstreams where the client holds the credential — an
// OAuth session token, for instance. Injecting a server-side key there would
// replace a valid session with an invalid one.
type passthrough struct{}

func (passthrough) Apply(*http.Request) error { return nil }

func (passthrough) Mode() AuthMode { return AuthPassthrough }

// leasedInjector applies ONE specific key to ONE outbound request.
//
// It is the single credential-writing type for header mode and for every
// pooled lease, so there is exactly one place in the package where a resolved
// key is written onto a request. For AuthInject the fields are
// header="Authorization" and prefix="Bearer ", which makes the outbound bytes
// byte-identical to bearerInjector's.
//
// It DELETES an inbound Authorization header whenever that is not the header it
// is writing: otherwise a caller-supplied Authorization would be copied through
// untouched, defeating the whole point of an inject-family mode.
type leasedInjector struct {
	key    string
	header string
	prefix string
	mode   AuthMode
}

func (l leasedInjector) Apply(req *http.Request) error {
	if l.key == "" {
		return fmt.Errorf("upstream credential is empty")
	}
	name := l.header
	if name == "" {
		name = "Authorization"
	}
	if !strings.EqualFold(name, "Authorization") {
		req.Header.Del("Authorization")
	}
	req.Header.Set(name, l.prefix+l.key)
	return nil
}

func (l leasedInjector) Mode() AuthMode {
	if l.mode == "" {
		return AuthInject
	}
	return l.mode
}

// keyLeaser is the OPTIONAL capability a pooled Authenticator advertises.
//
// handleProxy type-asserts for it. bearerInjector, leasedInjector and
// passthrough deliberately do NOT implement it, so a single-key route runs
// through code this change does not touch — which is what makes "extend by
// adding an implementation" literally true here.
type keyLeaser interface {
	leaseFor() (Authenticator, *KeyLease, admissionRefusal)
	retryAfter() time.Duration
	retire(idx int, reason RetireReason)
	inventory() KeyInventory
}

// rotatingInjector is the Authenticator for a pooled route, in EITHER inject or
// header mode.
//
// The pooling machinery is mode-agnostic because it operates on the key INDEX,
// never on the key or the header name: leaseFor hands out a leasedInjector
// carrying whichever header/prefix the mode requires. A route is pooled iff it
// declares plural sources, regardless of mode and regardless of count.
type rotatingInjector struct {
	keys   []string
	store  *Store
	route  string
	mode   AuthMode
	header string
	prefix string
}

var (
	_ Authenticator = (*rotatingInjector)(nil)
	_ Authenticator = leasedInjector{}
	_ keyLeaser     = (*rotatingInjector)(nil)
)

// Apply ALWAYS fails closed — there is deliberately no single-key shortcut.
//
// A one-key pool that quietly served keys[0] would emit no key_index and charge
// no budget, which is exactly the capacity lie pool validation exists to
// prevent: the route would report a healthy rotation while spending one plan
// forever. Every pooled request goes through leaseFor.
func (r *rotatingInjector) Apply(*http.Request) error {
	return fmt.Errorf("route %q: rotating credential requires a key lease; Apply was called without one", r.route)
}

// Mode reports the configured mode, so a pooled inject route is substitutable
// for a single-key one and auth_mode stays the closed set operators configure.
// key_index is what distinguishes the two in the audit trail.
func (r *rotatingInjector) Mode() AuthMode { return r.mode }

// leaseFor reserves a key and returns an Authenticator bound to it plus the
// lease the caller must settle.
//
// The third result is refusalNone on success and otherwise says WHY — the 503
// answers differ, and a single boolean is what let an admission refusal be
// reported to callers as a spent plan. A missing Store and an out-of-range
// index are refusalDrained rather than refusalAdmission because neither will
// clear on its own: the safe label is the one that does not promise a caller a
// short wait it will not get.
func (r *rotatingInjector) leaseFor() (Authenticator, *KeyLease, admissionRefusal) {
	if r.store == nil {
		return nil, nil, refusalDrained
	}
	lease, refusal := r.store.acquire(r.route)
	if refusal != refusalNone {
		return nil, nil, refusal
	}
	i := lease.Index()
	if i < 0 || i >= len(r.keys) {
		lease.Settle(UsageSample{Outcome: OutcomeFailed})
		return nil, nil, refusalDrained
	}
	return leasedInjector{key: r.keys[i], header: r.header, prefix: r.prefix, mode: r.mode}, lease, refusalNone
}

// retryAfter is the wait to advertise for a DRAINED route: the time until the
// earliest key becomes selectable again. It is not the answer for an admission
// refusal, which clears when an in-flight lease settles rather than at any time
// this store can name — see refusalAnswerFor.
func (r *rotatingInjector) retryAfter() time.Duration {
	if r.store == nil {
		return MinRetryAfter
	}
	if d, ok := r.store.RetryAfter(r.route); ok {
		return d
	}
	return MinRetryAfter
}

// retire parks the key at idx for the remainder of the accounting window. It is
// how an upstream quota signal leaves the rotation.
func (r *rotatingInjector) retire(idx int, reason RetireReason) {
	if r.store == nil {
		return
	}
	r.store.retireForWindow(r.route, idx, reason)
}

// inventory is the /healthz key surface for a pooled route. Counts only: never
// a key, prefix, suffix, length or fingerprint.
//
// The Store is reached ONLY through this capability, so nothing outside the
// injector that owns it holds a reference — there is no second, write-only map
// of stores to drift out of date.
func (r *rotatingInjector) inventory() KeyInventory {
	inv := KeyInventory{Mode: r.mode, Pooled: true, Keys: len(r.keys)}
	if r.store != nil {
		for _, st := range r.store.Snapshot(r.route) {
			if st.Selectable {
				inv.Available++
			}
		}
	}
	inv.Degraded = inv.Available == 0
	return inv
}

// NewAuthenticator builds a SINGLE-KEY route's Authenticator with a fresh
// default secret provider, resolving the credential at construction time so a
// missing one fails at startup rather than on the first request.
//
// It REFUSES a pooled route. A pool without a Store is not a functioning
// Authenticator: every Apply would fail closed while the object looked
// constructed. WithSecretProvider on NewServer is the only supported injection
// point for a pooled route.
func NewAuthenticator(r Route) (Authenticator, error) {
	if hasPluralKeys(r) {
		return nil, fmt.Errorf("route %q: a pooled route (key_envs/key_files/key_refs) must be built by NewServer; NewAuthenticator builds single-key routes only", r.Name)
	}
	return newAuthenticatorFor(r, NewDefaultSecretProvider(), nil)
}

// newAuthenticatorFor is the full constructor NewServer uses. Selection rules:
//
//	singular + inject       -> *bearerInjector    (UNCHANGED code path)
//	singular + header       -> leasedInjector     (no Store, no key_index)
//	plural   + inject|header-> *rotatingInjector  (leases; hands out leasedInjector)
//	passthrough             -> passthrough{}      (UNCHANGED code path)
//
// st is the accounting Store to bind to a pooled route. It is supplied by the
// caller rather than built here because its clock and retire observer are
// server-level options; its size is knowable from configuration alone, since
// resolveKeyPool yields exactly one key per declared slot.
func newAuthenticatorFor(r Route, sp SecretProvider, st *Store) (Authenticator, error) {
	switch r.Auth {
	case AuthInject, AuthHeaderInject:
		header, prefix := "Authorization", "Bearer "
		if r.Auth == AuthHeaderInject {
			header, prefix = r.KeyHeader, r.KeyPrefix
		}
		if hasPluralKeys(r) {
			keys, err := resolveKeyPool(r, sp)
			if err != nil {
				return nil, err
			}
			return &rotatingInjector{
				keys: keys, store: st, route: r.Name,
				mode: r.Auth, header: header, prefix: prefix,
			}, nil
		}
		key, err := resolveFirst(sp, secretRefs(r.KeyRef, r.KeyEnv, r.KeyFile))
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", r.Name, err)
		}
		// A BACKSTOP, not a layer, and the difference is worth stating because
		// it was mistaken for one: resolveFirst returns either an error or a
		// value that is already trimmed and non-empty, so nothing a
		// SecretProvider can return reaches this line blank. No test can kill
		// it on its own, and one that appears to is really killing
		// resolveFirst's guard. What pins it is the PRECONDITION, in
		// TestResolveFirst_NeverHandsBackAValueThatStillNeedsTrimming: if that
		// test ever fails, this check has become reachable and needs one of
		// its own. It stays because "Bearer " on the wire is severe enough not
		// to rest on one upstream check staying correct.
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("route %q: %w", r.Name, ErrSecretEmpty)
		}
		if r.Auth == AuthInject {
			// The historical path, untouched: same type, same single header,
			// same bytes on the wire as before rotation existed.
			return &bearerInjector{key: key}, nil
		}
		return leasedInjector{key: key, header: header, prefix: prefix, mode: AuthHeaderInject}, nil
	case AuthPassthrough:
		return passthrough{}, nil
	default:
		return nil, fmt.Errorf("route %q: unsupported auth mode %q", r.Name, r.Auth)
	}
}
