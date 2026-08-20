package channel

import (
	"fmt"
	"net/http"
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

// NewAuthenticator builds the Authenticator described by a route, resolving
// any credential from the environment or a file at construction time so a
// missing credential fails at startup rather than on the first request.
func NewAuthenticator(r Route) (Authenticator, error) {
	switch r.Auth {
	case AuthInject:
		key, err := readSecret(r.KeyEnv, r.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", r.Name, err)
		}
		return &bearerInjector{key: key}, nil
	case AuthPassthrough:
		return passthrough{}, nil
	default:
		return nil, fmt.Errorf("route %q: unsupported auth mode %q", r.Name, r.Auth)
	}
}
