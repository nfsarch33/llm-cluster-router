package proxy

import (
	"context"
	"net"
)

// plainHTTPListenerFactory is the legacy ListenerFactory that
// returns a plain TCP listener and a noop ServeLoop. It is
// selected when HELIXCHANNEL_ENABLED=false (or equivalently when
// the operator disables the AES/mTLS factory for back-compat).
//
// The production http.Server is constructed by the caller and
// passed to ListenAndServe; this factory only owns the TCP bind
// so the AES/mTLS factory and the plain HTTP factory share the
// same ListenerFactory contract.
type plainHTTPListenerFactory struct{}

// NewPlainHTTPListenerFactory returns a ListenerFactory that
// binds a plain TCP listener with no application-layer encryption.
// The ServeLoop is a noop that returns when ctx is cancelled;
// the caller is responsible for handing the listener to its own
// http.Server.Serve(ln).
func NewPlainHTTPListenerFactory() ListenerFactory {
	return &plainHTTPListenerFactory{}
}

func (p *plainHTTPListenerFactory) Channel() string { return "plain-http" }

func (p *plainHTTPListenerFactory) Listen(ctx context.Context, addr string) (net.Listener, ServeLoop, error) {
	if addr == "" {
		return nil, nil, ErrEmptyAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	serve := func(ctx context.Context, ln net.Listener) error {
		// The plain HTTP factory does not own a ServeLoop in the
		// usual sense — the production http.Server takes over the
		// listener via http.Server.Serve. We still honour ctx so
		// callers can stop the loop by cancelling context.
		<-ctx.Done()
		return nil
	}
	return ln, serve, nil
}

// SelectListenerFactory returns the ListenerFactory to use for
// the production main.go based on the HELIXCHANNEL_ENABLED knob.
// enabled=true → AES/mTLS (HelixChannel); enabled=false → legacy
// plain HTTP. This selector is the single source of truth for the
// choice; the production main.go calls it during serve startup
// (see ADR-085).
func SelectListenerFactory(enabled bool) ListenerFactory {
	if enabled {
		return NewAESMTLSListenerFactory()
	}
	return NewPlainHTTPListenerFactory()
}
