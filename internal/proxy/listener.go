package proxy

import (
	"context"
	"net"
)

// ServeLoop is the long-running accept loop for a listener. It MUST
// return promptly when ctx is cancelled. Implementations are
// expected to close the supplied net.Listener on exit if they own
// its lifecycle.
type ServeLoop func(ctx context.Context, ln net.Listener) error

// ListenerFactory abstracts construction of a TCP listener for a
// named encryption channel. A single daemon can compose multiple
// factories and run each ServeLoop in its own goroutine.
//
// The contract:
//
//   - Channel() returns a stable identifier used for metrics,
//     logging, and config keys.
//   - Listen(ctx, addr) returns a bound net.Listener and the
//     ServeLoop that should be run for it. addr is the host:port
//     the caller wants to bind. addr MUST NOT be empty; factories
//     return an error if it is.
type ListenerFactory interface {
	Channel() string
	Listen(ctx context.Context, addr string) (net.Listener, ServeLoop, error)
}

// aesMTLSListenerFactory builds the canonical AES/mTLS-flavoured
// HTTP listener. The actual TLS handshake is performed by callers
// that wrap the returned net.Listener in a tls.Listener; this
// factory only owns the TCP bind + ServeLoop plumbing so the
// production main.go can compose it alongside future channels.
type aesMTLSListenerFactory struct{}

// NewAESMTLSListenerFactory returns a ListenerFactory for the
// existing AES/mTLS HTTP path. The factory is intentionally
// minimal: the production router already has its http.Server
// constructed in main.go; this factory exists to make the
// dual-listener interface composable.
func NewAESMTLSListenerFactory() ListenerFactory {
	return &aesMTLSListenerFactory{}
}

func (a *aesMTLSListenerFactory) Channel() string { return "aes-mtls" }

func (a *aesMTLSListenerFactory) Listen(ctx context.Context, addr string) (net.Listener, ServeLoop, error) {
	if addr == "" {
		return nil, nil, errEmptyAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	serve := func(ctx context.Context, ln net.Listener) error {
		// Watch ctx in a goroutine; on cancellation, close the
		// listener so the blocked Accept call returns an error.
		// The caller still owns the listener for normal cleanup
		// (closing ln from outside the ServeLoop is safe; the
		// second Close is a no-op that returns an error we ignore).
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				// Listener was closed by another path (caller
				// shutdown or test teardown). Normal exit.
				return nil
			}
			// The actual request handling is delegated to the
			// caller's http.Server. This ServeLoop only models
			// the listen/accept seam; production wiring will
			// replace this no-op with a real handler.
			_ = conn.Close()
		}
	}
	return ln, serve, nil
}

// errEmptyAddr is returned by factories when addr is empty. It is
// declared as a sentinel so tests can assert against it without
// string matching.
var errEmptyAddr = &emptyAddrError{}

type emptyAddrError struct{}

func (*emptyAddrError) Error() string { return "proxy: listener addr must not be empty" }

// ErrEmptyAddr is the exported sentinel for tests and callers that
// want to detect an empty-address bind attempt.
var ErrEmptyAddr = errEmptyAddr
