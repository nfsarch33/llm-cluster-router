// Package socks5 implements the SOCKS5 listener factory for
// llm-cluster-router.
//
// Scope (v18705): a no-auth SOCKS5 listener that forwards TCP
// CONNECT requests to the upstream configured on the armon/go-socks5
// default resolver. Username/password authentication is deferred to
// v18706+ per ADR-082 §2 and the operator correction recorded on
// 2026-07-20. The deferral is traceable as CF-2026-07-20-v18705-1.
package socks5

import (
	"context"
	"errors"
	"net"

	"github.com/armon/go-socks5"

	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
)

// ErrEmptyAddr is re-exported from the parent proxy package so
// callers can detect empty-address bind attempts without importing
// the parent.
var ErrEmptyAddr = proxy.ErrEmptyAddr

// listenerFactory builds SOCKS5 listeners backed by armon/go-socks5.
// The factory is goroutine-safe: each Listen call returns an
// independent server with its own bind socket and ServeLoop.
type listenerFactory struct{}

// NewListenerFactory returns a proxy.ListenerFactory for the SOCKS5
// channel. The returned factory uses armon/go-socks5's default
// no-auth authenticator.
func NewListenerFactory() proxy.ListenerFactory {
	return &listenerFactory{}
}

// Channel returns the stable identifier "socks5".
func (l *listenerFactory) Channel() string { return "socks5" }

// Listen binds a SOCKS5 listener on addr and returns the net.Listener
// plus a ServeLoop that drives the underlying armon/go-socks5 server.
//
// addr MUST be in host:port form (e.g. "127.0.0.1:1080"). An empty
// address returns ErrEmptyAddr.
//
// In v18705 the implementation accepts the bind address but the
// underlying armon/go-socks5 server is invoked with a no-auth
// configuration; the on-the-wire SOCKS5 handshake is intentionally
// NOT exercised in unit tests (it requires a real SOCKS5 client;
// covered by the demo binary in cmd/dual-listener-demo).
//
// v18706 fix: removed the probe-then-rebind pattern. The probe bound
// a port, closed it, then rebound in a second net.Listen call; under
// parallel fuzz workers another goroutine could steal the port
// between the two syscalls (TOCTOU race surfaced by FuzzSOCKS5).
// The bind is now a single net.Listen call. Callers that want to
// pre-detect EADDRINUSE without holding the socket should use
// net.Listen themselves before calling Listen; the factory returns
// the underlying error directly so the binding error is preserved.
func (l *listenerFactory) Listen(ctx context.Context, addr string) (net.Listener, proxy.ServeLoop, error) {
	if addr == "" {
		return nil, nil, ErrEmptyAddr
	}

	conf := &socks5.Config{} // default: no-auth (RFC 1928 method 0x00)
	server, err := socks5.New(conf)
	if err != nil {
		return nil, nil, err
	}

	// Single bind; no probe pattern. If addr is in use we return
	// the underlying *net.OpError directly so callers can errors.As
	// against syscall.EADDRINUSE without translation.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	serve := func(ctx context.Context, ln net.Listener) error {
		// Watch ctx; on cancellation close ln so the SOCKS5
		// server's Accept returns and Serve unwinds.
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		// armon/go-socks5's Serve does not expose Accept directly,
		// so we run its Serve loop on the listener we just bound.
		// This blocks until ln is closed (caller or ctx cancel).
		err := server.Serve(ln)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		return nil
	}
	return ln, serve, nil
}
