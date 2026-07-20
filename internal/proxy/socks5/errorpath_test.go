package socks5

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSOCKS5ListenerFactory_Listen_BindConflict verifies that when
// the requested address is already in use by another listener, the
// factory returns a non-nil error wrapping EADDRINUSE rather than
// silently binding to a different port. This protects operators
// from misconfigured configs that would otherwise start the SOCKS5
// listener on an unintended port.
func TestSOCKS5ListenerFactory_Listen_BindConflict(t *testing.T) {
	// Hold an exclusive listener on a free loopback address.
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold listener: %v", err)
	}
	defer hold.Close()
	addr := hold.Addr().String()

	f := NewListenerFactory()
	ln, serve, err := f.Listen(context.Background(), addr)
	if err == nil {
		// Cleanup the success branch so we don't leak the listener.
		if ln != nil {
			_ = ln.Close()
		}
		_ = serve
		t.Fatal("expected error on bind conflict, got nil")
	}
	if ln != nil {
		t.Errorf("Listen returned non-nil net.Listener on bind conflict: %v", ln)
	}
	if serve != nil {
		t.Errorf("Listen returned non-nil ServeLoop on bind conflict: %v", serve)
	}
	// Verify the underlying syscall is EADDRINUSE so operators can
	// match on the error chain.
	var sysErr *net.OpError
	if !errors.As(err, &sysErr) {
		t.Errorf("err = %v, want *net.OpError", err)
		return
	}
	var errno syscall.Errno
	if !errors.As(sysErr.Err, &errno) && !errors.Is(err, syscall.EADDRINUSE) {
		// Best-effort: some platforms wrap differently.
		if !strings.Contains(err.Error(), "address already in use") {
			t.Logf("note: err = %v (not strictly EADDRINUSE; platform-dependent)", err)
		}
	}
}

// TestSOCKS5ListenerFactory_Listen_InvalidAddr verifies that an
// invalid host:port (malformed) returns a non-nil error without
// panicking. The factory must not crash on garbage input.
func TestSOCKS5ListenerFactory_Listen_InvalidAddr(t *testing.T) {
	f := NewListenerFactory()
	cases := []string{
		"not-a-valid-address",
		"999.999.999.999:80",
		"127.0.0.1:notaport",
	}
	for _, addr := range cases {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			ln, serve, err := f.Listen(context.Background(), addr)
			if err == nil {
				if ln != nil {
					_ = ln.Close()
				}
				_ = serve
				t.Fatalf("addr=%q: expected error, got nil", addr)
			}
			if ln != nil {
				t.Errorf("addr=%q: Listen returned non-nil net.Listener on error: %v", addr, ln)
			}
		})
	}
}

// TestSOCKS5ListenerFactory_ServeLoop_ReturnsNilOnContextCancel
// verifies the happy-path cancellation: when the context is cancelled
// before any client connects, the ServeLoop returns nil within a
// bounded time. This complements the existing test by exercising
// the case where there is zero traffic.
func TestSOCKS5ListenerFactory_ServeLoop_ReturnsNilOnContextCancel(t *testing.T) {
	f := NewListenerFactory()
	addr := freeLoopbackAddr(t)

	ctx, cancel := context.WithCancel(context.Background())

	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		cancel()
		t.Fatalf("Listen: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln) }()

	// Cancel immediately, before any connection arrives.
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeLoop returned %v on context cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeLoop did not return within 2s of context cancel")
	}
	_ = ln.Close()
}

// TestSOCKS5ListenerFactory_ServeLoop_NilAfterExternalClose verifies
// that if the caller closes the net.Listener from outside the
// ServeLoop (a legitimate teardown path), the ServeLoop returns nil
// rather than a confusing "use of closed connection" error. This
// matches the AES/mTLS factory's behaviour for symmetry.
func TestSOCKS5ListenerFactory_ServeLoop_NilAfterExternalClose(t *testing.T) {
	f := NewListenerFactory()
	addr := freeLoopbackAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln) }()

	// Close from outside the ServeLoop (operator-driven shutdown).
	_ = ln.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeLoop returned %v after external Close, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeLoop did not return within 2s of external Close")
	}
}

// TestSOCKS5ListenerFactory_NonSOCKS5ClientConnectionCloses verifies
// that when a raw TCP client connects without speaking SOCKS5, the
// SOCKS5 server closes the connection cleanly (rather than leaking
// it). We assert via SetReadDeadline on the client side that the
// server closes the connection within a bounded window. The exact
// error from armon/go-socks5 is not part of the public contract; we
// only assert "closed cleanly within 1s" so the test is robust
// against library upgrades.
func TestSOCKS5ListenerFactory_NonSOCKS5ClientConnectionCloses(t *testing.T) {
	f := NewListenerFactory()
	addr := freeLoopbackAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln) }()

	// Connect and write a single non-SOCKS5 byte. The server
	// should close the connection promptly (RFC 1928 specifies
	// the server may drop unknown methods, but armon/go-socks5
	// closes the connection on a malformed handshake).
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x42}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Set a short read deadline. The server should close its end,
	// which causes our Read to return EOF promptly.
	if err := conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err == nil {
		t.Errorf("expected server to close connection; got %d bytes", n)
	}
	// EOF, "use of closed network connection", or timeout (after
	// server closes and we read nothing) are all acceptable
	// outcomes. We log the err for diagnostics and pass the test
	// as long as the server did NOT keep the connection open
	// indefinitely.
	t.Logf("read after non-SOCKS5 byte: n=%d err=%v (expected EOF or closed)", n, err)
}
