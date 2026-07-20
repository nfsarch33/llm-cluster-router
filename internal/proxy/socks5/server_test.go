package socks5

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestSOCKS5ListenerFactory_Channel verifies the SOCKS5 factory uses
// the stable identifier "socks5" for metrics, logging, and config
// keys.
func TestSOCKS5ListenerFactory_Channel(t *testing.T) {
	f := NewListenerFactory()
	if got := f.Channel(); got != "socks5" {
		t.Errorf("Channel() = %q, want socks5", got)
	}
}

// TestSOCKS5ListenerFactory_Listen_RejectsEmptyAddr verifies that
// an empty address is rejected with a sentinel error.
func TestSOCKS5ListenerFactory_Listen_RejectsEmptyAddr(t *testing.T) {
	f := NewListenerFactory()
	_, _, err := f.Listen(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty addr, got nil")
	}
	if !errors.Is(err, ErrEmptyAddr) {
		t.Errorf("err = %v, want ErrEmptyAddr sentinel", err)
	}
}

// freeLoopbackAddr returns a host:port pair that is currently free
// for binding. The probe listener is closed before the returned
// address is handed to the test body.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen probe: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestSOCKS5ListenerFactory_Listen_BindsAndCancellable verifies that
// the factory binds a real TCP listener on a loopback address and
// that the returned ServeLoop exits cleanly when the context is
// cancelled. The factory does NOT speak SOCKS5 in this test (that
// is covered by a separate end-to-end smoke); we only assert the
// bind + ServeLoop plumbing.
func TestSOCKS5ListenerFactory_Listen_BindsAndCancellable(t *testing.T) {
	f := NewListenerFactory()
	addr := freeLoopbackAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if ln == nil {
		t.Fatal("Listen returned nil net.Listener")
	}
	if serve == nil {
		t.Fatal("Listen returned nil ServeLoop")
	}
	defer ln.Close()

	// Run the ServeLoop and confirm it exits within 2s after cancel.
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeLoop returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ServeLoop did not return within 2s after cancel")
	}
}

// TestSOCKS5ListenerFactory_Listen_AcceptsTCPConnection verifies that
// a TCP connection to the listener's address completes the three-way
// handshake before the context is cancelled. The test deliberately
// does NOT speak SOCKS5; that is verified separately. We only check
// that the listener is reachable.
func TestSOCKS5ListenerFactory_Listen_AcceptsTCPConnection(t *testing.T) {
	f := NewListenerFactory()
	addr := freeLoopbackAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var accepted atomic.Bool
	// Custom ServeLoop stub: record first Accept and exit.
	stubServe := func(ctx context.Context, ln net.Listener) error {
		_ = serve // ensure factory-produced ServeLoop is reachable
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		conn, err := ln.Accept()
		if err == nil {
			accepted.Store(true)
			_ = conn.Close()
		}
		return nil
	}

	done := make(chan error, 1)
	go func() { done <- stubServe(ctx, ln) }()

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeLoop stub did not return")
	}

	if !accepted.Load() {
		t.Error("listener did not accept the test TCP connection")
	}
}
