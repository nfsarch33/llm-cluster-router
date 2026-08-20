package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// newAddr returns a free loopback TCP address; tests bind to it so
// parallel runs do not collide. The address is closed immediately
// after capture so the listener itself can bind it.
func newAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen probe: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// fakeFactory is a minimal ListenerFactory used by the contract tests.
// It captures the addr it was asked to bind and returns a fake listener
// that records ServeLoop invocations.
type fakeFactory struct {
	channel string
	addr    atomic.Value // string
	served  atomic.Int32
}

func (f *fakeFactory) Channel() string { return f.channel }

func (f *fakeFactory) Listen(ctx context.Context, addr string) (net.Listener, ServeLoop, error) {
	if addr == "" {
		return nil, nil, errors.New("addr must not be empty")
	}
	f.addr.Store(addr)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	serve := func(ctx context.Context, ln net.Listener) error {
		f.served.Add(1)
		// Watch ctx; on cancellation, close the listener so the
		// blocked Accept call returns and the loop can exit.
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return nil // listener closed -> normal shutdown
		}
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		return nil
	}
	return ln, serve, nil
}

func TestListenerFactory_Channel_StableIdentifier(t *testing.T) {
	f := &fakeFactory{channel: "aes-mtls"}
	if got := f.Channel(); got != "aes-mtls" {
		t.Errorf("Channel() = %q, want aes-mtls", got)
	}
}

func TestListenerFactory_Listen_RejectsEmptyAddr(t *testing.T) {
	f := &fakeFactory{channel: "socks5"}
	_, _, err := f.Listen(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty addr, got nil")
	}
}

func TestListenerFactory_Listen_BindsAndAccepts(t *testing.T) {
	f := &fakeFactory{channel: "aes-mtls"}
	addr := newAddr(t)

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
	defer func() { _ = ln.Close() }()

	// Drive the ServeLoop in a goroutine and cancel after a short
	// connection so the loop exits cleanly.
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln) }()

	// Open a client connection and immediately close.
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	// Allow the ServeLoop to register the connection.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && f.served.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if f.served.Load() == 0 {
		t.Errorf("ServeLoop was never invoked")
	}

	// Stop the ServeLoop by closing the listener; second Accept returns
	// an error which the fake treats as normal shutdown.
	_ = ln.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeLoop returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ServeLoop did not return within 2s after cancel")
	}

	if got := f.addr.Load(); got != addr {
		t.Errorf("addr captured = %v, want %s", got, addr)
	}
}

func TestListenerFactory_Listen_ContextCancelledStopsServeLoop(t *testing.T) {
	f := &fakeFactory{channel: "socks5"}
	addr := newAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln) }()

	// Cancel the context before any client connects; the ServeLoop
	// must still exit (the test fake treats Accept's "use of closed
	// network connection" error as a normal shutdown, but real
	// implementations should observe ctx.Done()).
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

func TestAESMTLSListenerFactory_ChannelAndServeContract(t *testing.T) {
	// The AES/mTLS factory must satisfy the ListenerFactory contract
	// and use a stable channel identifier. We assert against a
	// factory instance constructed via the package helper.
	f := NewAESMTLSListenerFactory()
	if f == nil {
		t.Fatal("NewAESMTLSListenerFactory returned nil")
	}
	if got := f.Channel(); got != "aes-mtls" {
		t.Errorf("Channel() = %q, want aes-mtls", got)
	}
	// Listen must succeed on a free loopback address.
	addr := newAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if ln == nil || serve == nil {
		t.Fatalf("Listen returned nil listener or serve: ln=%v serve=%v", ln, serve)
	}
	defer func() { _ = ln.Close() }()
}
