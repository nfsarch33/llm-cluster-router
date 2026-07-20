package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestDemoMockUpstream_HandlesHTTPRequest verifies the in-process
// mock upstream that backs the dual-listener demo binary accepts a
// TCP connection, reads a request, and writes a fixed response.
func TestDemoMockUpstream_HandlesHTTPRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, serve, err := startMockUpstream(ctx, "hello-from-mock")
	if err != nil {
		t.Fatalf("startMockUpstream: %v", err)
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("addr = %q, want 127.0.0.1:*", addr)
	}

	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send a minimal HTTP/1.1 GET request.
	req := "GET / HTTP/1.1\r\nHost: mock\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "hello-from-mock") {
		t.Errorf("response missing body marker; got %q", string(buf[:n]))
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("mock upstream did not return within 2s after cancel")
	}
}

// TestDualListenerDemo_RequiresAESAddrAndSOCKS5Addr verifies the
// demo binary's flag validation: an empty aes-addr or socks5-addr
// returns a structured error.
func TestDualListenerDemo_RequiresAESAddrAndSOCKS5Addr(t *testing.T) {
	tests := []struct {
		name      string
		aes       string
		socks     string
		wantErrIs error
	}{
		{"both empty", "", "", errEmptyFlag},
		{"socks5 empty", "127.0.0.1:0", "", errEmptyFlag},
		{"aes empty", "", "127.0.0.1:0", errEmptyFlag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDualListenerDemo(context.Background(), tt.aes, tt.socks, "vtest")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErrIs) {
				t.Errorf("err = %v, want %v", err, tt.wantErrIs)
			}
		})
	}
}

// TestDualListenerDemo_BothListenersAcceptTCP verifies that when
// run with valid flags, both listener factories bind and accept at
// least one TCP connection. The test uses a SOCKS5-aware client
// (net.Dial) to confirm reachability of both ports.
func TestDualListenerDemo_BothListenersAcceptTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use fixed free ports picked from the OS.
	aesAddr := freePort(t)
	socksAddr := freePort(t)

	done := make(chan error, 1)
	go func() { done <- runDualListenerDemo(ctx, aesAddr, socksAddr, "demo-body") }()

	// Give listeners a moment to bind.
	time.Sleep(50 * time.Millisecond)

	// Dial both addresses.
	dialer := net.Dialer{Timeout: 2 * time.Second}
	for _, addr := range []string{aesAddr, socksAddr} {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Errorf("dial %s: %v", addr, err)
			continue
		}
		_ = conn.Close()
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("runDualListenerDemo did not return within 2s after cancel")
	}
}

// freePort binds a listener on a free port, captures the address,
// and immediately closes the listener. The returned address can be
// re-bound by a subsequent call.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen probe: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
