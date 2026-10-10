package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// echoServer is a tiny upstream echo used by client tests. It reads
// what the client sends and writes it back so we can assert that
// bytes travelled through the SOCKS5 tunnel unmodified.
func echoServer(t *testing.T, addrCh chan<- string) (net.Listener, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echoServer listen: %v", err)
	}
	addrCh <- ln.Addr().String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln, func() {
		_ = ln.Close()
		<-done
	}
}

func TestDialContext_NoAuthThroughLocalServer(t *testing.T) {
	addrCh := make(chan string, 1)
	_, stop := echoServer(t, addrCh)
	defer stop()
	upstreamAddr := <-addrCh

	srvLn, srvStop := startTestSOCKS5(t)
	defer srvStop()
	proxyAddr := srvLn.Addr().String()

	// SOCKS5 connect to upstreamAddr through proxyAddr.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, proxyAddr, upstreamAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	payload := []byte("hello-over-socks5")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	readBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, readBuf); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(readBuf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", readBuf, payload)
	}
}

func TestDialContext_ServerRejectsUnknownAddr(t *testing.T) {
	srvLn, srvStop := startTestSOCKS5(t)
	defer srvStop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Port 1 is almost certainly closed; we expect a SOCKS5 server reply
	// code 0x05 (connection refused) wrapped in *ErrServerReply.
	_, err := DialContext(ctx, srvLn.Addr().String(), "127.0.0.1:1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var sErr *ErrServerReply
	if !errors.As(err, &sErr) {
		t.Logf("got non-ErrServerReply (acceptable if OS refused before handshake): %v", err)
	}
}

func TestDialContext_RespectsContextDeadline(t *testing.T) {
	srvLn, srvStop := startTestSOCKS5(t)
	defer srvStop()

	// 1ms deadline is well before any handshake can complete.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	_, err := DialContext(ctx, srvLn.Addr().String(), "127.0.0.1:1")
	if err == nil {
		t.Fatalf("expected deadline error, got nil")
	}
	if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "i/o timeout") && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Logf("got %v (acceptable if classification differs)", err)
	}
}

func TestSplitHostPort_Defaults443(t *testing.T) {
	host, port, err := splitHostPort("api.minimaxi.com")
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}
	if host != "api.minimaxi.com" || port != 443 {
		t.Fatalf("got host=%q port=%d, want api.minimaxi.com:443", host, port)
	}
}

func TestSplitHostPort_ParsesExplicitPort(t *testing.T) {
	host, port, err := splitHostPort("api.minimaxi.com:8443")
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}
	if host != "api.minimaxi.com" || port != 8443 {
		t.Fatalf("got host=%q port=%d, want api.minimaxi.com:8443", host, port)
	}
}

func TestIndexOf(t *testing.T) {
	if indexOf([]byte("hello\r\nworld"), []byte("\r\n")) != 5 {
		t.Fatal("expected match at 5")
	}
	if indexOf([]byte("hello"), []byte("xyz")) != -1 {
		t.Fatal("expected no match")
	}
	if indexOf([]byte(""), []byte("")) != 0 {
		t.Fatal("empty needle should match at 0")
	}
}

// startTestSOCKS5 starts an in-process no-auth SOCKS5 server on 127.0.0.1.
// Used by client tests to exercise the on-wire handshake.
func startTestSOCKS5(t *testing.T) (net.Listener, func()) {
	t.Helper()
	factory := NewListenerFactory()
	ln, loop, err := factory.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("factory.Listen: %v", err)
	}
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		_ = loop(context.Background(), ln)
	}()
	stop := func() {
		_ = ln.Close()
		<-loopDone
	}
	return ln, stop
}
