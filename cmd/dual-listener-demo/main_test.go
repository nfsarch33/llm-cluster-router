package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

// TestDualListenerDemo_EmitsAgentraceEvents verifies the
// observability wiring: when runDualListenerDemo is invoked with
// an Agentrace log path, the demo writes one event per accept to
// the NDJSON log.
func TestDualListenerDemo_EmitsAgentraceEvents(t *testing.T) {
	dir := t.TempDir()
	agentracePath := filepath.Join(dir, "agentrace.ndjson")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	aesAddr := freePort(t)
	socksAddr := freePort(t)

	// Note: we pass the observability deps via the package-level
	// override — runDualListenerDemo picks them up.
	prev := agentraceLogPath
	agentraceLogPath = agentracePath
	t.Cleanup(func() { agentraceLogPath = prev })

	done := make(chan error, 1)
	go func() { done <- runDualListenerDemo(ctx, aesAddr, socksAddr, "demo-body") }()
	time.Sleep(50 * time.Millisecond)

	// Drive a real HTTP request through the AES-style listener so
	// the demo's handler records an accept.
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", aesAddr)
	if err != nil {
		t.Fatalf("dial aes: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runDualListenerDemo did not return within 2s after cancel")
	}

	data, err := os.ReadFile(agentracePath)
	if err != nil {
		t.Fatalf("read agentrace: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatal("no agentrace events recorded")
	}
	var sawAES bool
	for _, line := range lines {
		var e map[string]any
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("malformed line: %v", err)
		}
		if e["listener"] == "aes-mtls" && e["event"] == "demo.accept" {
			sawAES = true
		}
	}
	if !sawAES {
		t.Errorf("no aes-mtls demo.accept event found in:\n%s", string(data))
	}
}

// TestDualListenerDemo_ExposesMetricsEndpoint verifies that the
// /metrics handler on the demo serves the dual-listener
// Prometheus series when a metrics addr is supplied.
func TestDualListenerDemo_ExposesMetricsEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	aesAddr := freePort(t)
	socksAddr := freePort(t)
	metricsAddr := freePort(t)

	prev := metricsListenAddr
	metricsListenAddr = metricsAddr
	t.Cleanup(func() { metricsListenAddr = prev })

	done := make(chan error, 1)
	go func() { done <- runDualListenerDemo(ctx, aesAddr, socksAddr, "demo-body") }()
	time.Sleep(80 * time.Millisecond)

	// Hit /metrics.
	resp, err := http.Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	out := string(body)
	if !strings.Contains(out, "llm_cluster_router_connections_total") {
		t.Errorf("/metrics missing connections series:\n%s", out)
	}
	if !strings.Contains(out, "llm_cluster_router_bytes_total") {
		t.Errorf("/metrics missing bytes series:\n%s", out)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runDualListenerDemo did not return within 2s after cancel")
	}
}

// TestStartMetricsServer_HonoursCtxShutdown verifies the metrics
// server goroutine returns promptly when ctx is cancelled.
func TestStartMetricsServer_HonoursCtxShutdown(t *testing.T) {
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- startMetricsServer(ctx, addr) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("metrics server did not return within 2s")
	}
}

// touchBufioReader is referenced to keep bufio import alive in
// case future tests need buffered reads.
var _ = bufio.NewReader
