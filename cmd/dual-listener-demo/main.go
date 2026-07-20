// Command dual-listener-demo runs an AES/mTLS-style HTTP listener
// and a SOCKS5 listener side-by-side against an in-process mock
// upstream. It is a proof-of-concept for the ListenerFactory
// contract introduced in v18705 (see ADR-082).
//
// Scope: this binary is NOT wired into the production router
// boot sequence. It exists for:
//
//  1. Demonstrating that two ListenerFactory implementations can
//     compose in a single daemon.
//  2. Smoke-testing the v18705 closeout evidence gate.
//  3. Regression-test scaffolding for future dual-listener work.
//
// Usage:
//
//	go run ./cmd/dual-listener-demo \
//	    --aes-addr 127.0.0.1:18080 \
//	    --socks5-addr 127.0.0.1:11080 \
//	    --mock-body "hello from the demo upstream"
//
// The mock upstream binds to a random loopback port and listens
// for raw HTTP/1.1 GET requests; on receipt it returns the
// configured mock body. This keeps the demo self-contained and
// requires no external services.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
	socks5proxy "github.com/nfsarch33/llm-cluster-router/internal/proxy/socks5"
)

// errEmptyFlag is returned by runDualListenerDemo when an
// address flag is empty. Sentinel for tests via errors.Is.
var errEmptyFlag = errors.New("dual-listener-demo: aes-addr and socks5-addr must both be set")

// startMockUpstream binds an in-process HTTP server on a random
// loopback port and returns the address plus a serve function. The
// HTTP server replies to any request with the configured body.
func startMockUpstream(ctx context.Context, body string) (string, func(context.Context) error, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
	srv := &http.Server{Handler: mux}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr := ln.Addr().String()

	serve := func(ctx context.Context) error {
		// Shut down when ctx is cancelled.
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	return addr, serve, nil
}

// runDualListenerDemo wires both listener factories against the
// mock upstream and blocks until ctx is cancelled. The AES/mTLS
// listener accepts plain TCP (TLS termination is performed by the
// upstream reverse-proxy in production; see ADR-082 §2 scope cap)
// and forwards requests to the mock upstream over loopback. The
// SOCKS5 listener forwards CONNECT requests to the mock upstream.
//
// runDualListenerDemo returns nil on graceful shutdown, or a
// non-nil error if flag validation fails or any listener exits
// unexpectedly before shutdown.
func runDualListenerDemo(ctx context.Context, aesAddr, socksAddr, mockBody string) error {
	if aesAddr == "" || socksAddr == "" {
		return errEmptyFlag
	}

	upstreamAddr, mockServe, err := startMockUpstream(ctx, mockBody)
	if err != nil {
		return fmt.Errorf("start mock upstream: %w", err)
	}

	// Mock upstream runs in its own goroutine.
	go func() { _ = mockServe(ctx) }()

	// Build the AES/mTLS-style listener factory and wire it to a
	// minimal HTTP handler that proxies the request to the mock
	// upstream over loopback. This is the proof that the factory
	// composes with an http.Server.
	aesFactory := proxy.NewAESMTLSListenerFactory()
	aesLn, aesServe, err := aesFactory.Listen(ctx, aesAddr)
	if err != nil {
		return fmt.Errorf("aes-mtls listen: %w", err)
	}
	// aesServe is the factory's generic ServeLoop; for HTTP we use
	// http.Server.Serve directly on aesLn instead. The ServeLoop is
	// exported by the factory so non-HTTP channels (raw TCP relays,
	// future mTLS) can reuse it; HTTP callers ignore it.
	_ = aesServe
	aesHandler := newLoopbackProxyHandler(upstreamAddr)
	aesServer := &http.Server{
		Handler:           aesHandler,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// SOCKS5 listener: builds the factory and lets armon/go-socks5
	// drive the ServeLoop. The SOCKS5 server itself opens the
	// outbound TCP connection to the resolved upstream, so the
	// mock upstream must be reachable via its bound loopback
	// address.
	socksFactory := socks5proxy.NewListenerFactory()
	socksLn, socksServe, err := socksFactory.Listen(ctx, socksAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}

	// Wire shutdown coordination.
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := aesServer.Serve(aesLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("aes-mtls serve: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := socksServe(ctx, socksLn); err != nil {
			errCh <- fmt.Errorf("socks5 serve: %w", err)
		}
	}()

	// Wait for ctx cancellation; on cancel, shut down both servers.
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = aesServer.Shutdown(shutdownCtx)
	_ = aesLn.Close()
	_ = socksLn.Close()

	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			return e
		}
	}
	return nil
}

// newLoopbackProxyHandler returns an http.Handler that proxies
// every request to the supplied loopback upstream address. It is
// the minimal "AES/mTLS-style" request handler for the demo: in
// production the http.Server in main.go handles real LLM routes;
// here we just want to prove that the listener factory's bind +
// Accept seam composes with an http.Server.
func newLoopbackProxyHandler(upstream string) http.Handler {
	client := &http.Client{Timeout: 5 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://"+upstream+r.RequestURI, r.Body)
		if err != nil {
			http.Error(w, "proxy: build request failed", http.StatusInternalServerError)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "proxy: upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = bufio.NewReader(resp.Body).WriteTo(w)
	})
}

func main() {
	var (
		aesAddr   = flag.String("aes-addr", "127.0.0.1:18080", "TCP bind address for the AES/mTLS-style HTTP listener")
		socksAddr = flag.String("socks5-addr", "127.0.0.1:11080", "TCP bind address for the SOCKS5 listener")
		mockBody  = flag.String("mock-body", "hello from the dual-listener demo mock upstream", "body served by the in-process mock upstream")
	)
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SIGINT / SIGTERM cancels the context for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	go func() {
		<-sigCh
		cancel()
	}()

	log.Printf("dual-listener-demo starting: aes=%s socks5=%s", *aesAddr, *socksAddr)
	if err := runDualListenerDemo(ctx, *aesAddr, *socksAddr, *mockBody); err != nil {
		log.Fatalf("dual-listener-demo: %v", err)
	}
	log.Printf("dual-listener-demo stopped")
}
