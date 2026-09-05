package channel

// Shutdown lifecycle pins (v18815).
//
// WHY: every listener in this package shut down with a flat
// `context.WithTimeout(context.Background(), 5*time.Second)`, and 5 seconds is
// ALSO net/http's own threshold for reclaiming a connection that was accepted
// but has not yet sent a request header (stdlib issue 22682). The two being
// equal made a clean shutdown arithmetically impossible whenever one such
// connection existed: Shutdown returned context.DeadlineExceeded, the error was
// propagated unchanged, and `helixchannel gateway` exited NON-ZERO on an
// ordinary SIGTERM.
//
// Measured against the old code, one connection, varying only its age at the
// moment shutdown began: none -> 0s/nil; freshly opened -> 5s/deadline
// exceeded; the same connection aged past 5s -> 0s/nil. The third arm is what
// identified the mechanism -- nothing about the connection blocks shutdown, the
// budget merely expired at the instant the connection became reclaimable.
//
// Every "shuts down cleanly" case below is bracketed by a control, because
// "Serve returned nil" proves nothing unless the same code can also be shown to
// return an error, and to still be waiting for something real.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The invariant. This is the whole defect in one line, and it is the assertion
// a future "tidy up the magic numbers" commit has to trip over.
// ---------------------------------------------------------------------------

func TestShutdownGraceClearsNetHTTPStateNewGrace(t *testing.T) {
	if shutdownGrace <= httpStateNewIdleGrace {
		t.Fatalf("shutdownGrace = %s, net/http's StateNew reclamation grace = %s: "+
			"a budget that does not EXCEED it can never drain a connection that was "+
			"accepted and then said nothing, which is the defect this constant exists "+
			"to prevent", shutdownGrace, httpStateNewIdleGrace)
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func shutdownTestConfig(t *testing.T, listen string) *Config {
	t.Helper()
	t.Setenv("V18815_SHUTDOWN_TEST_KEY", "sk-shutdown-test")
	dir := t.TempDir()
	p := dir + "/gateway.yml"
	body := fmt.Sprintf("listen: %q\nroutes:\n  - name: mm\n    prefix: /mm/\n"+
		"    upstream: \"http://127.0.0.1:9\"\n    auth: inject\n"+
		"    key_env: V18815_SHUTDOWN_TEST_KEY # gitleaks:allow - env NAME, not a secret\n"+
		"    enabled: true\n", listen)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

func shutdownTestListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// dialSilently opens a TCP connection and deliberately sends NOTHING, which is
// StateNew on the server side. This is the connection an LB health probe, a
// pre-dialling connection pool, or a client still in its TLS handshake presents.
func dialSilently(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// Give the server time to accept it, so it is genuinely in StateNew rather
	// than still sitting in the backlog when shutdown starts.
	time.Sleep(150 * time.Millisecond)
	return c
}

// awaitShutdown cancels ctx and reports how the serve call returned.
func awaitShutdown(t *testing.T, cancel context.CancelFunc, done <-chan error) (time.Duration, error) {
	t.Helper()
	cancel()
	start := time.Now()
	select {
	case err := <-done:
		return time.Since(start), err
	case <-time.After(shutdownGrace + 20*time.Second):
		t.Fatal("serve never returned, even well past the shutdown budget")
		return 0, nil
	}
}

func requireCleanShutdown(t *testing.T, what string, elapsed time.Duration, err error) {
	t.Helper()
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s: shutdown = %v after %s, want a clean shutdown. "+
			"A connection that was accepted and then said nothing is not reclaimable "+
			"by net/http for %s, so a budget of %s or less can never drain it.",
			what, err, elapsed.Round(10*time.Millisecond), httpStateNewIdleGrace, httpStateNewIdleGrace)
	}
	if err != nil {
		t.Fatalf("%s: shutdown = %v after %s, want nil", what, err, elapsed.Round(10*time.Millisecond))
	}
	if elapsed >= shutdownGrace {
		t.Fatalf("%s: shutdown took %s, which is the whole %s budget -- it drained by "+
			"running out of time, not by finishing", what, elapsed.Round(10*time.Millisecond), shutdownGrace)
	}
}

// ---------------------------------------------------------------------------
// The reverse-proxy leg: Server.Serve. This is the path `helixchannel gateway`
// takes, and the one whose failure made SIGTERM exit non-zero.
// ---------------------------------------------------------------------------

func TestServe_CleanShutdownWithAcceptedButSilentConnection(t *testing.T) {
	ln := shutdownTestListener(t)
	addr := ln.Addr().String()
	srv, err := NewServer(shutdownTestConfig(t, addr), NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	time.Sleep(150 * time.Millisecond)

	dialSilently(t, addr)

	elapsed, err := awaitShutdown(t, cancel, done)
	requireCleanShutdown(t, "Server.Serve", elapsed, err)
}

// CONTROL for the case above. With no connection at all the shutdown is clean
// and immediate on the OLD code too, so if this ever starts failing the test
// above is passing against a shutdown that has stopped working entirely rather
// than against the fix.
func TestServe_CleanShutdownWithNoConnections(t *testing.T) {
	ln := shutdownTestListener(t)
	srv, err := NewServer(shutdownTestConfig(t, ln.Addr().String()), NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	time.Sleep(150 * time.Millisecond)

	elapsed, err := awaitShutdown(t, cancel, done)
	requireCleanShutdown(t, "Server.Serve (no connections)", elapsed, err)
	if elapsed > httpStateNewIdleGrace {
		t.Fatalf("an idle server took %s to stop; nothing should have been waited on",
			elapsed.Round(10*time.Millisecond))
	}
}

// ---------------------------------------------------------------------------
// The AES leg: Server.ServeWrapped. Same defect, same fix, different listener.
// ---------------------------------------------------------------------------

func TestServeWrapped_CleanShutdownWithAcceptedButSilentConnection(t *testing.T) {
	ln := shutdownTestListener(t)
	addr := ln.Addr().String()
	srv, err := NewServer(shutdownTestConfig(t, addr), NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var key [32]byte
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ServeWrapped(ctx, ln, key) }()
	time.Sleep(150 * time.Millisecond)

	dialSilently(t, addr)

	elapsed, err := awaitShutdown(t, cancel, done)
	requireCleanShutdown(t, "Server.ServeWrapped", elapsed, err)
}

// ---------------------------------------------------------------------------
// The client-side listeners. Both carried the identical 5s budget.
// ---------------------------------------------------------------------------

func TestAESBridge_CleanShutdownWithAcceptedButSilentConnection(t *testing.T) {
	ln := shutdownTestListener(t)
	addr := ln.Addr().String()
	b := &AESBridge{Listen: addr, Gateway: "127.0.0.1:1"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.Serve(ctx, ln) }()
	time.Sleep(150 * time.Millisecond)

	dialSilently(t, addr)

	elapsed, err := awaitShutdown(t, cancel, done)
	requireCleanShutdown(t, "AESBridge.Serve", elapsed, err)
}

func TestClientProxy_CleanShutdownWithAcceptedButSilentConnection(t *testing.T) {
	probe := shutdownTestListener(t)
	addr := probe.Addr().String()
	_ = probe.Close() // hand the port to ClientProxy, which binds it itself

	p := &ClientProxy{
		Listen:  addr,
		Gateway: "127.0.0.1:1",
		Token:   "shutdown-test-token", // gitleaks:allow - fixture, not a credential
		Audit:   NewAuditor(io.Discard),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.ListenAndServe(ctx) }()

	// It binds for itself, so wait for the socket rather than for a sleep.
	var bound bool
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			bound = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bound {
		t.Fatal("client proxy never bound its listener")
	}

	dialSilently(t, addr)

	elapsed, err := awaitShutdown(t, cancel, done)
	requireCleanShutdown(t, "ClientProxy.ListenAndServe", elapsed, err)
}

// ---------------------------------------------------------------------------
// The forced-close path, driven directly so it costs milliseconds rather than
// the whole shutdownGrace. This is why the budget is a parameter.
// ---------------------------------------------------------------------------

func TestShutdownHTTPServerWithin_ForcesCloseReportsAndStillJoins(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var once bool
	srv := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !once {
				once = true
				entered <- struct{}{}
			}
			<-release // hold the connection in StateActive
		}),
	}
	t.Cleanup(func() { close(release) })

	ln := shutdownTestListener(t)
	addr := ln.Addr().String()
	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	go func() { _, _ = http.Get("http://" + addr + "/held") }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("handler never ran; nothing was holding the connection open")
	}

	start := time.Now()
	err := shutdownHTTPServerWithin(srv, serveErr, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("shutdown of a server with a stuck handler = nil, want the forced close reported")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if !containsStr(err.Error(), "remaining connections were closed") {
		t.Fatalf("err = %q, want it to say the connections were closed, not just that a deadline passed", err)
	}
	// The join is the point: it returned, which means the serve goroutine had
	// already returned, which only happens because Close() was called.
	if elapsed > 10*time.Second {
		t.Fatalf("forced shutdown took %s; it did not join promptly", elapsed.Round(10*time.Millisecond))
	}
}

// CONTROL for the case above: the same helper, the same tiny budget, but
// nothing stuck. It must come back nil -- otherwise the assertion above is
// satisfied by any small budget rather than by a connection that would not
// drain.
func TestShutdownHTTPServerWithin_TinyBudgetIsFineWhenNothingIsStuck(t *testing.T) {
	srv := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	ln := shutdownTestListener(t)
	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()
	time.Sleep(150 * time.Millisecond)

	if err := shutdownHTTPServerWithin(srv, serveErr, 200*time.Millisecond); err != nil {
		t.Fatalf("shutdown of an idle server with a 200ms budget = %v, want nil", err)
	}
}

func containsStr(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
