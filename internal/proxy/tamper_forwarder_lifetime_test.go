package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// startTamperForwarder used to spawn a goroutine with no termination path at
// all -- `for range ticker.C` with no stop channel, no ctx and no exit
// condition -- and the serve loop called it once per accepted TCP connection,
// uncapped, on a conn it closed on the very next line. The goroutine and its
// 10ms ticker therefore outlived their subject by the life of the process,
// keeping the *crypto.WrapConn reachable the whole time.
//
// Nothing in the suite noticed, because a goroutine that never returns is
// invisible to a test that only checks the metric it writes. These two tests
// assert the LIFETIME instead: the first on the forwarder directly, the second
// through the serve loop that owns the wiring.

// TestStartTamperForwarder_ReturnsWhenItsContextIsDone pins the exit path
// itself. Eight forwarders are started, observed to be running, then retired;
// the count must come back down. Restore `for range ticker.C` and it does not.
func TestStartTamperForwarder_ReturnsWhenItsContextIsDone(t *testing.T) {
	const forwarders = 8

	key := defaultDemoAESKey()
	wrapped := make([]*crypto.WrapConn, 0, forwarders)
	for i := 0; i < forwarders; i++ {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close() })
		wrapped = append(wrapped, crypto.Wrap(server, key))
	}

	base := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	for _, wc := range wrapped {
		startTamperForwarder(ctx, wc)
	}

	// Observe them RUNNING before asserting they stop. Without this the test
	// would also pass against a startTamperForwarder that returned immediately,
	// and the assertion below would be about nothing.
	waitForGoroutines(t, base+forwarders, 5*time.Second)

	cancel()
	for _, wc := range wrapped {
		_ = wc.Close()
	}
	settleGoroutines(t, base, 1, 5*time.Second, "eight tamper forwarders whose context was cancelled")
}

// TestAESMTLSServeLoop_TamperForwarderDiesWithTheAcceptedConnection is the
// wiring half: it is not enough for the forwarder to be STOPPABLE, something
// has to actually stop it. The serve loop closes each wrapped conn immediately
// (no http.Server is registered on this path), so the forwarder's context has
// to be retired in the same breath, or the goroutine outlives the connection it
// was polling -- one per accept, with no cap, which is the defect.
func TestAESMTLSServeLoop_TamperForwarderDiesWithTheAcceptedConnection(t *testing.T) {
	const conns = 8

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, serve, err := NewAESMTLSListenerFactory().Listen(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	served := make(chan error, 1)
	go func() { served <- serve(ctx, ln) }()

	// One warm-up connection first, so the serve loop and its context watcher
	// are demonstrably running before the baseline is read. A baseline taken
	// while those goroutines are still being scheduled would be low by two and
	// would make this assertion fire on its own fixture.
	dialAndAwaitClose(t, addr, -1)
	base := runtime.NumGoroutine()

	for i := 0; i < conns; i++ {
		dialAndAwaitClose(t, addr, i)
	}

	settleGoroutines(t, base, 2, 5*time.Second, "eight connections accepted and closed by the aes-mtls serve loop")

	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Error("ServeLoop did not return within 5s of context cancellation")
	}
}

// dialAndAwaitClose opens one connection and waits for the serve loop to close
// it. The EOF is the proof the connection was ACCEPTED and wrapped -- i.e. that
// a forwarder was started for it -- so a goroutine assertion made afterwards is
// measuring something rather than racing the accept loop.
func dialAndAwaitClose(t *testing.T, addr string, i int) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %d: %v", i, err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var scratch [1]byte
	if _, err := c.Read(scratch[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("conn %d: read after accept = %v, want io.EOF once the serve loop closes the wrapped conn", i, err)
	}
}

// waitForGoroutines waits, bounded, for the live goroutine count to reach at
// least want.
func waitForGoroutines(t *testing.T, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	got := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		if got = runtime.NumGoroutine(); got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutines = %d after %v, want >= %d: the forwarders never started, so nothing below is being tested", got, within, want)
}

// settleGoroutines waits, bounded, for the live goroutine count to come back
// down to baseline+slack and dumps what was still standing if it does not.
//
// The sleep is a POLL interval, not synchronisation: goroutine teardown has no
// event to wait on, so the only honest assertion is "it settles within a bound"
// rather than "it has settled by now", which would be a race against the
// scheduler dressed up as a test.
func settleGoroutines(t *testing.T, baseline, slack int, within time.Duration, what string) {
	t.Helper()
	limit := baseline + slack
	deadline := time.Now().Add(within)
	got := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		if got = runtime.NumGoroutine(); got <= limit {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	buf = buf[:runtime.Stack(buf, true)]
	t.Errorf("after %s, goroutines = %d after %v, want <= %d (baseline %d): the forwarders never retired.\n%s", what, got, within, limit, baseline, buf)
}
