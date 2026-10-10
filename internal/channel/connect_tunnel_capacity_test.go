package channel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// H1: nothing bounded the number of CONNECT tunnels a gateway would carry, nor
// the lifetime of one that was established and then went silent.
//
// Every other admission gate on this leg is per-REQUEST and constant-cost --
// the feature flag, the constant-time token compare, the exact-match allowlist,
// the dial timeout. None of them counts anything, so all of them together
// answer "may this caller open a tunnel" and none answers "may this caller open
// another ten thousand". One leaked CONNECT token therefore bought unbounded
// sockets, goroutines and copy buffers, and ReadHeaderTimeout stops applying at
// the moment of the hijack, so a tunnel that was opened and then simply held
// was held for as long as the peer felt like holding it.
//
// The tests below pin the three facts that make that finite: the (cap+1)th
// tunnel is refused rather than served, a finished tunnel gives its slot back,
// and a silent tunnel is reaped rather than parked.

// TestConnect_AtCapacity_RefusesWith503AndRetryAfter is the cap itself.
//
// It also asserts where in the chain the refusal happens. A bound that refused
// AFTER the dial would still leave a saturated gateway making outbound
// connections on demand -- the amplifier property -- so the target's accept
// count is part of the assertion, not decoration.
func TestConnect_AtCapacity_RefusesWith503AndRetryAfter(t *testing.T) {
	const maxTunnels = 2
	target := newHoldOpenTarget(t)
	gateway := newCapacityGateway(t, target.addr, maxTunnels, 30*time.Second)

	held := make([]net.Conn, 0, maxTunnels+1)
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; i < maxTunnels; i++ {
		conn, _, resp := dialPlainConnect(t, gateway, target.addr)
		held = append(held, conn)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("tunnel %d: status = %d, want 200 (below the cap of %d)", i+1, resp.StatusCode, maxTunnels)
		}
	}

	// Both admitted tunnels have reached the target by the time their CONNECT
	// replies came back, because the reply is written after the dial returns.
	target.waitForAccepts(t, maxTunnels, 5*time.Second)

	over, _, resp := dialPlainConnect(t, gateway, target.addr)
	held = append(held, over)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("tunnel %d of a cap of %d: status = %d, want %d: the gateway carried a tunnel it had no slot for", maxTunnels+1, maxTunnels, resp.StatusCode, http.StatusServiceUnavailable)
	}
	secs, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || secs < 1 {
		t.Errorf("Retry-After = %q (parse err %v), want an integer >= 1: a refusal with no wait tells a client nothing but 'try again immediately', which is how a full gateway gets hammered", resp.Header.Get("Retry-After"), err)
	}
	var body struct {
		Error string `json:"error"`
		Route string `json:"route"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode refusal body: %v", err)
	}
	_ = resp.Body.Close()
	if body.Error != "tunnels_at_capacity" {
		t.Errorf("refusal code = %q, want %q: the code is the one vocabulary shared by the body, the audit line and the metric", body.Error, "tunnels_at_capacity")
	}
	if body.Route != connectRouteLabel {
		t.Errorf("refusal route = %q, want %q", body.Route, connectRouteLabel)
	}

	// The refusal must be pre-dial. Observed over a window rather than at an
	// instant because the target counts in its own accept goroutine: a dial
	// that had happened would land here within microseconds, but "has not
	// happened" is only observable by looking for a while.
	if n := target.acceptsWithin(250*time.Millisecond, maxTunnels+1); n > maxTunnels {
		t.Errorf("target accepted %d connections, want %d: the refused tunnel was dialled before it was refused, so a saturated gateway is still an outbound amplifier", n, maxTunnels)
	}
}

// TestConnect_ReleasedTunnelSlotIsReusable is the other half of the cap: a
// semaphore that is acquired and never released is a gateway that answers 503
// forever after its first burst, which is a worse outage than the exhaustion it
// replaced. The release is a defer, so this covers every exit from the handler.
func TestConnect_ReleasedTunnelSlotIsReusable(t *testing.T) {
	target := newHoldOpenTarget(t)
	// Idle is left long and the half-close linger is shortened, so the ONLY
	// thing that can end this tunnel is the client closing it. An idle reap
	// would prove the wrong property here.
	gateway := newCapacityGateway(t, target.addr, 1, 30*time.Second, WithConnectHalfCloseLinger(250*time.Millisecond))

	first, _, resp := dialPlainConnect(t, gateway, target.addr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first tunnel: status = %d, want 200", resp.StatusCode)
	}

	blocked, _, resp := dialPlainConnect(t, gateway, target.addr)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second tunnel while the only slot is held: status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	_ = blocked.Close()

	// Closing the client ends both copy directions, the handler returns, and
	// the deferred release runs. There is no event on this side to wait on --
	// the slot is given back inside the gateway -- so the honest assertion is
	// that a retry starts succeeding within a bound.
	_ = first.Close()
	if !tunnelAdmittedWithin(t, gateway, target.addr, 5*time.Second) {
		t.Fatal("no CONNECT was admitted in 5s after the only tunnel closed: the slot was taken and never given back, so this gateway now refuses every tunnel for the rest of its life")
	}
}

// TestConnect_IdleTunnelIsReapedAndFreesItsSlot is the lifetime bound.
//
// The tunnel here is the pathological one: established, allowlisted,
// authorised, and then silent in both directions forever. Neither peer
// half-closes, so neither the CloseWrite relay nor the linger backstop is
// reachable; before the idle deadline there was nothing at all to end it. The
// fixtures are chosen so that only the gateway can be what ends it -- the
// target never writes and never closes, and the client is read with a deadline
// far longer than the idle bound so a client-side timeout cannot be mistaken
// for a reaping.
//
// idle is kept well below the default 30s linger deliberately, because that is
// the deployment shape in which arming can undo the idle bound. It EXERCISES
// the arm-must-only-tighten rule but does not pin it -- whether a broken arm
// shows up here depends on whether both directions expire in the same
// scheduling instant, so it passes on an idle machine and hangs on a busy one.
// TestTunnelDeadlines_ArmingCannotExtendAnIdleDeadline is what pins it.
func TestConnect_IdleTunnelIsReapedAndFreesItsSlot(t *testing.T) {
	const idle = 250 * time.Millisecond
	target := newHoldOpenTarget(t)
	gateway := newCapacityGateway(t, target.addr, 1, idle)

	conn, br, resp := dialPlainConnect(t, gateway, target.addr)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tunnel: status = %d, want 200", resp.StatusCode)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var scratch [1]byte
	n, err := br.Read(scratch[:])
	switch {
	case err == nil:
		t.Fatalf("read through an idle tunnel returned %d byte(s) from a target that never writes; the fixture is not the one this test needs", n)
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatalf("the tunnel was still open 10s into an idle timeout of %v: nothing reaps a tunnel that is established and then silent, so holding one costs an attacker a socket and costs the gateway two goroutines, two sockets and 64KiB", idle)
	}

	// Reaping that does not release the slot would trade an unbounded hold for
	// a permanently shrinking cap, which is the same outage arrived at slowly.
	if !tunnelAdmittedWithin(t, gateway, target.addr, 5*time.Second) {
		t.Fatal("no CONNECT was admitted in 5s after the idle tunnel was reaped: the reaper freed the sockets but not the semaphore slot")
	}
}

// TestTunnelDeadlines_ArmingCannotExtendAnIdleDeadline pins the half of the
// tighten-only rule that a black-box tunnel test can only sample.
//
// The scenario is exactly what a gateway with idle < linger does on every
// tunnel that goes quiet: one direction expires on the idle deadline and arms
// the half-close linger while the OTHER direction is still parked in Read on a
// deadline that was about to fire. An arm that applies the linger deadline
// unconditionally hands that parked direction a fresh linger-long lease -- the
// socket that was one instant from being reaped is now held for another thirty
// seconds, and the idle bound has been undone by the mechanism that was
// supposed to reinforce it.
//
// Driven directly against tunnelDeadlines over net.Pipe rather than through a
// tunnel, because through a tunnel the outcome depends on which of two
// goroutines the scheduler happens to run first: the defect is real either way,
// but only this shape reports it every time.
func TestTunnelDeadlines_ArmingCannotExtendAnIdleDeadline(t *testing.T) {
	const idle = 100 * time.Millisecond
	const linger = 30 * time.Second

	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer func() {
		_ = client.Close()
		_ = clientPeer.Close()
		_ = upstream.Close()
		_ = upstreamPeer.Close()
	}()

	d := &tunnelDeadlines{client: client, upstream: upstream, idle: idle, linger: linger}
	d.refreshIdle(client)
	d.refreshIdle(upstream)
	d.arm()

	start := time.Now()
	unblocked := make(chan time.Duration, 1)
	go func() {
		var scratch [1]byte
		_, _ = upstream.Read(scratch[:])
		unblocked <- time.Since(start)
	}()

	// The select is the BOUND, not synchronisation: there is no event that
	// says "this read is still blocked", so the only honest assertion is that
	// it comes back inside a window far shorter than the linger it must not
	// have been granted.
	select {
	case took := <-unblocked:
		if took > 20*idle {
			t.Errorf("the read came back after %v against an idle deadline of %v: arming pushed it out", took, idle)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the read was still blocked 5s after arming, against an idle deadline of %v that had already been set: arming EXTENDED the deadline it exists to bound, so on every gateway with idle_timeout below the half-close linger the first direction to expire buys the second a fresh %v on a socket that was about to be reaped", idle, linger)
	}
}

// TestValidateConnect_BoundsDefaultAndRefuseNegative pins the config half. The
// interesting case is ZERO: every gateway config written before these keys
// existed omits them, so a zero that meant "unlimited" would leave exactly the
// deployments the bound exists for running unbounded.
func TestValidateConnect_BoundsDefaultAndRefuseNegative(t *testing.T) {
	base := func() *Config {
		return &Config{
			Listen: "127.0.0.1:0",
			Connect: ConnectConfig{
				Enabled:      true,
				TokenEnv:     "TEST_CONNECT_BOUNDS_TOKEN",
				AllowedHosts: []string{"api.example.invalid:443"},
			},
		}
	}

	cfg := base()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate with the bounds omitted: %v", err)
	}
	if cfg.Connect.MaxConcurrent != DefaultConnectMaxConcurrent {
		t.Errorf("max_concurrent omitted = %d, want the default %d: an omitted key must not mean unlimited", cfg.Connect.MaxConcurrent, DefaultConnectMaxConcurrent)
	}
	if cfg.Connect.IdleTimeout != DefaultConnectIdleTimeout {
		t.Errorf("idle_timeout omitted = %v, want the default %v: an omitted key must not mean never reap", cfg.Connect.IdleTimeout, DefaultConnectIdleTimeout)
	}

	cfg = base()
	cfg.Connect.MaxConcurrent = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "max_concurrent") {
		t.Errorf("validate with max_concurrent -1 = %v, want an error naming max_concurrent", err)
	}

	cfg = base()
	cfg.Connect.IdleTimeout = -time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "idle_timeout") {
		t.Errorf("validate with idle_timeout -1s = %v, want an error naming idle_timeout", err)
	}
}

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

// holdOpenTarget stands in for a provider endpoint that accepts and then does
// nothing: it never writes and never closes, draining whatever arrives. That is
// what makes it usable as the target of a SILENT tunnel -- there is no action
// it can take that would end a tunnel, so a tunnel that ends was ended by the
// gateway.
type holdOpenTarget struct {
	addr    string
	accepts atomic.Int64
}

func newHoldOpenTarget(t *testing.T) *holdOpenTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	tgt := &holdOpenTarget{addr: ln.Addr().String()}

	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			tgt.accepts.Add(1)
			go func() { _, _ = io.Copy(io.Discard, conn) }()
		}
	}()
	return tgt
}

// waitForAccepts blocks, bounded, until the target has accepted at least n.
func (h *holdOpenTarget) waitForAccepts(t *testing.T, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if h.accepts.Load() >= int64(n) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("target accepted %d connections in %v, want at least %d", h.accepts.Load(), within, n)
}

// acceptsWithin watches the accept count for window and returns the highest
// value seen, stopping early once it reaches stopAt. The poll is an OBSERVATION
// WINDOW for a negative claim ("no further dial happened"), not synchronisation
// for a positive one: there is no event that signals a dial that never occurred.
func (h *holdOpenTarget) acceptsWithin(window time.Duration, stopAt int) int {
	deadline := time.Now().Add(window)
	high := int(h.accepts.Load())
	for time.Now().Before(deadline) {
		if got := int(h.accepts.Load()); got > high {
			high = got
		}
		if high >= stopAt {
			return high
		}
		time.Sleep(5 * time.Millisecond)
	}
	return high
}

// newCapacityGateway serves a CONNECT-enabled gateway over PLAINTEXT on
// loopback and returns its address.
//
// Plaintext is the right fixture for these three, and deliberately different
// from the TLS-terminating fixture the half-close tests insist on: the bound
// under test is counted in the handler before the conn is ever hijacked, so it
// is posture-independent, and a plaintext listener keeps the failure being read
// here about admission rather than about handshakes.
func newCapacityGateway(t *testing.T, target string, maxConcurrent int, idle time.Duration, opts ...ServerOption) string {
	t.Helper()
	t.Setenv("TEST_CONNECT_CAP_TOKEN", "cap-token-not-real")
	cfg := &Config{
		Listen: "127.0.0.1:0",
		Connect: ConnectConfig{
			Enabled:       true,
			TokenEnv:      "TEST_CONNECT_CAP_TOKEN",
			AllowedHosts:  []string{target},
			DialTimeout:   5 * time.Second,
			MaxConcurrent: maxConcurrent,
			IdleTimeout:   idle,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return ln.Addr().String()
}

// dialPlainConnect opens one authorised CONNECT and returns the conn, the
// buffered reader that owns any bytes read past the reply, and the reply.
//
// The reply is parsed with http.ReadResponse against a CONNECT request so a 200
// is correctly read as having no body -- anything after the blank line is
// tunnel payload and stays in the reader -- while a 503 keeps its JSON body.
func dialPlainConnect(t *testing.T, gateway, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", gateway, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer cap-token-not-real\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT reply: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, br, resp
}

// tunnelAdmittedWithin retries CONNECT until one is admitted or the bound
// expires, closing every attempt it makes so the retries cannot themselves be
// what exhausts the cap.
//
// The CONN is closed BEFORE the body, and that order is load-bearing. To
// net/http a 2xx reply to CONNECT has an UNBOUNDED body -- the body IS the
// tunnel -- so http.body.Close drains it, and draining a tunnel nobody is
// writing to blocks until the tunnel dies. Closing the conn first turns that
// drain into an immediate error. Written the other way round, this helper
// waits out the idle timeout on every success and reports the bound it was
// measuring as its own latency.
func tunnelAdmittedWithin(t *testing.T, gateway, target string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		conn, _, resp := dialPlainConnect(t, gateway, target)
		status := resp.StatusCode
		_ = conn.Close()
		_ = resp.Body.Close()
		if status == http.StatusOK {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
