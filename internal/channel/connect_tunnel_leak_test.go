package channel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The CONNECT tunnel leaked goroutines on ONE deployment posture and only that
// one: a gateway that terminates TLS. Nothing in the suite covered it, because
// every other tunnel test either drives the handler through a recorder that
// cannot be hijacked, or drives it over a plaintext listener where the hijacked
// conn really is the *net.TCPConn the old code asserted on.
//
// Both tests below therefore insist on a REAL tls.Server-wrapped listener. A
// plaintext listener passes them with the defect fully restored, so a future
// simplification of the fixture is a silent removal of the coverage.

// TestConnectTunnel_TLSTerminatedGatewayRelaysTheUpstreamHalfClose is the C1
// regression: with the gateway terminating TLS, the hijacked client conn is a
// *tls.Conn, and the old `client.(*net.TCPConn)` assertion returned false, so
// the upstream half-close was never relayed. The client, having been told
// nothing, stayed open and idle; the client->upstream copy blocked forever;
// wg.Wait never returned; and the handler goroutine plus the two deferred
// Closes went with it -- three goroutines and two sockets per tunnel, with
// nothing capping the total.
//
// The assertion is the one an affected client would make: after the upstream
// half-closes, a read must yield io.EOF. Reverting closeWriter to the concrete
// *net.TCPConn assertion turns that read into a deadline timeout.
func TestConnectTunnel_TLSTerminatedGatewayRelaysTheUpstreamHalfClose(t *testing.T) {
	const greeting = "upstream-said-this-then-hung-up"
	target := halfCloseTarget(t, greeting, 1)

	t.Setenv("TEST_CONNECT_LEAK_TOKEN", "leak-token")
	// No linger override: the backstop is left at its 30s production value so
	// it cannot be what rescues this test. Only the half-close relay can.
	srv := connectLeakServer(t, target)
	cert, pool := selfSignedLoopbackTLS(t)
	gateway := serveTLSGateway(t, srv, cert)

	base := runtime.NumGoroutine()

	conn := dialConnectTunnel(t, gateway, target, "leak-token", pool)
	defer func() { _ = conn.Close() }()

	if _, err := io.ReadFull(conn, make([]byte, len(greeting))); err != nil {
		t.Fatalf("read greeting through the tunnel: %v", err)
	}

	// The upstream has already half-closed by now. A gateway that relays it
	// sends close_notify, which surfaces here as io.EOF.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var scratch [1]byte
	_, err := conn.Read(scratch[:])
	if !errors.Is(err, io.EOF) {
		t.Errorf("read after the upstream half-closed = %v, want io.EOF: the TLS-terminating gateway never relayed the FIN, so this client would sit open forever and the handler would stay parked in wg.Wait", err)
	}

	// A client that IS told the tunnel is finished closes, and everything
	// downstream of it must unwind.
	_ = conn.Close()
	settleGoroutines(t, base, 1, 5*time.Second, "one completed TLS-terminated CONNECT tunnel")
}

// TestConnectTunnel_IdleClientIgnoringTheFINCannotParkTheTunnel is the second
// half of C1: the backstop.
//
// CloseWrite asks a peer to go away; nothing compels it to. A client that reads
// the FIN and then neither writes nor closes -- which is every abandoned agent
// process, and is trivial for an attacker to arrange deliberately -- still
// parks the client->upstream copy on a socket that will never produce another
// byte. The deadline armed when the first direction finishes is what bounds
// that, and this test is what proves the deadline is armed at all: remove the
// armLinger calls and these four tunnels never unwind.
func TestConnectTunnel_IdleClientIgnoringTheFINCannotParkTheTunnel(t *testing.T) {
	const tunnels = 4
	const greeting = "upstream-said-this-then-hung-up"
	target := halfCloseTarget(t, greeting, tunnels)

	t.Setenv("TEST_CONNECT_LEAK_TOKEN", "leak-token")
	srv := connectLeakServer(t, target, WithConnectHalfCloseLinger(250*time.Millisecond))
	cert, pool := selfSignedLoopbackTLS(t)
	gateway := serveTLSGateway(t, srv, cert)

	base := runtime.NumGoroutine()

	// Deliberately never closed and never read from again: these clients are
	// the unresponsive peer. They are kept referenced so nothing can be
	// finalised out from under the assertion.
	conns := make([]*tls.Conn, 0, tunnels)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := 0; i < tunnels; i++ {
		conns = append(conns, dialConnectTunnel(t, gateway, target, "leak-token", pool))
	}

	// Slack of 2 against a leak of at least 2 goroutines per tunnel (the parked
	// copy and the handler blocked in wg.Wait), so 4 tunnels put 8 or more
	// goroutines on the wrong side of the threshold and the reading cannot be
	// confused with scheduler noise.
	settleGoroutines(t, base, 2, 10*time.Second, fmt.Sprintf("%d TLS-terminated CONNECT tunnels whose clients ignored the FIN", tunnels))
}

// connectLeakServer builds a CONNECT-enabled gateway allowlisting exactly one
// target. The listen string is a loopback literal, which matters only in that
// it keeps Config.Validate happy: the handler decides scope from the socket the
// request arrived on, and serveTLSGateway binds 127.0.0.1.
func connectLeakServer(t *testing.T, target string, opts ...ServerOption) *Server {
	t.Helper()
	cfg := &Config{
		Listen: "127.0.0.1:0",
		Connect: ConnectConfig{
			Enabled: true, TokenEnv: "TEST_CONNECT_LEAK_TOKEN",
			AllowedHosts: []string{target}, DialTimeout: 5 * time.Second,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard), opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// serveTLSGateway runs the gateway handler behind a tls.Server-wrapped
// listener, which is what makes the hijacked conn a *tls.Conn. Server.Serve is
// not used because it insists on cert FILES; the posture under test is the TLS
// termination itself, and tls.NewListener reproduces it exactly.
//
// http.Server.Close does not wait on hijacked connections -- net/http stops
// tracking a conn the moment it enters StateHijacked -- so the cleanup below
// cannot mask a parked tunnel by tearing it down before the assertion runs.
func serveTLSGateway(t *testing.T, srv *Server, cert tls.Certificate) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	ln := tls.NewListener(raw, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return raw.Addr().String()
}

// dialConnectTunnel opens one authorised CONNECT tunnel and returns it with the
// 200 reply already consumed, so the caller reads tunnelled bytes and nothing
// else. The reply is exactly 39 bytes and is read with ReadFull rather than a
// bufio.Reader precisely so that no tunnel payload is swallowed into a buffer
// the caller cannot see.
func dialConnectTunnel(t *testing.T, gateway, target, token string, pool *x509.CertPool) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", gateway, &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls dial gateway: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n", target, target, token); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reply := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if !strings.Contains(string(reply), "200") {
		t.Fatalf("CONNECT reply = %q, want a 200", reply)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

// halfCloseTarget stands in for a provider endpoint that finishes its response
// and half-closes: it writes greeting, sends FIN with CloseWrite, and then
// keeps its READ side open, draining until the peer goes away. Keeping the read
// side open is the whole point -- a target that closed outright would make the
// gateway unwind for a reason that has nothing to do with the half-close.
func halfCloseTarget(t *testing.T, greeting string, accepts int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for i := 0; i < accepts; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, err := io.WriteString(conn, greeting); err != nil {
					return
				}
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// settleGoroutines waits, bounded, for the live goroutine count to come back
// down to baseline+slack and reports what was still standing if it does not.
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
	t.Errorf("after %s, goroutines = %d after %v, want <= %d (baseline %d): the tunnel did not unwind.\n%s", what, got, within, limit, baseline, buf)
}

// selfSignedLoopbackTLS mints a throwaway P-256 certificate valid for
// 127.0.0.1 and returns it with a pool that trusts it, so the client verifies
// the chain properly instead of reaching for InsecureSkipVerify.
func selfSignedLoopbackTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "connect-tunnel-leak-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
