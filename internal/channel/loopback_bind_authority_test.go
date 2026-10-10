package channel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This file pins the answer to a defect that arrived three times.
//
// Each round added an accommodation to a predicate that GATES A RELAXATION --
// first a loopback exemption for "localhost", then inet_aton parsing, then an
// unconditional zone strip -- and each accommodation created a new string the
// predicate trusted and the OS resolved differently. The third was
// "127.0.0.1%evil": bareHost dropped the zone, net.ParseIP then read 127.0.0.1,
// isLoopbackListen said loopback -- and net.Listen, which knows IPv4 has no
// zones, treated the whole string as a HOST NAME, resolved it through the hosts
// file and DNS, and bound 172.29.144.56. All three relaxations fired on a
// routable socket.
//
// Patching the third spelling would have invited a fourth. The class is
// eliminated instead: nothing is gated on a PREDICTION of what net.Listen will
// do any more. The gateway binds, reads ln.Addr() -- the address the kernel
// actually gave it, which no spelling and no resolver can disagree with -- and
// decides from that, before it serves a single request.
//
// The config-time predicate stays, demoted to what it can soundly be: an early,
// advisory refusal that catches the obvious mistakes while an operator is still
// reading the file.

// stagedListener is a real, dialable listener on loopback that REPORTS whatever
// address a test needs.
//
// It exists so a test can stage a bind shape -- a wildcard socket, one of the
// host's routable addresses -- without opening a port to the network, and so
// that Accept and Close are observable. accepts is the load-bearing one: it is
// how "not one request was served in that window" is proved rather than
// asserted, because net/http cannot serve a request it never accepted.
type stagedListener struct {
	net.Listener
	addr    net.Addr
	accepts atomic.Int64
	closed  atomic.Bool
}

func (l *stagedListener) Addr() net.Addr { return l.addr }

func (l *stagedListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	return l.Listener.Accept()
}

func (l *stagedListener) Close() error {
	l.closed.Store(true)
	return l.Listener.Close()
}

// stagedOn returns a listener really bound to loopback that reports addr.
func stagedOn(t *testing.T, addr net.Addr) *stagedListener {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return &stagedListener{Listener: raw, addr: addr}
}

// serveExpectingRefusal runs Serve and requires it to return an error promptly.
//
// The bounded wait is the point. A Serve that decides too late -- or not at all
// -- goes on serving and blocks until ctx is cancelled, and a test that simply
// called Serve would hang until the package timeout and report nothing useful.
// This fails with the sentence that names what actually went wrong.
func serveExpectingRefusal(t *testing.T, srv *Server, ln net.Listener) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve returned nil where a refusal was required: the socket is reachable from other hosts and this configuration is only permissible while it is not")
		}
		return err
	case <-time.After(10 * time.Second):
		cancel()
		<-done
		t.Fatal("Serve is SERVING where a refusal was required: it either did not decide from the bound socket, or decided after handing the listener to net/http")
		return nil
	}
}

// tokenlessServer builds a gateway in the one posture the bind rule governs:
// no gateway token and no written-down allow_unauthenticated, so reaching the
// socket is the whole of the admission decision. Validate is NOT called -- these
// tests are about what happens when the config text and the socket disagree,
// which is exactly the case Validate cannot see.
func tokenlessServer(t *testing.T, listen string) *Server {
	t.Helper()
	cfg := &Config{
		Listen: listen,
		Routes: []Route{{
			Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
			Auth: AuthPassthrough, Enabled: true,
		}},
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.ProxyAuthMode() != ProxyAuthLoopbackOnly {
		t.Fatalf("proxy_auth = %q, want %q: this config names no gateway token", srv.ProxyAuthMode(), ProxyAuthLoopbackOnly)
	}
	return srv
}

// ipv4ZoneListens are the spelling class aec1653 did not consider: a zone
// suffix on something that is not an IPv6 address. Only IPv6 has zones, so a
// '%' here makes the whole string a host NAME as far as net.Listen is
// concerned.
var ipv4ZoneListens = []string{
	"127.0.0.1%evil", "127.0.0.1%lo", "127.0.0.53%eth0", "127.1%evil",
}

// zoneHintFragment is the sentence the zone refusal must carry, matched on a
// fragment so the test fails on it being GONE rather than on it being reworded.
const zoneHintFragment = "only an IPv6 address has zones"

// TestBareHost_StripsAZoneOnlyWhereAZoneIsLegal is the narrow half of the fix.
//
// bareHost used to drop everything after '%' unconditionally, which is what let
// "127.0.0.1%evil" reach net.ParseIP as "127.0.0.1". Go decides an address
// family from the first '.' or ':' in the string, so a zone is parsed only when
// the address is IPv6 -- and this function now applies the same test, which is
// what keeps its answer and the OS's answer aligned instead of merely close.
func TestBareHost_StripsAZoneOnlyWhereAZoneIsLegal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want, why string
	}{
		{"127.0.0.1", "127.0.0.1", "no zone, nothing to do"},
		{"[::1]", "::1", "brackets come off"},
		{"::1%lo", "::1", "a legitimate IPv6 zone: net.Listen splits it off and binds ::1"},
		{"fe80::1%eth0", "fe80::1", "the same, on a link-local address"},
		{"::ffff:127.0.0.1%evil", "::ffff:127.0.0.1", "IPv6 text, so Go parses the zone; measured binding 127.0.0.1"},
		{"127.0.0.1%evil", "127.0.0.1%evil", "IPv4 has no zones, so this whole string is a host NAME to net.Listen"},
		{"127.1%evil", "127.1%evil", "the same, on an inet_aton spelling"},
		{"2130706433%evil", "2130706433%evil", "no dot and no colon before the '%': not an address at all"},
		{"localhost%1", "localhost%1", "a name with a '%' in it is still a name"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := bareHost(tc.in); got != tc.want {
				t.Errorf("bareHost(%q) = %q, want %q: %s", tc.in, got, tc.want, tc.why)
			}
		})
	}
}

// TestBareHost_AgreesWithNetListen is the measurement behind the table above.
//
// For every spelling this package claims is an address literal with a zone, the
// kernel must hand back the address bareHost said it would. This is the check
// that would have caught the defect at the moment it was written: the old
// bareHost claimed "127.0.0.1%evil" was 127.0.0.1, and net.Listen disagreed by
// going to the resolver.
func TestBareHost_AgreesWithNetListen(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"127.0.0.1", "[::1%lo]", "[::ffff:127.0.0.1%evil]", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			ln, err := net.Listen("tcp", host+":0")
			if err != nil {
				t.Skipf("listen %q: %v (this host cannot stage the spelling)", host, err)
			}
			defer func() { _ = ln.Close() }()

			bare, _ := splitHostPortLenient(host + ":0")
			want := net.ParseIP(bareHost(bare))
			if want == nil {
				t.Fatalf("bareHost(%q) did not parse, yet net.Listen bound %v; the predicate is narrower than the kernel", bare, ln.Addr())
			}
			got := addrIP(ln.Addr())
			if !got.Equal(want) {
				t.Errorf("net.Listen(%q) bound %v, bareHost predicted %v; a predicate that disagrees with the kernel is how three relaxations end up on the wrong socket", host, got, want)
			}
			if !got.IsLoopback() {
				t.Errorf("net.Listen(%q) bound %v, which is not loopback", host, got)
			}
		})
	}
}

// TestLoopbackListen_RefusesAZoneOnAnIPv4Address is the regression test for the
// measured fail-open, and it must fail if anyone restores the unconditional
// zone strip.
//
// Before the fix: isLoopbackListen("127.0.0.1%evil:14443") was true, the socket
// bound 172.29.144.56, and the gateway started with no token, permitted
// loopback allowed_hosts entries and a disarmed dial guard.
func TestLoopbackListen_RefusesAZoneOnAnIPv4Address(t *testing.T) {
	t.Parallel()
	for _, host := range ipv4ZoneListens {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			listen := host + ":14443"

			if isLoopbackListen(listen) {
				t.Fatalf("isLoopbackListen(%q) = true; IPv4 has no zones, so net.Listen reads that string as a host NAME and resolves it through the hosts file and DNS -- what it binds is a resolver's answer, not proof of a loopback-only bind", listen)
			}

			// The advisory refusal, which is what an operator meets first.
			err := tokenlessValidate(listen)
			if err == nil {
				t.Fatalf("tokenless Validate(listen=%q) = nil; a bind whose address a resolver chooses must ask for a token", listen)
			}
			if !strings.Contains(err.Error(), "gateway_auth") {
				t.Errorf("error = %v, want it to name gateway_auth", err)
			}

			// The CONNECT allowlist relaxation stays shut too.
			if err := connectCfg(listen, "127.0.0.1:9200").Validate(); err == nil {
				t.Errorf("Validate(listen=%q, allowed=[127.0.0.1:9200]) = nil; nothing here proves that bind is loopback-only, so a local target may let a remote CONNECT holder launder itself into a loopback caller", listen)
			}
		})
	}
}

// TestLoopbackZoneHint_ExplainsTheSpellingItRefuses keeps the refusal
// actionable. An operator who wrote "127.0.0.1%eth0" wrote a real syntax; what
// they need told is that it is IPv6-only syntax, and that the string they wrote
// is therefore a name.
func TestLoopbackZoneHint_ExplainsTheSpellingItRefuses(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"127.0.0.1%evil", "127.0.0.1%lo", "127.1%evil"} {
		listen := host + ":14443"
		hint := loopbackZoneHint(listen)
		if hint == "" {
			t.Errorf("loopbackZoneHint(%q) is empty, want the zone hint", listen)
			continue
		}
		if !strings.Contains(hint, zoneHintFragment) {
			t.Errorf("hint = %q, want it to say why the zone is not applicable", hint)
		}
		if !strings.Contains(hint, "127.0.0.1") {
			t.Errorf("hint = %q, want it to name the spelling that works", hint)
		}
		if got := loopbackListenHint(listen); got != hint {
			t.Errorf("loopbackListenHint(%q) did not return the zone hint", listen)
		}
		if got := loopbackNameHint(listen); got != "" {
			t.Errorf("loopbackNameHint(%q) = %q, want empty: that refusal is about a zone, not a reserved name", listen, got)
		}
	}

	// And it stays off every refusal it does not explain -- including the
	// IPv6 zone that is legitimate, and a zone on an address that is not
	// loopback at all.
	for _, listen := range []string{
		"[::1%lo]:14443", "fe80::1%eth0:14443", "127.0.0.1:14443", "localhost:14443",
		"0.0.0.0:14443", "127.1:14443", "192.0.2.10%eth0:14443",
	} {
		if got := loopbackZoneHint(listen); got != "" {
			t.Errorf("loopbackZoneHint(%q) = %q, want empty", listen, got)
		}
	}
}

// TestLoadConfig_RefusesAZoneOnAnIPv4LoopbackBind is the same direction end to
// end through the file loader, because that is where an operator meets it.
func TestLoadConfig_RefusesAZoneOnAnIPv4LoopbackBind(t *testing.T) {
	t.Parallel()
	for _, host := range ipv4ZoneListens {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "gateway.yml")
			body := fmt.Sprintf("listen: %q\n"+
				"routes:\n"+
				"  - name: a\n"+
				"    prefix: /a/\n"+
				"    upstream: https://example.invalid\n"+
				"    auth: passthrough\n"+
				"    enabled: true\n", host+":14443")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			_, err := LoadConfig(path)
			if err == nil {
				t.Fatalf("LoadConfig accepted a tokenless bind spelled %q; net.Listen resolves that string, so trusting it waives the gateway token on whatever socket comes back", host)
			}
			if !strings.Contains(err.Error(), zoneHintFragment) {
				t.Errorf("LoadConfig error = %v, want it to explain the zone", err)
			}
		})
	}
}

// TestLoopbackListen_KeepsTheLegitimateIPv6Zone is the other direction, and it
// is the reason the fix is a family test rather than a ban on '%'. "[::1%lo]"
// is a real loopback bind, net.Listen binds ::1 for it, and it must stay
// tokenless.
func TestLoopbackListen_KeepsTheLegitimateIPv6Zone(t *testing.T) {
	t.Parallel()
	const listen = "[::1%lo]:14443"

	if !isLoopbackListen(listen) {
		t.Fatalf("isLoopbackListen(%q) = false; an IPv6 zone is legal syntax and net.Listen splits it off and binds ::1", listen)
	}
	if err := tokenlessValidate(listen); err != nil {
		t.Errorf("tokenless Validate(listen=%q) = %v, want nil", listen, err)
	}
	if got := loopbackListenHint(listen); got != "" {
		t.Errorf("loopbackListenHint(%q) = %q, want empty: there is nothing wrong with that spelling", listen, got)
	}
}

// TestBoundListenScope_ReadsTheSocketAndNothingElse states the authoritative
// rule on its own, including the one that is easy to get wrong: a wildcard bind
// is NOT loopback-only, because it accepts remote peers.
func TestBoundListenScope_ReadsTheSocketAndNothingElse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		addr net.Addr
		want listenScope
	}{
		{"v4 loopback", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 14443}, scopeLoopbackOnly},
		{"anywhere in 127/8", &net.TCPAddr{IP: net.ParseIP("127.0.0.53"), Port: 14443}, scopeLoopbackOnly},
		{"v6 loopback", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 14443}, scopeLoopbackOnly},
		{"v6 loopback with a zone", &net.TCPAddr{IP: net.ParseIP("::1"), Zone: "lo", Port: 14443}, scopeLoopbackOnly},
		{"v4 wildcard", &net.TCPAddr{IP: net.IPv4zero, Port: 14443}, scopeReachable},
		{"v6 wildcard", &net.TCPAddr{IP: net.IPv6unspecified, Port: 14443}, scopeReachable},
		{"a routable address", &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 14443}, scopeReachable},
		{"an address shape we cannot read", &net.UnixAddr{Name: "/run/gw.sock", Net: "unix"}, scopeReachable},
		{"no address at all", nil, scopeReachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := boundListenScope(tc.addr); got != tc.want {
				t.Errorf("boundListenScope(%v) = %v, want %v; undecidable is not loopback, and a wildcard socket accepts remote peers", tc.addr, got, tc.want)
			}
		})
	}
}

// TestServe_RefusesATokenlessWildcardBindWithoutServingARequest is the central
// test of the whole change, and it pins ORDER as well as outcome.
//
// The socket is a REAL wildcard bind. The config text predicts loopback and is
// wrong, which is the shape every round of this defect took. A client is
// already connected and its request already written before Serve is called, so
// it is sitting in the accept backlog: if Serve accepted before deciding, that
// is the request it would answer. It must never be answered, Accept must never
// be called, and the listener must be closed.
func TestServe_RefusesATokenlessWildcardBindWithoutServingARequest(t *testing.T) {
	raw, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen wildcard: %v", err)
	}
	defer func() { _ = raw.Close() }()
	ln := &stagedListener{Listener: raw, addr: raw.Addr()}

	port := raw.Addr().(*net.TCPAddr).Port
	client, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the bound socket: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := io.WriteString(client, "GET /healthz HTTP/1.1\r\nHost: gw\r\n\r\n"); err != nil {
		t.Fatalf("write the queued request: %v", err)
	}

	// The config PREDICTS loopback. The socket says otherwise, and the
	// socket is what decides.
	srv := tokenlessServer(t, "127.0.0.1:14443")
	serveErr := serveExpectingRefusal(t, srv, ln)
	if !strings.Contains(serveErr.Error(), "gateway_auth") {
		t.Errorf("Serve error = %v, want it to name gateway_auth", serveErr)
	}
	if !strings.Contains(serveErr.Error(), raw.Addr().String()) {
		t.Errorf("Serve error = %v, want it to name %s, the address actually bound; naming the config string instead is what made three rounds of this defect hard to see", serveErr, raw.Addr())
	}
	if n := ln.accepts.Load(); n != 0 {
		t.Errorf("Accept was called %d times before the refusal, want 0; not one request may be served between binding and refusing", n)
	}
	if !ln.closed.Load() {
		t.Error("the listener was not closed on refusal; a refused gateway must not leave a socket bound")
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	n, rerr := client.Read(buf)
	if rerr == nil && n > 0 {
		t.Fatalf("the queued request was answered with %q; the refusal must land before a single request is served", buf[:n])
	}
}

// TestServe_TheSocketOverridesAConfigStringThatPredictedLoopback stages the
// exact defect shape without needing a hosts file: a config that this package
// reads as loopback, on a socket that is not.
//
// It is the staged twin of the measured failure. "127.0.0.1%evil" resolved to
// 172.29.144.56; "0x7f000001" resolved to 10.255.255.254; "localhost" could
// resolve anywhere. All three are the same event as far as this test is
// concerned -- the string said loopback and the kernel said otherwise -- which
// is why the fix is not a fourth spelling.
func TestServe_TheSocketOverridesAConfigStringThatPredictedLoopback(t *testing.T) {
	ln := stagedOn(t, &net.TCPAddr{IP: net.ParseIP("172.29.144.56"), Port: 14443})
	srv := tokenlessServer(t, "127.0.0.1%evil:14443")

	// The advisory now refuses this too, so state that the socket-level
	// refusal does not depend on it: the same refusal must land for a
	// spelling the advisory accepts.
	staged := serveExpectingRefusal(t, srv, ln)
	if !strings.Contains(staged.Error(), "172.29.144.56:14443") {
		t.Errorf("Serve error = %v, want it to name the address actually bound; that is the address the measured attack put the socket on while the predicate still said loopback", staged)
	}
	if n := ln.accepts.Load(); n != 0 {
		t.Errorf("Accept was called %d times, want 0", n)
	}

	// The advisory-clean case: listen is a plain loopback literal, which
	// Validate accepts, and the socket is still routable.
	ln2 := stagedOn(t, &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 14443})
	srv2 := tokenlessServer(t, "127.0.0.1:14443")
	if err := srv2.cfg.Validate(); err != nil {
		t.Fatalf("Validate(listen=127.0.0.1:14443) = %v, want nil: the advisory has nothing to object to here, which is the point", err)
	}
	err := serveExpectingRefusal(t, srv2, ln2)
	if !strings.Contains(err.Error(), "10.0.0.5:14443") {
		t.Errorf("Serve error = %v, want it to name the address actually bound", err)
	}
	if n := ln2.accepts.Load(); n != 0 {
		t.Errorf("Accept was called %d times, want 0", n)
	}
}

// TestServe_ServesATokenlessConfigurationOnARealLoopbackSocket is the direction
// that must NOT regress: a genuine loopback bind stays tokenless, which is the
// historical default and every developer box.
//
// The config string here predicts the WRONG answer in the safe direction --
// "0.0.0.0:14443" -- so the test also shows the socket is what is read, not
// merely that a loopback config is accepted.
func TestServe_ServesATokenlessConfigurationOnARealLoopbackSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	srv := tokenlessServer(t, "0.0.0.0:14443")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	})

	url := "http://" + ln.Addr().String() + "/healthz"
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get(url) //nolint:noctx // a fixed loopback URL in a test
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s: %v; a genuine loopback bind must serve without a gateway token", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := srv.servingScope(httptest.NewRequest(http.MethodGet, "/a/x", nil)); got != scopeLoopbackOnly {
		t.Errorf("servingScope after adopting a loopback socket = %v, want %v", got, scopeLoopbackOnly)
	}
}

// TestServe_RefusesALoopbackAllowlistEntryOnANonLoopbackSocket covers the
// second relaxation on the same authority.
//
// Validate accepted this allowlist because the config text said the bind was
// loopback-only, where a tunnel to a local service grants a caller nothing it
// could not open itself. On a socket other hosts can reach, that reasoning is
// gone: the entry is the laundering path, and the gateway must say so at
// startup rather than at the first tunnelled request.
func TestServe_RefusesALoopbackAllowlistEntryOnANonLoopbackSocket(t *testing.T) {
	target := echoListener(t)
	t.Setenv("TEST_SELFREF_TOKEN", "connect-token")

	cfg := connectCfg("127.0.0.1:14443", target)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil: on a loopback-only bind this allowlist is the ordinary local deployment", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln := stagedOn(t, &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 45209})
	serveErr := serveExpectingRefusal(t, srv, ln)
	if !strings.Contains(serveErr.Error(), "allowed_hosts") {
		t.Errorf("Serve error = %v, want it to name allowed_hosts", serveErr)
	}
	if !strings.Contains(serveErr.Error(), "10.0.0.5:45209") {
		t.Errorf("Serve error = %v, want it to name the address actually bound", serveErr)
	}
	if n := ln.accepts.Load(); n != 0 {
		t.Errorf("Accept was called %d times before the refusal, want 0", n)
	}
}

// TestConnectDialRefusal_HangsOnTheScopeNotAConfigString covers the third
// relaxation. The guard takes a listenScope now; there is no string left for a
// spelling to fool.
func TestConnectDialRefusal_HangsOnTheScopeNotAConfigString(t *testing.T) {
	t.Parallel()
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51000}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9200}

	if got := connectDialRefusal(scopeLoopbackOnly, local, remote); got != "" {
		t.Errorf("connectDialRefusal(scopeLoopbackOnly) = %q, want empty: on a loopback-only socket every CONNECT client is already a local process", got)
	}
	if got := connectDialRefusal(scopeReachable, local, remote); got != "target_resolves_to_loopback" {
		t.Errorf("connectDialRefusal(scopeReachable) = %q, want target_resolves_to_loopback", got)
	}
	if got := connectDialRefusal(scopeUnknown, local, remote); got != "target_resolves_to_loopback" {
		t.Errorf("connectDialRefusal(scopeUnknown) = %q, want target_resolves_to_loopback: no socket has been adopted, and undecidable is not loopback", got)
	}
}

// TestServingScope_ReadsASocketAndNeverTheConfigString pins the request-path
// authority, including its fallback.
//
// The fallback matters because Handler is exported: an embedder can mount it on
// their own http.Server, and then nothing was adopted. It falls back to the
// address THIS connection was accepted on -- still a kernel-assigned socket
// address, just a narrower one -- and never to Config.Listen. A connection
// accepted on 127.0.0.1 has a peer on this machine by construction, so there is
// no remote caller to launder.
func TestServingScope_ReadsASocketAndNeverTheConfigString(t *testing.T) {
	t.Parallel()
	srv := tokenlessServer(t, "127.0.0.1:14443")
	base := httptest.NewRequest(http.MethodGet, "/a/x", nil)

	withLocal := func(a net.Addr) *http.Request {
		return base.WithContext(context.WithValue(base.Context(), http.LocalAddrContextKey, a))
	}

	if got := srv.servingScope(base); got != scopeReachable {
		t.Errorf("servingScope with no socket at all = %v, want %v; listen %q says loopback and it must count for nothing", got, scopeReachable, srv.cfg.Listen)
	}
	loop := withLocal(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 14443})
	if got := srv.servingScope(loop); got != scopeLoopbackOnly {
		t.Errorf("servingScope for a connection accepted on 127.0.0.1 = %v, want %v", got, scopeLoopbackOnly)
	}
	wild := withLocal(&net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 14443})
	if got := srv.servingScope(wild); got != scopeReachable {
		t.Errorf("servingScope for a connection accepted on 10.0.0.5 = %v, want %v", got, scopeReachable)
	}

	// An adopted socket outranks the connection: a wildcard listener is
	// judged reachable for every request on it, loopback ones included,
	// because the listener accepts remote peers.
	srv.scope.Store(uint32(scopeReachable))
	if got := srv.servingScope(loop); got != scopeReachable {
		t.Errorf("servingScope after adopting a reachable socket = %v, want %v; the adopted answer is the server's answer", got, scopeReachable)
	}
}
