package channel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The escalation these tests pin, in the order the layers stand:
//
// handleConnect dials an allowlisted target verbatim. If that target is the
// gateway's own address, the tunnelled request comes back on the loopback
// interface, isLoopbackPeer correctly calls it local, and gateway_auth's
// token_loopback_exempt posture serves it WITHOUT a gateway token. A remote
// holder of the CONNECT token — a credential whose whole point is that it is
// bounded by allowed_hosts — thereby acquires the power to spend every key on
// every enabled route. It was reproduced over a real socket at
// listen 0.0.0.0:P with allowed_hosts [127.0.0.1:P].
//
// Layer one refuses the configuration. Layer two refuses the dial.

// selfRefListen is a non-loopback bind: the posture under which a local CONNECT
// target is an escalation rather than a local process talking to itself.
const selfRefListen = "0.0.0.0:45209"

// connectCfg builds a connect-only config. It does NOT call Validate: each test
// says which layer it is exercising.
func connectCfg(listen string, hosts ...string) *Config {
	return &Config{
		Listen: listen,
		Connect: ConnectConfig{
			Enabled: true, TokenEnv: "TEST_SELFREF_TOKEN",
			AllowedHosts: hosts, DialTimeout: 5 * time.Second,
		},
		// Not the subject here: without it, every non-loopback bind below
		// would fail on the gateway_auth rule instead of the connect one.
		GatewayAuth: GatewayAuthConfig{AllowUnauthenticated: true},
	}
}

// TestLoadConfig_RejectsTheMeasuredSelfAllowlistEscalation reproduces the
// measured configuration exactly and requires it to die at LoadConfig — the
// moment an operator can still see the message — rather than at the first
// tunnelled request, which nobody watches.
func TestLoadConfig_RejectsTheMeasuredSelfAllowlistEscalation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yml")
	body := fmt.Sprintf(`listen: %q
gateway_auth:
  token_env: TEST_SELFREF_GW # gitleaks:allow — env NAME, not a secret
connect:
  enabled: true
  token_env: TEST_SELFREF_TOKEN # gitleaks:allow — env NAME, not a secret
  allowed_hosts:
    - 127.0.0.1:45209
`, selfRefListen)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted a gateway that allowlists its own address; that configuration launders a remote CONNECT caller into a loopback one")
	}
	for _, want := range []string{"allowed_hosts", "127.0.0.1:45209", "loopback", "dial itself"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("LoadConfig error = %q, want it to contain %q so an operator can see WHICH entry and WHY", err, want)
		}
	}
}

// TestValidateConnect_RejectsLocalTargetsOnANonLoopbackBind walks the spellings
// an attacker reaches for after the obvious one fails. Every case names the
// same machine; only the notation differs.
func TestValidateConnect_RejectsLocalTargetsOnANonLoopbackBind(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"dotted quad":                   "127.0.0.1:45209",
		"a different loopback host":     "127.0.0.2:45209",
		"loopback on another port":      "127.0.0.1:8080",
		"short form":                    "127.1:45209",
		"three part form":               "127.0.1:45209",
		"hex":                           "0x7f000001:45209",
		"decimal integer":               "2130706433:45209",
		"octal":                         "0177.0.0.1:45209",
		"single octal integer":          "017700000001:45209",
		"ipv6 loopback":                 "[::1]:45209",
		"ipv4 mapped ipv6 loopback":     "[::ffff:127.0.0.1]:45209",
		"ipv6 loopback with a zone":     "[::1%lo]:45209",
		"unspecified v4":                "0.0.0.0:45209",
		"unspecified v6":                "[::]:45209",
		"unspecified short form":        "0:45209",
		"empty host":                    ":45209",
		"localhost":                     "localhost:45209",
		"localhost cased":               "LocalHost:45209",
		"localhost fully qualified":     "localhost.:45209",
		"localhost.localdomain":         "localhost.localdomain:45209",
		"ip6-localhost":                 "ip6-localhost:45209",
		"ip6-loopback":                  "ip6-loopback:45209",
		"a name under .localhost":       "gateway.localhost:45209",
		"a cased name under .LOCALHOST": "Gateway.LOCALHOST:45209",
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := connectCfg(selfRefListen, entry)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted allowed_hosts %q on listen %q; it names the local machine", entry, selfRefListen)
			}
			if !strings.Contains(err.Error(), entry) {
				t.Errorf("Validate error = %q, want it to name the offending entry %q", err, entry)
			}
		})
	}
}

// TestValidateConnect_AcceptsGenuinelyRemoteTargets is the other half of the
// bargain: a check that refuses the shipped configuration is not a fix, it is
// an outage. These are the entries deploy/helixchannel/gateway.example.yml
// actually carries, plus the awkward ones nearby.
func TestValidateConnect_AcceptsGenuinelyRemoteTargets(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"provider host":                            "api.anthropic.com:443",
		"second provider host":                     "statsig.anthropic.com:443",
		"third provider host":                      "api.minimaxi.com:443",
		"a routable literal":                       "203.0.113.7:443",
		"a routable v6 literal":                    "[2001:db8::1]:443",
		"a private literal":                        "10.0.0.5:443",
		"a name that merely starts with localhost": "localhost-shard.example:443",
		"a name that merely contains localhost":    "not-localhost.example:443",
		"a numeric-looking name":                   "3.4.5.6:443",
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := connectCfg(selfRefListen, entry)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate rejected a legitimate remote target %q: %v", entry, err)
			}
		})
	}
}

// TestValidateConnect_DocumentsWhatItCannotDecide is not an endorsement. Both
// entries below are accepted, and both COULD be this machine:
//
//   - a routable literal on the gateway's own port, under a wildcard bind that
//     owns that port on every interface. Deciding it means enumerating the
//     host's addresses at validation time, which is stale the moment one is
//     added and would reject a legitimate neighbour on the same port.
//   - any NAME at all, whose A record this code refuses to look up.
//
// They are accepted HERE and refused at dial time by connectDialRefusal. This
// test exists so that if someone later makes the validator "complete", they
// have to come and delete a test that says why it is not.
func TestValidateConnect_DocumentsWhatItCannotDecide(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{"203.0.113.7:45209", "gateway-alias.example:45209"} {
		t.Run(entry, func(t *testing.T) {
			t.Parallel()
			cfg := connectCfg(selfRefListen, entry)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate rejected %q: this entry is UNDECIDABLE from config text, and the dial-time guard is what covers it. If this now fails because the validator got stricter, check that it did not also start rejecting legitimate neighbours: %v", entry, err)
			}
		})
	}
}

// TestValidateConnect_LoopbackBindStillAllowsLoopbackTargets guards the
// carve-out. On a loopback-only bind every CONNECT client is already a local
// process, so a tunnel to a local service grants it nothing it could not open
// directly — and refusing it would break the shipped end-to-end tunnel test and
// every developer running the gateway on their own box. What stays refused is
// the gateway dialling its OWN socket.
func TestValidateConnect_LoopbackBindStillAllowsLoopbackTargets(t *testing.T) {
	t.Parallel()
	ok := map[string]*Config{
		"an ephemeral local target, as the end-to-end tunnel test configures it": connectCfg("127.0.0.1:0", "127.0.0.1:41235"),
		"a local service on another port":                                        connectCfg("127.0.0.1:14443", "127.0.0.1:9200"),
		"localhost by name on another port":                                      connectCfg("localhost:14443", "localhost:9200"),
	}
	for name, cfg := range ok {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate rejected a legitimate loopback deployment: %v", err)
			}
		})
	}

	loops := map[string]*Config{
		"the gateway's own socket":              connectCfg("127.0.0.1:14443", "127.0.0.1:14443"),
		"the gateway's own socket, named":       connectCfg("127.0.0.1:14443", "localhost:14443"),
		"the gateway's own socket, hex spelled": connectCfg("127.0.0.1:14443", "0x7f000001:14443"),
	}
	for name, cfg := range loops {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate accepted an allowlist entry naming the gateway's own listen socket")
			}
			if !strings.Contains(err.Error(), "own listen port") {
				t.Errorf("Validate error = %q, want it to say the entry is the gateway's own listen port", err)
			}
		})
	}
}

// TestValidateConnect_RejectsTheGatewaysOwnRoutableAddress covers the form that
// needs no loopback at all: the operator writes the bind address into the
// allowlist. 10.0.0.5 is this machine when the gateway is bound to it, on every
// port, not only its own.
func TestValidateConnect_RejectsTheGatewaysOwnRoutableAddress(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{"10.0.0.5:14443", "10.0.0.5:8080", "0x0a000005:8080"} {
		t.Run(entry, func(t *testing.T) {
			t.Parallel()
			cfg := connectCfg("10.0.0.5:14443", entry)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %q while bound to 10.0.0.5:14443; that address IS this machine", entry)
			}
			if !strings.Contains(err.Error(), "own listen address") {
				t.Errorf("Validate error = %q, want it to name the gateway's own listen address", err)
			}
		})
	}
}

// TestValidateConnect_StillRequiresHostPort keeps the pre-existing shape check
// working now that the entry is split rather than scanned for a colon.
func TestValidateConnect_StillRequiresHostPort(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{"api.anthropic.com", "a:b:c", ""} {
		t.Run(fmt.Sprintf("%q", entry), func(t *testing.T) {
			t.Parallel()
			cfg := connectCfg(selfRefListen, entry)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted malformed allowed_hosts entry %q", entry)
			}
			if !strings.Contains(err.Error(), "must be host:port") {
				t.Errorf("Validate error = %q, want the host:port shape complaint", err)
			}
		})
	}
}

// TestParseIPv4Numeric pins the decision procedure the alternative spellings
// rest on. A blocklist of literals would pass the first two rows and fail the
// rest; this is why the check parses instead of matching.
func TestParseIPv4Numeric(t *testing.T) {
	t.Parallel()
	loopback := []string{"127.1", "127.0.1", "0x7f000001", "0X7F000001", "2130706433", "0177.0.0.1", "017700000001", "127.0x1"}
	for _, in := range loopback {
		ip, ok := parseIPv4Numeric(in)
		if !ok || !ip.IsLoopback() {
			t.Errorf("parseIPv4Numeric(%q) = %v, %v; want a loopback address", in, ip, ok)
		}
	}
	unspecified := []string{"0", "0x0", "0.0", "00"}
	for _, in := range unspecified {
		ip, ok := parseIPv4Numeric(in)
		if !ok || !ip.IsUnspecified() {
			t.Errorf("parseIPv4Numeric(%q) = %v, %v; want the unspecified address", in, ip, ok)
		}
	}
	notLocal := []string{"3232235777", "10.0.0.5", "0x0a000005"}
	for _, in := range notLocal {
		ip, ok := parseIPv4Numeric(in)
		if !ok {
			t.Errorf("parseIPv4Numeric(%q) failed to parse a valid numeric address", in)
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() {
			t.Errorf("parseIPv4Numeric(%q) = %v; want a routable address", in, ip)
		}
	}
	notNumeric := []string{"api.anthropic.com", "", "1.2.3.4.5", "0x", "127.0.0.256", "4294967296", "127.-1", "example.invalid", "08"}
	for _, in := range notNumeric {
		if ip, ok := parseIPv4Numeric(in); ok {
			t.Errorf("parseIPv4Numeric(%q) = %v, true; want it refused as a non-address", in, ip)
		}
	}
}

// TestConnectDialRefusal states the second layer's rule directly, including the
// branch a CI box cannot stage: a peer whose address equals our own end of the
// socket is this machine, which is what a self-dial to a routable local address
// looks like.
func TestConnectDialRefusal(t *testing.T) {
	t.Parallel()
	tcp := func(s string, port int) net.Addr { return &net.TCPAddr{IP: net.ParseIP(s), Port: port} }
	cases := []struct {
		name, listen  string
		local, remote net.Addr
		want          string
	}{
		{"loopback peer on a wildcard bind", "0.0.0.0:45209", tcp("127.0.0.1", 51000), tcp("127.0.0.1", 45209), "target_resolves_to_loopback"},
		{"v6 loopback peer", "0.0.0.0:45209", tcp("::1", 51000), tcp("::1", 45209), "target_resolves_to_loopback"},
		{"our own routable address", "0.0.0.0:45209", tcp("10.0.0.5", 51000), tcp("10.0.0.5", 45209), "target_resolves_to_gateway_host"},
		{"a genuine remote peer", "0.0.0.0:45209", tcp("10.0.0.5", 51000), tcp("203.0.113.7", 443), ""},
		{"loopback peer but a loopback bind", "127.0.0.1:45209", tcp("127.0.0.1", 51000), tcp("127.0.0.1", 9200), ""},
		{"an unknown peer address", "0.0.0.0:45209", tcp("10.0.0.5", 51000), nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := connectDialRefusal(tc.listen, tc.local, tc.remote); got != tc.want {
				t.Errorf("connectDialRefusal(%q) = %q, want %q", tc.listen, got, tc.want)
			}
		})
	}
}

// TestConnect_DialTimeGuardRefusesATargetThatResolvedToLoopback proves the
// second layer stands on its own.
//
// The configuration below is exactly the one LoadConfig now refuses, built in
// memory so that Validate is bypassed — which is also how the gap the validator
// cannot close reaches this code in production: an allowlisted NAME whose A
// record is 127.0.0.1 is undecidable from config text and arrives here looking
// like any other target.
//
// The recorder deliberately does not implement http.Hijacker, so the two
// outcomes are distinguishable at a glance: 403 means the guard fired before
// the tunnel; 500 hijack_unsupported means the dial was accepted and it did
// not.
func TestConnect_DialTimeGuardRefusesATargetThatResolvedToLoopback(t *testing.T) {
	target := echoListener(t)

	t.Setenv("TEST_SELFREF_TOKEN", "connect-token")
	cfg := connectCfg(selfRefListen, target)
	var audit bytes.Buffer
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(&audit))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := connectThrough(srv, target, "203.0.113.9:51000")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("CONNECT to a loopback target returned %d, want %d; the gateway must not tunnel into itself", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(audit.String(), "target_resolves_to_loopback") {
		t.Errorf("audit stream = %s, want a connect_denied line naming the self-dial", audit.String())
	}
}

// TestConnect_DialTimeGuardIsOffForALoopbackBind keeps the guard from becoming
// an outage on the one deployment shape it must not touch: a gateway bound to
// loopback tunnelling to a local service, which is what TestConnectTunnel_
// EndToEnd exercises and what a developer box runs.
func TestConnect_DialTimeGuardIsOffForALoopbackBind(t *testing.T) {
	target := echoListener(t)

	t.Setenv("TEST_SELFREF_TOKEN", "connect-token")
	cfg := connectCfg("127.0.0.1:0", target)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), NewAuditor(io.Discard))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// The recorder cannot be hijacked, so the tunnel cannot complete here; what
	// matters is that the request got PAST the allowlist and the dial guard.
	rec := connectThrough(srv, target, "127.0.0.1:51000")
	if rec.Code == http.StatusForbidden {
		t.Fatal("CONNECT to a local service from a loopback-bound gateway was refused 403; the guard must not fire on this shape")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (hijack unsupported, i.e. the dial was accepted)", rec.Code, http.StatusInternalServerError)
	}
}

// echoListener starts a loopback echo server and returns its host:port.
func echoListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// connectThrough drives one authorised CONNECT at the handler.
func connectThrough(srv *Server, target, peer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodConnect, "http://"+target, nil)
	req.Host = target
	req.RemoteAddr = peer
	req.Header.Set("Proxy-Authorization", "Bearer connect-token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}
