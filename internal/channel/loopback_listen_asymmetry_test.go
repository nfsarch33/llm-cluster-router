package channel

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file pins an ASYMMETRY, and the asymmetry is deliberate.
//
// Two predicates in this package both say "loopback". They do not answer the
// same question, and an earlier attempt to give them one shared answer — on the
// theory that every spelling should be judged consistently across all three
// surfaces — opened a hole. Consistency of OUTCOME was the wrong goal.
// Soundness per question is the right one:
//
//   - localTargetKind decides a CONNECT TARGET. Our code is the only thing that
//     decides it, and deciding "loopback" REFUSES the entry. A generous reading
//     fails CLOSED, so it recognises inet_aton's whole grammar (127.1,
//     0x7f000001, 2130706433, 0177.0.0.1) and a blocklist of reserved names.
//   - isLoopbackListen predicts what a LISTEN address will bind. The OS resolver
//     decides that, not us, so the prediction can never be sound and NOTHING is
//     gated on it any more: it is an ADVISORY refusal that catches obvious
//     mistakes at LoadConfig, and the relaxations hang on the bound socket
//     instead (boundListenScope, and loopback_bind_authority_test.go). Because
//     it can now only refuse, it still trusts nothing but an address literal
//     net.ParseIP can read -- a generous reading here would let an obvious
//     mistake through to the socket for no gain.
//
// Both excluded classes were measured, not theorised. With listen
// "0x7f000001:45425" trusted as loopback, the socket actually bound
// 10.255.255.254:45425 — the hosts file decided it — tokenless startup was
// accepted, an anonymous caller got 200, and the upstream saw the route key. The
// same attack spelled "localhost" was already refused. That side by side is the
// whole argument: a resolver's answer must never be what switches the gateway's
// posture off.

// inetAtonLoopbackHosts are the numeric spellings that mean 127.0.0.1 to a C
// resolver. Every one of them must be recognised as a CONNECT target and
// refused as proof of a loopback bind.
var inetAtonLoopbackHosts = []string{
	"127.1", "127.0.1", "2130706433", "0x7f000001", "0177.0.0.1", "017700000001",
}

// Fragments of the two refusal messages, so a test fails on the sentence being
// gone rather than on it being reworded.
const (
	nameHintFragment    = "NAMES loopback but does not spell it"
	numericHintFragment = "is an inet_aton spelling of 127.0.0.1"
)

// dialGuardArmed reports whether the dial-time CONNECT guard would refuse a
// loopback peer on a gateway carrying this listen string that has adopted no
// socket and is answering a request that carries no connection address.
//
// It must answer TRUE for every string now, loopback literals included, and
// that is the fix rather than an oversight: the guard moved off the config text
// and onto the bound socket, so no spelling can disarm it any more. What does
// disarm it is a loopback SOCKET, pinned in loopback_bind_authority_test.go.
func dialGuardArmed(listen string) bool {
	srv := &Server{cfg: &Config{Listen: listen}}
	req := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:9200", nil)
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 14443}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9200}
	return connectDialRefusal(srv.servingScope(req), local, remote) != ""
}

// tokenlessValidate runs Validate on a config whose only interesting property
// is its bind: no gateway token, so the gateway_auth rule decides it.
func tokenlessValidate(listen string) error {
	cfg := &Config{
		Listen: listen,
		Routes: []Route{{
			Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
			Auth: AuthPassthrough, Enabled: true,
		}},
	}
	return cfg.Validate()
}

// TestLoopbackListen_TrustsOnlyAnAddressLiteral is the table the asymmetry
// lives in. Each row states both answers, and the rows where they differ are
// the point of the file rather than an inconsistency in it.
func TestLoopbackListen_TrustsOnlyAnAddressLiteral(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		host string
		// listenLoopback is what isLoopbackListen must answer: true only
		// where this package decides the bind without a resolver.
		listenLoopback bool
		// targetLocal is whether the SAME spelling, read as a CONNECT
		// target, is recognised as this machine.
		targetLocal bool
	}{
		// Literals. We decide them, net.Listen decides them the same way,
		// and no resolver is consulted by either: one answer, soundly.
		{"dotted quad", "127.0.0.1", true, true},
		{"anywhere in 127/8", "127.0.0.53", true, true},
		{"IPv6 loopback", "[::1]", true, true},
		{"IPv4-mapped IPv6 loopback", "[::ffff:127.0.0.1]", true, true},
		{"IPv6 loopback with a zone", "[::1%lo]", true, true},

		// inet_aton spellings. Recognised as a target, where recognising
		// them refuses an entry; refused as a bind, where net.Listen would
		// hand the string to the resolver and the answer would relax three
		// defences.
		{"inet_aton two parts", "127.1", false, true},
		{"inet_aton three parts", "127.0.1", false, true},
		{"hex", "0x7f000001", false, true},
		{"decimal", "2130706433", false, true},
		{"octal", "0177.0.0.1", false, true},
		{"octal, one part", "017700000001", false, true},

		// Names. Same asymmetry, same reason.
		{"localhost", "localhost", false, true},
		{"localhost.localdomain", "localhost.localdomain", false, true},
		{"a name under .localhost", "gw.localhost", false, true},

		// Local but never loopback-ONLY: these bind everything.
		{"wildcard v4", "0.0.0.0", false, true},
		{"wildcard v6", "[::]", false, true},
		{"empty host", "", false, true},

		// Neither, either way.
		{"routable literal", "192.0.2.10", false, false},
		{"an ordinary hostname", "gateway.internal", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			listen := tc.host + ":14443"

			// 1. the prediction itself.
			if got := isLoopbackListen(listen); got != tc.listenLoopback {
				t.Errorf("isLoopbackListen(%q) = %v, want %v; a bind is loopback here only when an address literal says so, because everything else lets a resolver decide whether three defences stay on", listen, got, tc.listenLoopback)
			}

			// 2. the target-side answer, which is a different question
			// and may legitimately differ.
			if got := localTargetKind(tc.host) != ""; got != tc.targetLocal {
				t.Errorf("localTargetKind(%q) local = %v, want %v", tc.host, got, tc.targetLocal)
			}

			// 3. the CONNECT rule in the validator, which relaxes on the
			// bind answer: a loopback target on a port that is not the
			// gateway's own is legitimate on a loopback-only bind and an
			// escalation on any other.
			err := connectCfg(listen, "127.0.0.1:9200").Validate()
			if tc.listenLoopback && err != nil {
				t.Errorf("Validate(listen=%q, allowed=[127.0.0.1:9200]) = %v, want nil: that bind IS decidably loopback-only, so a loopback target on another port is the ordinary local deployment", listen, err)
			}
			if !tc.listenLoopback && err == nil {
				t.Errorf("Validate(listen=%q, allowed=[127.0.0.1:9200]) = nil, want a refusal: nothing here proves that bind is loopback-only, so a local target may let a remote CONNECT holder launder itself into a loopback caller", listen)
			}

			// 4. the dial-time guard, which this string has no say over
			// any more. It is armed on EVERY row, the loopback literals
			// included, because no socket has been adopted -- and that
			// column no longer tracking column 1 is the whole of the
			// class fix.
			if !dialGuardArmed(listen) {
				t.Errorf("the dial-time guard is disarmed for listen %q with no socket adopted; it must hang on a bound socket and never on the config text", listen)
			}

			// 5. the gateway_auth rule, the third thing the bind answer
			// relaxes: a tokenless bind we cannot decide must not start.
			gwErr := tokenlessValidate(listen)
			if tc.listenLoopback && gwErr != nil {
				t.Errorf("tokenless Validate(listen=%q) = %v, want nil", listen, gwErr)
			}
			if !tc.listenLoopback && gwErr == nil {
				t.Errorf("tokenless Validate(listen=%q) = nil, want a refusal naming gateway_auth", listen)
			}
		})
	}
}

// TestLoopbackListen_InetAtonSpellingsAreNotProofOfALoopbackBind is the
// regression test for the fail-open direction, and it must fail if anyone
// reintroduces the generous parse.
//
// net.Listen does NOT parse "127.1" or "0x7f000001" as address literals. It
// hands them to the platform resolver, so the hosts file and DNS choose what
// gets bound — measured as a real socket on 10.255.255.254 while the predicate
// said loopback, with a tokenless config accepted, an anonymous caller served
// 200 and the upstream key spent. "0x7f000001" was additionally observed
// reaching DNS. All three relaxations must therefore stay armed on every one of
// these spellings.
func TestLoopbackListen_InetAtonSpellingsAreNotProofOfALoopbackBind(t *testing.T) {
	t.Parallel()
	for _, host := range inetAtonLoopbackHosts {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			listen := host + ":14443"

			if isLoopbackListen(listen) {
				t.Fatalf("isLoopbackListen(%q) = true; net.Listen resolves that string through the hosts file and DNS instead of parsing it, so it is a resolver's answer and not proof of a loopback-only bind", listen)
			}

			// Relaxation one: the gateway token stays required, and the
			// refusal explains the spelling rather than merely refusing.
			err := tokenlessValidate(listen)
			if err == nil {
				t.Fatalf("tokenless Validate(listen=%q) = nil; a bind whose address a resolver chooses must ask for a token", listen)
			}
			if !strings.Contains(err.Error(), "gateway_auth") {
				t.Errorf("error = %v, want it to name gateway_auth", err)
			}
			if !strings.Contains(err.Error(), numericHintFragment) {
				t.Errorf("error = %v, want the sentence naming the spelling; an operator who wrote an address that IS 127.0.0.1 to their resolver needs to be told why it was not taken as one", err)
			}
			if !strings.Contains(err.Error(), "Write the address in full") {
				t.Errorf("error = %v, want it to name the fix", err)
			}

			// Relaxation two: loopback allowed_hosts entries stay refused.
			why := connectSelfReference("127.0.0.1", "9200", listen, isLoopbackListen(listen))
			if why == "" {
				t.Errorf("connectSelfReference(127.0.0.1, 9200, listen=%q) is empty; the config-time CONNECT layer is disarmed by a numeric-spelled bind", listen)
			}
			if !strings.Contains(why, numericHintFragment) {
				t.Errorf("refusal = %q, want the spelling hint here too", why)
			}

			// Relaxation three: the dial-time guard stays armed. Nothing
			// in a config string can disarm it now, which is why a hosts
			// file pointing that spelling at a routable address cannot
			// switch off the dial-time layer either.
			if !dialGuardArmed(listen) {
				t.Errorf("the dial-time guard is disarmed on listen %q with no socket adopted", listen)
			}
		})
	}
}

// TestLoadConfig_RefusesALoopbackBindWrittenInAnInetAtonSpelling is the same
// direction end to end through the file loader, because that is where an
// operator meets it.
//
// The refusal is not merely defensible, it is also the only useful outcome in a
// shipped artifact: every container image here builds with CGO_ENABLED=0, which
// forces the pure-Go resolver, and that resolver cannot bind any of these
// spellings at all. Accepting them would trade a legible config-time error for
// an obscure runtime bind failure.
func TestLoadConfig_RefusesALoopbackBindWrittenInAnInetAtonSpelling(t *testing.T) {
	t.Parallel()
	for _, host := range inetAtonLoopbackHosts {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "gateway.yml")
			body := fmt.Sprintf("listen: %q\n"+
				"connect:\n"+
				"  enabled: true\n"+
				"  token_env: TEST_LOOPBACK_SPELLING_TOKEN # gitleaks:allow — env NAME, not a secret\n"+
				"  allowed_hosts:\n"+
				"    - \"127.0.0.1:9200\"\n"+
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
				t.Fatalf("LoadConfig accepted a tokenless bind spelled %q; what that string binds is a resolver's answer, and trusting it waives the gateway token on whatever socket comes back", host)
			}
			if !strings.Contains(err.Error(), numericHintFragment) {
				t.Errorf("LoadConfig error = %v, want it to explain the spelling", err)
			}
		})
	}
}

// TestLoopbackListen_RefusesToTrustANameAsProofOfALoopbackBind pins the same
// direction for names, which is a behaviour change.
//
// "localhost" included: every use of the bind answer RELAXES something, so
// trusting a spelling fails open, and the only way to decide a name is to
// resolve it, which would make startup depend on whoever answers the resolver.
// The blocklist keeps its other job, where the same answer fails closed: as a
// CONNECT TARGET a reserved name is still local.
func TestLoopbackListen_RefusesToTrustANameAsProofOfALoopbackBind(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{"localhost:14443", "localhost.localdomain:14443", "ip6-localhost:14443", "gw.localhost:14443"} {
		t.Run(listen, func(t *testing.T) {
			t.Parallel()

			if isLoopbackListen(listen) {
				t.Fatalf("isLoopbackListen(%q) = true; a name is not proof of a loopback-only bind", listen)
			}

			// Layer one stays armed.
			why := connectSelfReference("127.0.0.1", "9200", listen, isLoopbackListen(listen))
			if why == "" {
				t.Errorf("connectSelfReference(127.0.0.1, 9200, listen=%q) is empty; the config-time layer is disarmed by a name-spelled bind", listen)
			}
			if !strings.Contains(why, nameHintFragment) {
				t.Errorf("refusal = %q, want it to tell the operator to write the address", why)
			}

			// Layer two stays armed, and no config string can change
			// that: a hosts file pointing that name at a routable address
			// cannot switch off the dial-time layer.
			if !dialGuardArmed(listen) {
				t.Errorf("the dial-time guard is disarmed on listen %q with no socket adopted", listen)
			}

			// And the gateway leg asks for a token, actionably.
			err := tokenlessValidate(listen)
			if err == nil {
				t.Fatalf("tokenless Validate(listen=%q) = nil; a bind this code cannot decide must ask for a token", listen)
			}
			if !strings.Contains(err.Error(), "gateway_auth") {
				t.Errorf("error = %v, want it to name gateway_auth", err)
			}
			if !strings.Contains(err.Error(), nameHintFragment) {
				t.Errorf("error = %v, want the hint that says which word to change; a startup refusal on a fresh host is only useful if it does", err)
			}
			if !strings.Contains(err.Error(), "127.0.0.1") {
				t.Errorf("error = %v, want it to name the spelling that works", err)
			}
		})
	}
}

// TestLoopbackListen_TheTwoWaysOutOfTheRefusalWork keeps the behaviour change
// survivable: an operator who wrote a name or a numeric spelling has exactly
// two fixes, and both are in the message.
func TestLoopbackListen_TheTwoWaysOutOfTheRefusalWork(t *testing.T) {
	t.Parallel()

	t.Run("spell the address", func(t *testing.T) {
		t.Parallel()
		for _, listen := range []string{"127.0.0.1:14443", "[::1]:14443"} {
			if err := tokenlessValidate(listen); err != nil {
				t.Errorf("Validate(listen=%q) = %v, want nil", listen, err)
			}
		}
	})

	t.Run("configure a token", func(t *testing.T) {
		t.Parallel()
		for _, listen := range []string{"localhost:14443", "127.1:14443", "0x7f000001:14443"} {
			cfg := &Config{
				Listen: listen,
				Routes: []Route{{
					Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
					Auth: AuthPassthrough, Enabled: true,
				}},
				GatewayAuth: GatewayAuthConfig{TokenEnv: "GW"},
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate(listen=%q) = %v, want nil: an undecidable bind with a token is authenticated whatever it resolves to", listen, err)
			}
		}
	})
}

// TestLoopbackListenHint_FiresOnlyOnTheSpellingItExplains keeps each sentence
// off the refusals it does not explain. Appending a spelling hint to a wildcard
// bind's error would send the operator hunting a problem that is not there, and
// telling someone who wrote 127.1 to "write the address" when they think they
// did is worse than saying nothing.
func TestLoopbackListenHint_FiresOnlyOnTheSpellingItExplains(t *testing.T) {
	t.Parallel()

	for _, listen := range []string{"localhost:14443", "ip6-loopback:14443", "x.localhost:14443"} {
		if got := loopbackNameHint(listen); got == "" {
			t.Errorf("loopbackNameHint(%q) is empty, want the name hint", listen)
		}
		if got := loopbackNumericHint(listen); got != "" {
			t.Errorf("loopbackNumericHint(%q) = %q, want empty: that bind is a name, not a numeric spelling", listen, got)
		}
	}

	for _, host := range inetAtonLoopbackHosts {
		listen := host + ":14443"
		if got := loopbackNumericHint(listen); got == "" {
			t.Errorf("loopbackNumericHint(%q) is empty, want the numeric hint", listen)
		}
		if got := loopbackNameHint(listen); got != "" {
			t.Errorf("loopbackNameHint(%q) = %q, want empty: that bind is a numeric spelling, not a name", listen, got)
		}
		if got := loopbackListenHint(listen); got != loopbackNumericHint(listen) {
			t.Errorf("loopbackListenHint(%q) did not return the numeric hint", listen)
		}
	}

	// Nothing about a spelling: a wildcard, an empty host, an ordinary
	// hostname, a routable literal, a working loopback literal, and a
	// numeric spelling that is not loopback at all.
	for _, listen := range []string{
		"0.0.0.0:14443", ":14443", "192.0.2.10:14443", "127.0.0.1:14443",
		"[::1]:14443", "gateway.internal:14443", "0xc0000210:14443",
	} {
		if got := loopbackListenHint(listen); got != "" {
			t.Errorf("loopbackListenHint(%q) = %q, want empty: that refusal is not about a loopback spelling", listen, got)
		}
	}
}

// TestReservedLoopbackNames_StillDecideACONNECTTarget guards the half of the
// blocklist that is kept. The same answer that is refused as proof of a
// loopback BIND is still sufficient to refuse an allowlist ENTRY, because there
// it fails closed.
func TestReservedLoopbackNames_StillDecideACONNECTTarget(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{"localhost:9200", "localhost.localdomain:9200", "ip6-localhost:9200", "svc.localhost:9200"} {
		t.Run(entry, func(t *testing.T) {
			t.Parallel()
			err := connectCfg(selfRefListen, entry).Validate()
			if err == nil {
				t.Fatalf("Validate accepted %q on a wildcard bind; a reserved loopback name is still this machine", entry)
			}
			if !strings.Contains(err.Error(), "a reserved loopback name") {
				t.Errorf("error = %v, want it to say the entry is a reserved loopback name", err)
			}
		})
	}
}

// TestInetAtonSpellings_StillDecideACONNECTTarget is the other side of the
// asymmetry, stated where it is easy to break by "simplifying" the two
// predicates back into one: tightening the LISTEN predicate must not tighten
// the TARGET one, which is generous on purpose because there it fails closed.
func TestInetAtonSpellings_StillDecideACONNECTTarget(t *testing.T) {
	t.Parallel()
	for _, host := range inetAtonLoopbackHosts {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			err := connectCfg(selfRefListen, host+":9200").Validate()
			if err == nil {
				t.Fatalf("Validate accepted %q on a wildcard bind; that spelling is 127.0.0.1 to any C resolver, and refusing it costs nothing", host)
			}
			if !strings.Contains(err.Error(), "alternative numeric form") {
				t.Errorf("error = %v, want it to say the entry is a loopback address in an alternative numeric form", err)
			}
		})
	}
}
