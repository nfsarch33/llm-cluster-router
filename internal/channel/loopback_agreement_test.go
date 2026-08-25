package channel

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two definitions of "loopback" used to live in this package. localTargetKind
// (connect_target.go) decided the CONNECT target with net.ParseIP plus
// inet_aton's grammar plus a blocklist of reserved names; isLoopbackListen
// (config.go) decided the BIND with net.ParseIP plus the literal string
// "localhost". They disagreed in both directions, and both directions had
// consequences:
//
//	isLoopbackListen("127.1:14443")      = false, but 127.1 IS loopback
//	isLoopbackListen("0x7f000001:14443") = false, likewise
//	isLoopbackListen("localhost:14443")  = true, on SPELLING alone
//
// The numeric disagreement failed closed and was an availability bug: a real
// loopback-only deployment that wrote its bind as 127.1 had its own legitimate
// loopback allowed_hosts entries refused at startup, which on a fresh host
// reads as an inexplicable refusal to boot.
//
// The name disagreement failed open: a bind spelled "localhost" was trusted as
// loopback-only, which waives the gateway-token requirement AND disarms both
// CONNECT defence layers. A host whose /etc/hosts pointed localhost at a
// routable address switched all three off silently.
//
// There is now one procedure. These tests pin that all three consumers — the
// config validator, the dial-time guard and the listen predicate — read it the
// same way, and pin the deliberate choice made about names.

// dialGuardArmed reports whether connectDialRefusal would refuse a loopback
// peer on this bind. It is the runtime half of the same question the validator
// answers from config text.
func dialGuardArmed(listen string) bool {
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 14443}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9200}
	return connectDialRefusal(listen, local, remote) != ""
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

// TestLoopbackDefinition_IsOneAnswerEverywhere is the table the fix exists for.
// Every spelling below is judged by all three consumers, and a row that
// disagrees with itself fails naming which consumer drifted.
func TestLoopbackDefinition_IsOneAnswerEverywhere(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		listen   string
		loopback bool
	}{
		{"dotted quad", "127.0.0.1:14443", true},
		{"anywhere in 127/8", "127.0.0.53:14443", true},
		{"inet_aton two parts", "127.1:14443", true},
		{"inet_aton three parts", "127.0.1:14443", true},
		{"hex", "0x7f000001:14443", true},
		{"decimal", "2130706433:14443", true},
		{"octal", "0177.0.0.1:14443", true},
		{"octal, one part", "017700000001:14443", true},
		{"IPv6 loopback", "[::1]:14443", true},
		{"IPv4-mapped IPv6 loopback", "[::ffff:127.0.0.1]:14443", true},
		{"IPv6 loopback with a zone", "[::1%lo]:14443", true},

		{"wildcard v4", "0.0.0.0:14443", false},
		{"wildcard v6", "[::]:14443", false},
		{"empty host", ":14443", false},
		{"routable literal", "192.0.2.10:14443", false},
		// The deliberate half: names decide nothing here. See
		// TestLoopbackListen_RefusesToTrustANameAsProofOfALoopbackBind.
		{"localhost", "localhost:14443", false},
		{"localhost.localdomain", "localhost.localdomain:14443", false},
		{"a name under .localhost", "gw.localhost:14443", false},
		{"an ordinary hostname", "gateway.internal:14443", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// 1. the listen predicate.
			if got := isLoopbackListen(tc.listen); got != tc.loopback {
				t.Errorf("isLoopbackListen(%q) = %v, want %v", tc.listen, got, tc.loopback)
			}

			// 2. the config validator, through the CONNECT rule: a loopback
			// target on a port that is not the gateway's own is legitimate
			// on a loopback-only bind and an escalation on any other.
			err := connectCfg(tc.listen, "127.0.0.1:9200").Validate()
			if tc.loopback && err != nil {
				t.Errorf("Validate(listen=%q, allowed=[127.0.0.1:9200]) = %v, want nil: that bind IS loopback-only, so a loopback target on another port is the ordinary local deployment", tc.listen, err)
			}
			if !tc.loopback && err == nil {
				t.Errorf("Validate(listen=%q, allowed=[127.0.0.1:9200]) = nil, want a refusal: that bind is not loopback-only, so a local target lets a remote CONNECT holder launder itself into a loopback caller", tc.listen)
			}

			// 3. the dial-time guard, which relaxes on exactly the same
			// answer and must therefore stay armed on exactly the same
			// binds.
			if got := dialGuardArmed(tc.listen); got == tc.loopback {
				t.Errorf("connectDialRefusal armed=%v on listen %q while isLoopbackListen=%v; the guard is disarmed on loopback-only binds and only those, so these two must be opposites", got, tc.listen, tc.loopback)
			}

			// 4. the gateway_auth rule, the third thing loopback-ness
			// relaxes: a tokenless non-loopback bind must not start.
			gwErr := tokenlessValidate(tc.listen)
			if tc.loopback && gwErr != nil {
				t.Errorf("tokenless Validate(listen=%q) = %v, want nil", tc.listen, gwErr)
			}
			if !tc.loopback && gwErr == nil {
				t.Errorf("tokenless Validate(listen=%q) = nil, want a refusal naming gateway_auth", tc.listen)
			}
		})
	}
}

// TestLoadConfig_LoopbackBindInAnAlternativeNumericSpellingStarts is the
// availability regression, end to end through the file loader rather than the
// predicate: 127.1 is 127.0.0.1 to every C resolver, the deployment is
// loopback-only, and its own loopback target must not be refused at startup.
func TestLoadConfig_LoopbackBindInAnAlternativeNumericSpellingStarts(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{"127.1:14443", "0x7f000001:14443", "2130706433:14443", "0177.0.0.1:14443"} {
		t.Run(listen, func(t *testing.T) {
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
				"    enabled: true\n", listen)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := LoadConfig(path); err != nil {
				t.Fatalf("LoadConfig refused a loopback-only deployment that spells its bind %q: %v", listen, err)
			}
		})
	}
}

// TestLoopbackListen_RefusesToTrustANameAsProofOfALoopbackBind pins the
// decision taken on the name direction, which is a behaviour change.
//
// A name is NOT accepted as proof of a loopback-only bind — "localhost"
// included — because every use of that answer RELAXES something: it waives the
// gateway token, it permits loopback allowed_hosts entries, and it disarms
// connectDialRefusal. Trusting a spelling therefore fails open, and the only
// way to decide a name is to resolve it, which would make startup depend on
// whoever answers the resolver. The blocklist keeps its other job, where the
// same answer fails closed: as a CONNECT TARGET a reserved name is still local.
func TestLoopbackListen_RefusesToTrustANameAsProofOfALoopbackBind(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{"localhost:14443", "localhost.localdomain:14443", "ip6-localhost:14443", "gw.localhost:14443"} {
		t.Run(listen, func(t *testing.T) {
			t.Parallel()

			if isLoopbackListen(listen) {
				t.Fatalf("isLoopbackListen(%q) = true; a name is not proof of a loopback-only bind", listen)
			}

			// Layer one stays armed.
			why := connectSelfReference("127.0.0.1", "9200", listen)
			if why == "" {
				t.Errorf("connectSelfReference(127.0.0.1, 9200, listen=%q) is empty; the config-time layer is disarmed by a name-spelled bind", listen)
			}
			if !strings.Contains(why, "NAMES loopback but does not spell it") {
				t.Errorf("refusal = %q, want it to tell the operator to write the address", why)
			}

			// Layer two stays armed.
			if !dialGuardArmed(listen) {
				t.Errorf("connectDialRefusal is disarmed on listen %q; a host file pointing that name at a routable address would switch off the dial-time layer too", listen)
			}

			// And the gateway leg asks for a token, actionably.
			err := tokenlessValidate(listen)
			if err == nil {
				t.Fatalf("tokenless Validate(listen=%q) = nil; a bind this code cannot decide must ask for a token", listen)
			}
			if !strings.Contains(err.Error(), "gateway_auth") {
				t.Errorf("error = %v, want it to name gateway_auth", err)
			}
			if !strings.Contains(err.Error(), "NAMES loopback but does not spell it") {
				t.Errorf("error = %v, want the hint that says which word to change; a startup refusal on a fresh host is only useful if it does", err)
			}
			if !strings.Contains(err.Error(), "127.0.0.1") {
				t.Errorf("error = %v, want it to name the spelling that works", err)
			}
		})
	}
}

// TestLoopbackListen_TheTwoWaysOutOfTheNameRefusalWork keeps the behaviour
// change survivable: an operator who wrote a name has exactly two fixes, and
// both are in the message.
func TestLoopbackListen_TheTwoWaysOutOfTheNameRefusalWork(t *testing.T) {
	t.Parallel()

	t.Run("spell the address", func(t *testing.T) {
		t.Parallel()
		if err := tokenlessValidate("127.0.0.1:14443"); err != nil {
			t.Fatalf("Validate = %v, want nil", err)
		}
	})

	t.Run("configure a token", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Listen: "localhost:14443",
			Routes: []Route{{
				Name: "a", Prefix: "/a/", Upstream: "https://example.invalid",
				Auth: AuthPassthrough, Enabled: true,
			}},
			GatewayAuth: GatewayAuthConfig{TokenEnv: "GW"},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate = %v, want nil: a name-spelled bind with a token is authenticated whatever it resolves to", err)
		}
	})
}

// TestLoopbackNameHint_FiresOnlyForNames keeps the hint off refusals it does
// not explain: appending it to a wildcard bind's error would send the operator
// looking for a spelling problem that is not there.
func TestLoopbackNameHint_FiresOnlyForNames(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{"localhost:14443", "ip6-loopback:14443", "x.localhost:14443"} {
		if loopbackNameHint(listen) == "" {
			t.Errorf("loopbackNameHint(%q) is empty, want the spelling hint", listen)
		}
	}
	for _, listen := range []string{"0.0.0.0:14443", ":14443", "192.0.2.10:14443", "127.0.0.1:14443", "127.1:14443", "gateway.internal:14443", "[::1]:14443"} {
		if got := loopbackNameHint(listen); got != "" {
			t.Errorf("loopbackNameHint(%q) = %q, want empty: that refusal is not about a name", listen, got)
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
