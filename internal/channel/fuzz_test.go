package channel

// Fuzz targets for the gateway's untrusted-input surfaces.
//
// internal/channel is the package that reads bytes chosen by a caller and
// spends money with them: a request path decides which upstream is contacted, a
// CONNECT target decides which host is dialled, a YAML file decides whether the
// reverse-proxy leg authenticates anybody, an upstream response body decides how
// much a key is charged, and an inbound header decides whose account a provider
// bills. Every target below asserts a PROPERTY of one of those decisions. None
// of them assert "does not panic" alone -- a fuzz target whose only oracle is
// the runtime is a target that passes on a wrong answer.
//
// Seeds are the real regressions this workstream has already paid for. They are
// named at each f.Add so a later reader can tell a regression seed from a
// happy-path one.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fuzzSecrets is a SecretProvider that answers from a fixed table, so a fuzz
// target can build a Server without touching the environment, the filesystem or
// a vault. Resolving from a table also keeps the two gateway tokens distinct,
// which NewServer refuses to start without.
type fuzzSecrets map[string]string

func (s fuzzSecrets) Resolve(ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("fuzz: no secret configured for %q", ref)
}

// fuzzAuditor keeps the last audit line, which is how these targets observe
// WHICH refusal fired rather than merely that a status code came back. The
// distinction matters: 403 "host_not_allowlisted" is refused BEFORE the dial,
// 403 "target_resolves_to_loopback" is refused after it, and only the first one
// proves nothing was contacted.
type fuzzAuditor struct {
	mu     sync.Mutex
	event  string
	reason string
	status int
}

func (a *fuzzAuditor) Log(e AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.event, a.reason, a.status = e.Event, e.Error, e.Status
}

func (a *fuzzAuditor) read() (event, reason string, status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.event, a.reason, a.status
}

func (a *fuzzAuditor) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.event, a.reason, a.status = "", "", 0
}

// fuzzCapture records what an upstream actually received. It is the oracle for
// the two targets whose invariant is about the request the gateway EMITTED, not
// about the one it accepted.
type fuzzCapture struct {
	mu     sync.Mutex
	seen   bool
	rawURI string
	host   string
	header http.Header
}

func (c *fuzzCapture) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = true
	c.rawURI = r.URL.EscapedPath()
	c.host = r.Host
	c.header = r.Header.Clone()
}

func (c *fuzzCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen, c.rawURI, c.host, c.header = false, "", "", nil
}

func (c *fuzzCapture) snapshot() (seen bool, rawURI, host string, header http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen, c.rawURI, c.host, c.header
}

// -----------------------------------------------------------------------------
// 1. Path routing and upstream path composition.
// -----------------------------------------------------------------------------

// FuzzChannelPathRouting drives arbitrary request paths through (*Server).match
// and the real Forward path composition, and checks where the bytes landed.
//
// INVARIANT: the path the upstream actually receives never escapes the route's
// configured upstream base, and the host contacted is never anything but the
// configured upstream host.
//
// SKIPPED, and deliberately not weakened to make it pass. Dot segments in a
// caller path survive composition and reach the upstream: Forward concatenates
// strings, http.NewRequestWithContext does not normalise a path, and neither
// does the Transport, so "/openai/../../admin" is emitted to the upstream as
// "/v1/../../admin" and an upstream that resolves dot segments serves /admin.
// That is the H2 path-normalisation carry-forward, which is byte-identical to
// main at 6e32801 and is explicitly out of scope for this change. The target is
// written to the FULL invariant so that the day H2 lands, deleting this Skip is
// the whole of the verification.
func FuzzChannelPathRouting(f *testing.F) {
	f.Skip("blocked on H2 path normalisation: dot segments in a caller path still reach the upstream (carry-forward, byte-identical to main at 6e32801). Delete this Skip when H2 lands -- do not weaken the invariant.")

	capt := &fuzzCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capt.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	f.Cleanup(upstream.Close)

	// A base with a path segment is the shape every real route has
	// ("https://api.minimaxi.com/v1"), and it is the shape that makes "escaped
	// the base" a question with an answer.
	const basePath = "/v1"
	cfg := &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{
			{Name: "openai", Prefix: "/openai/", Upstream: upstream.URL + basePath, Auth: AuthPassthrough, Enabled: true},
			{Name: "codex", Prefix: "/openai/codex/", Upstream: upstream.URL + basePath, Auth: AuthPassthrough, Enabled: true},
		},
	}
	if err := cfg.Validate(); err != nil {
		f.Fatalf("validate: %v", err)
	}
	srv, err := NewServer(cfg, NewHTTPForwarder(), &fuzzAuditor{})
	if err != nil {
		f.Fatalf("NewServer: %v", err)
	}
	fwd := NewHTTPForwarder()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	f.Add("/openai/v1/models", "")                           // happy path
	f.Add("/openai/../../admin", "")                         // the H2 carry-forward itself
	f.Add("/openai/codex/../../../etc/passwd", "")           // longest-prefix route, same escape
	f.Add("/openai/./v1/models", "")                         // single dot
	f.Add("/openai//..//..//admin", "")                      // empty segments around the escape
	f.Add("/openai/%2e%2e/%2e%2e/admin", "")                 // percent-encoded dot segments
	f.Add("/openai/v1/models", "a=1&b=%2e%2e")               // escape attempted through the query
	f.Add("/openai", "")                                     // prefix without its trailing slash
	f.Add("/openaix/v1", "")                                 // near-miss that must not match
	f.Add("/openai/v1/models/../../../../../../../root", "") // more dot segments than segments
	f.Add("/openai/\\../admin", "")                          // backslash, which some upstreams fold
	f.Add("/openai/v1;/../admin", "")                        // path parameter before the escape

	f.Fuzz(func(t *testing.T, reqPath, rawQuery string) {
		rt := srv.match(reqPath)
		if rt == nil {
			return
		}
		req := &http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Path: reqPath, RawQuery: rawQuery},
			Header: make(http.Header),
			Host:   "gateway.invalid",
			Body:   http.NoBody,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		capt.reset()
		resp, err := fwd.Forward(ctx, req, rt)
		if err != nil {
			// A path the URL parser refuses never reaches an upstream, which
			// satisfies the invariant by never composing anything.
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		seen, gotPath, gotHost, _ := capt.snapshot()
		if !seen {
			t.Fatalf("upstream recorded nothing for path %q", reqPath)
		}
		if gotHost != upstreamHost {
			t.Errorf("path %q reached host %q, want %q: a request path must never move the request off its route's upstream", reqPath, gotHost, upstreamHost)
		}
		clean := path.Clean(gotPath)
		if clean != basePath && !strings.HasPrefix(clean, basePath+"/") {
			t.Errorf("path %q composed to upstream path %q (cleans to %q), which escapes the route base %q", reqPath, gotPath, clean, basePath)
		}
	})
}

// -----------------------------------------------------------------------------
// 2. CONNECT target admission.
// -----------------------------------------------------------------------------

// FuzzConnectTarget drives arbitrary CONNECT targets at a gateway whose
// allowlist holds exactly one entry.
//
// TWO INVARIANTS, both of which are the difference between a bounded tunnel
// credential and an open relay:
//
//   - Nothing that is not case-folded byte-equal to an allowlist entry is ever
//     DIALLED. Observed two ways that do not share code: the refusal must be
//     "host_not_allowlisted", which handleConnect can only emit before the dial,
//     and no connection may arrive at the sink listener.
//   - Nothing that resolves to the gateway's own machine is ever TUNNELLED. The
//     one allowlisted entry is a loopback sink, so the allowlisted path must
//     still be refused, by connectDialRefusal, after the dial and before a byte
//     moves.
//
// No fuzz input can cause a dial to a name, so this target performs no DNS and
// contacts no provider: the only address it can ever reach is the local sink.
func FuzzConnectTarget(f *testing.F) {
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.Fatalf("listen sink: %v", err)
	}
	f.Cleanup(func() { _ = sink.Close() })

	// A connection arriving here is the ground truth for "the gateway dialled
	// it". The channel is the synchronisation point: the allowlisted path waits
	// for its own accept, so a non-empty channel on any other input means a dial
	// happened that the allowlist never authorised.
	accepted := make(chan struct{}, 64)
	go func() {
		for {
			c, aerr := sink.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}()

	allow := sink.Addr().String()
	lowerAllow := strings.ToLower(allow)
	const connectToken = "fuzz-connect-token"
	cfg := &Config{
		Listen: "127.0.0.1:0",
		Connect: ConnectConfig{
			Enabled:      true,
			AllowedHosts: []string{allow},
			TokenRef:     "env:FUZZ_CONNECT_TOKEN",
			DialTimeout:  5 * time.Second,
		},
	}
	if verr := cfg.Validate(); verr != nil {
		f.Fatalf("validate: %v", verr)
	}
	audit := &fuzzAuditor{}
	secrets := fuzzSecrets{"env:FUZZ_CONNECT_TOKEN": connectToken}
	srv, err := NewServer(cfg, NewHTTPForwarder(), audit, WithSecretProvider(secrets))
	if err != nil {
		f.Fatalf("NewServer: %v", err)
	}
	handler := srv.Handler()

	_, sinkPort, err := net.SplitHostPort(allow)
	if err != nil {
		f.Fatalf("split sink addr: %v", err)
	}

	f.Add(allow)                            // the one entry that is allowed
	f.Add(strings.ToUpper(allow))           // case folding is the documented match rule
	f.Add("127.1:" + sinkPort)              // inet_aton short form of the sink
	f.Add("0x7f000001:" + sinkPort)         // hex form
	f.Add("2130706433:" + sinkPort)         // decimal form
	f.Add("0177.0.0.1:" + sinkPort)         // octal form
	f.Add("[::ffff:127.0.0.1]:" + sinkPort) // IPv4-mapped IPv6
	f.Add("127.0.0.1%evil:" + sinkPort)     // zone on a dotted quad: a NAME to net.Dial
	f.Add("localhost:" + sinkPort)          // a name that resolves to the sink
	f.Add("evil.localhost:" + sinkPort)     // the .localhost suffix rule
	f.Add("127.0.0.1.:" + sinkPort)         // trailing-dot spelling
	f.Add(" " + allow)                      // leading whitespace
	f.Add(allow + " ")                      // trailing whitespace
	f.Add("")                               // empty host dials the local machine
	f.Add(":" + sinkPort)                   // empty host, explicit port
	f.Add("[::1]:" + sinkPort)              // IPv6 loopback
	f.Add("0.0.0.0:" + sinkPort)            // the unspecified address
	f.Add("api.anthropic.com:443")          // a real provider, which must never be dialled

	f.Fuzz(func(t *testing.T, target string) {
		audit.reset()
		req := &http.Request{
			Method:     http.MethodConnect,
			URL:        &url.URL{Host: target},
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Host:       target,
			Body:       http.NoBody,
			RemoteAddr: "198.51.100.7:40000",
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+connectToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		event, reason, _ := audit.read()
		if event == "connect_established" {
			t.Fatalf("target %q established a tunnel; the only allowlist entry is the loopback sink %q, which connectDialRefusal must refuse", target, allow)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("target %q got status %d (audit %q/%q), want 403: every target is either off the allowlist or resolves to this machine", target, rec.Code, event, reason)
		}

		if strings.ToLower(target) != lowerAllow {
			if reason != "host_not_allowlisted" {
				t.Fatalf("target %q was refused as %q, want %q: a target that is not byte-equal (case-folded) to an allowlist entry must be refused BEFORE the dial", target, reason, "host_not_allowlisted")
			}
			if len(accepted) != 0 {
				t.Fatalf("target %q is not on the allowlist yet a connection reached the sink %q", target, allow)
			}
			return
		}

		// The allowlisted entry IS the local machine, so it is dialled and then
		// refused. Waiting for the accept keeps the counter above honest.
		if reason != "target_resolves_to_loopback" {
			t.Fatalf("allowlisted target %q was refused as %q, want %q: a target that resolves to the gateway's own machine must never be tunnelled", target, reason, "target_resolves_to_loopback")
		}
		timer := time.NewTimer(20 * time.Second)
		defer timer.Stop()
		select {
		case <-accepted:
		case <-timer.C:
			t.Fatalf("allowlisted target %q produced no connection at the sink", target)
		}
	})
}

// -----------------------------------------------------------------------------
// 3. Gateway configuration.
// -----------------------------------------------------------------------------

// fuzzLoopbackLiteral is a SECOND, independently written answer to "does this
// bind address spell a loopback-only socket?", used as the oracle for
// FuzzGatewayConfigYAML.
//
// It is written out rather than calling isLoopbackListen because an oracle that
// calls the code under test proves nothing. The rule it implements is the one
// net.Listen itself follows: only an address LITERAL is decided here, a zone is
// legal on an IPv6 literal and nowhere else (a "%" after a dotted quad makes the
// whole string a host NAME that the platform resolver answers), and a name --
// "localhost" included -- is not an address at all.
func fuzzLoopbackLiteral(listen string) bool {
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		if !strings.Contains(host[:i], ":") {
			return false
		}
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// FuzzGatewayConfigYAML feeds arbitrary YAML to LoadConfig.
//
// INVARIANTS:
//
//   - Never panics, and the (config, error) pair is never ambiguous: exactly one
//     of them is set, so a rejection always carries a reason a caller can print.
//   - An ACCEPTED config never describes a tokenless, non-loopback listen
//     posture unless the operator wrote allow_unauthenticated down. That is the
//     one property that stands between a config file and a funded,
//     unauthenticated relay, and it has now been broken three times by three
//     different spellings of "loopback".
//   - An ACCEPTED config never enables CONNECT without both an allowlist and a
//     token source, because either half missing is an open relay.
func FuzzGatewayConfigYAML(f *testing.F) {
	dir := f.TempDir()
	cfgPath := filepath.Join(dir, "gateway.yaml")

	f.Add([]byte("listen: 127.0.0.1:14443\n"))                                                                             // minimal accepted
	f.Add([]byte("listen: 0.0.0.0:14443\n"))                                                                               // tokenless wildcard: must be refused
	f.Add([]byte("listen: localhost:14443\n"))                                                                             // a NAME is not proof of loopback
	f.Add([]byte("listen: 127.1:14443\n"))                                                                                 // inet_aton short form
	f.Add([]byte("listen: 2130706433:14443\n"))                                                                            // inet_aton decimal
	f.Add([]byte("listen: 0x7f000001:14443\n"))                                                                            // inet_aton hex
	f.Add([]byte("listen: 0177.0.0.1:14443\n"))                                                                            // inet_aton octal
	f.Add([]byte("listen: 127.0.0.1%evil:14443\n"))                                                                        // zone on a dotted quad: measured binding a routable address
	f.Add([]byte("listen: \"[::1%lo]:14443\"\n"))                                                                          // the legitimate IPv6 zone spelling
	f.Add([]byte("listen: 0.0.0.0:14443\ngateway_auth:\n  allow_unauthenticated: true\n"))                                 // written-down acceptance
	f.Add([]byte("listen: 0.0.0.0:14443\ngateway_auth:\n  token_env: GW\n"))                                               // token makes the wide bind legal
	f.Add([]byte("listen: 0.0.0.0:14443\ngateway_auth:\n  token_env: GW\n  allow_unauthenticated: true\n"))                // the refused contradiction
	f.Add([]byte("listen: 127.0.0.1:1\nconnect:\n  enabled: true\n  token_env: CT\n"))                                     // connect with no allowlist
	f.Add([]byte("listen: 127.0.0.1:1\nconnect:\n  enabled: true\n  allowed_hosts: [\"127.0.0.1:1\"]\n  token_env: CT\n")) // allowlists the gateway itself
	f.Add([]byte("listen: :14443\n"))                                                                                      // empty host is a wildcard bind
	f.Add([]byte("listen:\n"))                                                                                             // null
	f.Add([]byte("listen: [1, 2]\n"))                                                                                      // wrong YAML type
	f.Add([]byte("\x00\x01\x02"))                                                                                          // not YAML at all
	f.Add([]byte("a: &x [*x]\n"))                                                                                          // self-referential alias

	f.Fuzz(func(t *testing.T, raw []byte) {
		if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := LoadConfig(cfgPath)
		if (cfg == nil) == (err == nil) {
			t.Fatalf("LoadConfig returned cfg=%v err=%v: exactly one of them must be set, or a rejection has no reason and an acceptance has no config", cfg != nil, err)
		}
		if err != nil {
			return
		}
		if cfg.Listen == "" {
			t.Fatalf("accepted a config with an empty listen address")
		}
		g := cfg.GatewayAuth
		if !g.hasToken() && !g.AllowUnauthenticated && !fuzzLoopbackLiteral(cfg.Listen) {
			t.Errorf("accepted listen %q with no gateway token and no allow_unauthenticated: that posture authenticates nobody while the socket may be reachable from other hosts, so anyone who can open a TCP connection can spend every key on every enabled route", cfg.Listen)
		}
		if cfg.Connect.Enabled {
			if len(cfg.Connect.AllowedHosts) == 0 {
				t.Errorf("accepted connect.enabled with an empty allowed_hosts: that is an open relay")
			}
			if cfg.Connect.TokenEnv == "" && cfg.Connect.TokenFile == "" && cfg.Connect.TokenRef == "" {
				t.Errorf("accepted connect.enabled with no token source: the tunnel leg would authenticate nobody")
			}
		}
	})
}

// -----------------------------------------------------------------------------
// 4. Usage extraction and the charge it produces.
// -----------------------------------------------------------------------------

// fuzzReportedTokens is the reference reading of a token count: what a strict
// JSON parser says the upstream reported.
//
// It returns the value rounded UP, because the question the invariant asks is
// "could the gateway charge LESS than the upstream said", and a fractional
// report of 1.5 tokens is at least 2 whole ones. ok is false whenever the
// literal is not a JSON number at all, in which case the upstream reported
// nothing an oracle can compare against.
func fuzzReportedTokens(literal string) (int64, bool) {
	dec := json.NewDecoder(strings.NewReader(literal))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return 0, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, false
	}
	// An integer literal is read as an INTEGER. Going through float64 loses
	// precision above 2^53 and rounds UP, which made the oracle itself claim an
	// under-charge on "72100000000001020" -- the extractor charged exactly what
	// was reported and float64 said the report had been 72100000000001024.
	if iv, err := n.Int64(); err == nil {
		return iv, true
	}
	fv, err := n.Float64()
	if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
		return 0, false
	}
	// Outside the exactly-representable range there is no reliable comparison to
	// make, so the oracle declines rather than guessing.
	if math.Abs(fv) >= 1<<53 {
		return 0, false
	}
	return int64(math.Ceil(fv)), true
}

// FuzzUsageExtraction feeds arbitrary bytes, and arbitrary token literals, to
// the usage extractor that decides what a request costs.
//
// INVARIANT: a malformed or hostile upstream can never produce an AUTHORITATIVE
// charge (Estimated=false) that is LOWER than the count the upstream actually
// reported. Under-charging is not a cosmetic error here: it is the failure that
// suppresses leastTokens' degrade-to-request-ordering guard, which only fires on
// an estimated sample, so an under-charge also silently disables the guard that
// would have noticed.
//
// SECOND INVARIANT: the answer does not depend on how the body was chunked. The
// extractor keeps a rolling tail across Observe calls, so a usage object split
// across two TCP reads must produce the same sample as one that arrived whole --
// otherwise an upstream could choose its own price by choosing its write sizes.
func FuzzUsageExtraction(f *testing.F) {
	f.Add("1.5", uint8(0), []byte(nil))                       // the known past defect: charged 1, Estimated FALSE
	f.Add("12", uint8(0), []byte(nil))                        // happy path
	f.Add("12", uint8(1), []byte(nil))                        // same, one byte at a time
	f.Add("0", uint8(0), []byte(nil))                         // a real zero is not "unknown"
	f.Add("-5", uint8(0), []byte(nil))                        // negative
	f.Add("1e3", uint8(0), []byte(nil))                       // exponent notation
	f.Add("0.9", uint8(0), []byte(nil))                       // rounds up to 1, must not charge 0
	f.Add("00012", uint8(0), []byte(nil))                     // leading zeros
	f.Add("9223372036854775808", uint8(0), []byte(nil))       // one past MaxInt64
	f.Add("72100000000001020", uint8(0), []byte(nil))         // past 2^53: exact, but not in a float64
	f.Add("1_000", uint8(0), []byte(nil))                     // underscore separator
	f.Add("\"12\"", uint8(0), []byte(nil))                    // quoted number
	f.Add("12", uint8(0), []byte(`{"total_tokens":1}`))       // an earlier marker in the body
	f.Add("1.5", uint8(3), []byte(strings.Repeat("x", 9000))) // usage pushed past the retained tail
	f.Add("12", uint8(0), []byte(`data: {"total_tokens":`))   // a truncated SSE frame ahead of it

	f.Fuzz(func(t *testing.T, literal string, chunk uint8, junk []byte) {
		body := make([]byte, 0, len(junk)+len(literal)+64)
		body = append(body, junk...)
		body = append(body, `{"id":"x","usage":{"prompt_tokens":1,"total_tokens":`...)
		body = append(body, literal...)
		body = append(body, `}}`...)

		whole := NewUsageExtractor()
		whole.Observe(body)
		got := whole.Result()

		step := int(chunk) + 1
		pieces := NewUsageExtractor()
		for i := 0; i < len(body); i += step {
			pieces.Observe(body[i:min(i+step, len(body))])
		}
		if chunked := pieces.Result(); chunked != got {
			t.Fatalf("chunking changed the charge: %d-byte chunks gave %+v, one write gave %+v -- an upstream must not be able to pick its own price by picking its write sizes", step, chunked, got)
		}

		if got.Estimated || got.Tokens == TokensUnknown {
			return
		}
		if got.Tokens < 0 {
			t.Fatalf("authoritative charge is negative (%d) for literal %q", got.Tokens, literal)
		}
		// A marker inside the fuzzed junk makes "what the upstream reported"
		// ambiguous, and the extractor is documented to take the LAST one it can
		// read; there is no single truth to compare against.
		if bytes.Contains(junk, usageMarker) {
			return
		}
		reported, ok := fuzzReportedTokens(literal)
		if !ok {
			return
		}
		if got.Tokens < reported {
			t.Errorf("upstream reported %q but the gateway charged %d as AUTHORITATIVE: an authoritative charge must never be lower than the reported count (an under-charge also suppresses the estimated-sample guard)", literal, got.Tokens)
		}
	})
}

// -----------------------------------------------------------------------------
// 5. Caller credential headers.
// -----------------------------------------------------------------------------

// fuzzDeniedHeaders re-states the caller-credential deny-set independently of
// callerCredentialHeaders, for the same reason fuzzLoopbackLiteral re-states the
// loopback rule: an oracle that reads the table under test cannot catch an edit
// to that table. A name added to the production list and not to this one shows
// up as a failing invariant, which is the intended signal.
var fuzzDeniedHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"X-Api-Key",
	"Api-Key",
	"X-Goog-Api-Key",
	"Cookie",
	"OpenAI-Organization",
	"OpenAI-Project",
}

// fuzzAuthPosture is one auth mode with the outbound credential it is supposed
// to produce.
type fuzzAuthPosture struct {
	name string
	auth Authenticator
	// keyHeader is the route's key_header, which extends the deny-set.
	keyHeader string
	// wantHeader/wantValue is the credential the gateway itself writes. Empty
	// on the mode that writes none.
	wantHeader string
	wantValue  string
	// strips is false only for the mode that carries the CALLER's credential on
	// purpose.
	strips bool
}

// FuzzCredentialHeaderStrip feeds arbitrary inbound header names and values
// through the real forwarder to a real upstream, on every auth posture.
//
// INVARIANTS:
//
//   - On every INJECTING mode, no caller-supplied value for a credential-bearing
//     header reaches the upstream. The gateway is either a credential boundary or
//     a credential ADDER, and a provider that honours whichever credential it
//     likes turns the second one into "bill someone else's account through this
//     gateway".
//   - On every injecting mode the gateway's OWN credential arrives exactly once,
//     so a caller cannot displace it or make it ambiguous.
//   - Proxy-Authorization never reaches the upstream in ANY mode: it is
//     hop-by-hop, and it authenticates the hop to the gateway rather than the
//     gateway to the provider.
//   - PASSTHROUGH is exempt by design and must keep carrying the caller's
//     Authorization, because that mode exists for upstreams where the client
//     holds the credential.
func FuzzCredentialHeaderStrip(f *testing.F) {
	capt := &fuzzCapture{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capt.record(r)
		w.WriteHeader(http.StatusOK)
	}))
	f.Cleanup(upstream.Close)

	const gwKey = "gateway-held-key"
	const routeKeyHeader = "X-Route-Key"
	postures := []fuzzAuthPosture{
		{"inject/bearerInjector", &bearerInjector{key: gwKey}, "", "Authorization", "Bearer " + gwKey, true},
		{"inject/leasedInjector", leasedInjector{key: gwKey, prefix: "Bearer ", mode: AuthInject}, "", "Authorization", "Bearer " + gwKey, true},
		{"header/leasedInjector", leasedInjector{key: gwKey, header: routeKeyHeader, mode: AuthHeaderInject}, routeKeyHeader, routeKeyHeader, gwKey, true},
		{"passthrough", passthrough{}, "", "", "", false},
	}
	fwd := NewHTTPForwarder()

	f.Add("Authorization", "Bearer caller-stolen-token", uint8(0))
	f.Add("authorization", "Bearer caller-stolen-token", uint8(0))
	f.Add("AUTHORIZATION", "Bearer caller-stolen-token", uint8(1))
	f.Add("X-Api-Key", "sk-ant-caller", uint8(0))
	f.Add("x-api-key", "sk-ant-caller", uint8(2))
	f.Add("Api-Key", "azure-caller", uint8(1))
	f.Add("X-Goog-Api-Key", "goog-caller", uint8(0))
	f.Add("Cookie", "session=caller", uint8(0))
	f.Add("OpenAI-Organization", "org-someone-elses-budget", uint8(0)) // spend direction, not auth
	f.Add("OpenAI-Project", "proj-someone-elses-budget", uint8(1))     // likewise, one level down
	f.Add("openai-organization", "org-someone-elses-budget", uint8(2))
	f.Add("Proxy-Authorization", "Bearer gateway-hop-token", uint8(3)) // hop-by-hop, exempt mode
	f.Add("X-Route-Key", "caller-picked-route-key", uint8(2))          // the operator-named header
	f.Add("Authorization", "Bearer caller-stolen-token", uint8(3))     // passthrough must KEEP it
	f.Add("X-Forwarded-For", "203.0.113.9", uint8(0))                  // an ordinary header must survive
	f.Add("", "", uint8(0))
	f.Add("Authorization ", "Bearer caller", uint8(0)) // trailing space: not a legal name
	f.Add("Authorization", " ", uint8(3))              // an all-whitespace value is "" on the wire

	f.Fuzz(func(t *testing.T, name, value string, sel uint8) {
		p := postures[int(sel)%len(postures)]
		rt := &boundRoute{
			Route: Route{Name: "fz", Prefix: "/fz/", Upstream: upstream.URL, Auth: AuthInject, KeyHeader: p.keyHeader},
			Auth:  p.auth,
		}
		req := httptest.NewRequest(http.MethodPost, "/fz/v1/chat", nil)
		// Assigned into the map directly rather than through Set, so a
		// non-canonical spelling reaches the forwarder exactly as the caller
		// wrote it -- which is the whole question for a case-insensitive rule.
		req.Header[name] = []string{value}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		capt.reset()
		resp, err := fwd.Forward(ctx, req, rt)
		if err != nil {
			// A header net/http refuses to transmit never reaches an upstream.
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		seen, _, _, got := capt.snapshot()
		if !seen {
			t.Fatalf("posture %s: upstream recorded nothing", p.name)
		}

		if vs := got.Values("Proxy-Authorization"); len(vs) != 0 {
			t.Errorf("posture %s: Proxy-Authorization reached the upstream as %q: it is hop-by-hop and authenticates the caller to the GATEWAY, never the gateway to the provider", p.name, vs)
		}

		// Comparisons are made on the TRIMMED value, because RFC 9110 field
		// values carry no leading or trailing whitespace: net/http strips it on
		// the way out and again on the way in, so " sk-caller " is received as
		// "sk-caller". Trimming both sides keeps the strip assertion strictly
		// stronger (a value that survives in any spelling is caught) and keeps
		// the passthrough assertion from blaming the gateway for the wire.
		wantValue := strings.TrimSpace(value)

		if p.strips {
			denied := p.keyHeader != "" && strings.EqualFold(name, p.keyHeader)
			for _, d := range fuzzDeniedHeaders {
				if strings.EqualFold(name, d) {
					denied = true
					break
				}
			}
			if denied && wantValue != "" {
				canon := http.CanonicalHeaderKey(name)
				for _, v := range got.Values(canon) {
					if strings.TrimSpace(v) != wantValue {
						continue
					}
					if canon == p.wantHeader && wantValue == p.wantValue {
						// Indistinguishable from the gateway's own credential.
						continue
					}
					t.Errorf("posture %s: caller header %q reached the upstream carrying the caller's value %q; on a mode where the GATEWAY supplies the credential, a caller credential must not travel alongside it", p.name, name, value)
				}
			}
			vs := got.Values(p.wantHeader)
			if len(vs) != 1 || vs[0] != p.wantValue {
				t.Errorf("posture %s: upstream saw %s = %q, want exactly [%q]: a caller must not be able to displace or duplicate the gateway's own credential (caller sent %q: %q)", p.name, p.wantHeader, vs, p.wantValue, name, value)
			}
			return
		}

		// Passthrough: the exemption is the point of the mode, so assert it is
		// still there. A value that is empty once trimmed carries no credential
		// and cannot be traced through the wire, so it is excluded.
		if strings.EqualFold(name, "Authorization") && wantValue != "" {
			found := false
			for _, v := range got.Values("Authorization") {
				if strings.TrimSpace(v) == wantValue {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("posture %s: caller Authorization %q did not reach the upstream; passthrough exists for upstreams where the CLIENT holds the credential and must not strip it", p.name, value)
			}
		}
	})
}
