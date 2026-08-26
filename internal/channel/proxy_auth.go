package channel

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// GatewayTokenHeader carries the caller's gateway token on the REVERSE-PROXY
// leg.
//
// It is deliberately NOT "Authorization". Clients of an inject route are told
// to configure a placeholder bearer — Kilo Code refuses to send a request
// without some API key — and the forwarder strips that placeholder before the
// request leaves. Reading caller authentication out of the same header would
// make the gateway's admission decision depend on a value clients were told was
// meaningless, and would break every configured client on the day it landed.
//
// It is also NOT "Proxy-Authorization". That header belongs to the CONNECT leg
// and to authorizeConnect, and the two credentials are separate secrets on
// purpose: the CONNECT token gates a tunnel bounded by an allowlist, the
// gateway token gates the ability to spend every key on every enabled route.
// Overloading one for the other would silently widen whichever was configured
// first.
//
// SECURITY CHANGE 2026-08-27: renamed from "X-HelixChannel-Token" to
// "X-HLXN-Token" (operator naming convention: HLXN is the short code for
// "Helixon" across headers, env var prefixes and CLI flags going forward).
// Nothing reads the old name any more — this is a rename, not an added
// alias — so every remote client's configuration and every doc/example must
// be updated to the new header BEFORE this build reaches a host any
// non-loopback client talks to. A client still sending the old header is
// indistinguishable from one sending no header at all: refusalTokenRequired,
// not refusalTokenInvalid.
const GatewayTokenHeader = "X-HLXN-Token"

// gatewayAuthChallenge is the WWW-Authenticate value on a refusal.
//
// The scheme is a private one because the credential is not in Authorization,
// and the "header" auth-param names where it belongs — a caller that is refused
// otherwise has no way to learn what to send. The status is 401 rather than the
// CONNECT leg's 407: on this leg the gateway is an ORIGIN server as far as the
// client is concerned (clients set a base URL, not HTTPS_PROXY), and 407 would
// tell an HTTP client to look for proxy credentials it does not have.
const gatewayAuthChallenge = `HelixChannel realm="helixchannel-gateway", header="` + GatewayTokenHeader + `"`

// proxyAuthRefusal is WHY a caller was refused the reverse-proxy leg, or
// proxyAuthOK if it was not. The two refusals are different facts and the
// caller and the audit stream both get told which: "you sent nothing" is an
// unconfigured client, "you sent the wrong thing" is a stale or hostile one,
// and collapsing them makes a credential rotation indistinguishable from an
// attack.
type proxyAuthRefusal string

const (
	proxyAuthOK          proxyAuthRefusal = ""
	refusalTokenRequired proxyAuthRefusal = "gateway_token_required"
	refusalTokenInvalid  proxyAuthRefusal = "gateway_token_invalid"
)

// isLoopbackPeer reports whether the TCP peer is on 127.0.0.0/8 or ::1.
//
// It reads ONLY http.Request.RemoteAddr, which net/http fills in from the
// accepted connection. It deliberately consults no header: X-Forwarded-For,
// X-Real-IP and Forwarded are all caller-supplied strings, and honouring any of
// them would let a remote caller claim the exemption by typing "127.0.0.1" into
// a header. There is no configuration switch to make it trust one either — a
// gateway that can be talked into believing a caller is local has no loopback
// exemption, it has a bypass.
//
// Anything unparseable — a UNIX socket peer, an empty RemoteAddr, a hostname —
// is NOT loopback. The safe answer is the one that asks for a token.
func isLoopbackPeer(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	// A link-local zone ("fe80::1%eth0") is not loopback, but ::1%lo1 can
	// reach here on some stacks; ParseIP rejects the zone, so drop it first.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// auditClientAddr reports the address an audit line should blame for r.
//
// This is an OBSERVABILITY function, not an authorization function, and the
// distinction is the entire design: it is the sole reader of
// Config.TrustForwardedForAudit, it is never called from authorizeProxy or
// authorizeConnect, and nothing it returns changes whether a request is
// served. A caller cannot buy anything by setting X-Forwarded-For except a
// more (or less) accurate audit line.
//
// The condition for trusting the header is narrow on purpose: the peer that
// ACCEPTED this TCP connection must itself be loopback (isLoopbackPeer on
// r.RemoteAddr — the same predicate the auth path uses, so "loopback" means
// one thing everywhere in this package), which is the shape of exactly one
// deployment: a same-host TLS terminator relaying the public internet to a
// gateway bound on 127.0.0.1. A non-loopback peer's own address is already
// the real one and nothing overrides it.
//
// X-Forwarded-For may carry a comma-separated chain; only the FIRST entry
// (nearest the original client, per the header's own convention) is used,
// and only after net.ParseIP accepts it as a literal — the same numeric-only
// parse isLoopbackPeer uses, not a hostname the OS resolver could interpret
// differently between two calls. Anything that fails to parse falls back to
// r.RemoteAddr unchanged: this function fails closed to the value the
// process itself observed, never open to a string the caller supplied.
func (s *Server) auditClientAddr(r *http.Request) string {
	if !s.trustForwardedForAudit || !isLoopbackPeer(r.RemoteAddr) {
		return r.RemoteAddr
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return r.RemoteAddr
	}
	first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	if first == "" {
		return r.RemoteAddr
	}
	if net.ParseIP(first) == nil {
		return r.RemoteAddr
	}
	return first
}

// authorizeProxy decides whether a caller may use the reverse-proxy leg.
//
// The rules, in the order they are applied:
//
//	open / loopback_only  no gateway token is configured, so there is nothing to
//	                      check and every caller is served. Config.Validate
//	                      refuses to let loopback_only bind a non-loopback
//	                      address, and `open` is the explicit opt-out an
//	                      operator must write down to bind one anyway.
//	no token presented    served only under token_loopback_exempt AND only when
//	                      the TCP peer is genuinely loopback. Otherwise
//	                      gateway_token_required.
//	token presented       must be correct, whatever the peer. The exemption
//	                      exempts a caller from HAVING to present a token; it
//	                      does not exempt a presented token from being checked,
//	                      so a local client configured with a stale token fails
//	                      loudly instead of silently working and then breaking
//	                      the day it moves off the box.
//
// The blank-token guards are two SEPARATE properties, unlike authorizeConnect's
// mutually redundant pair:
//
//   - presented == "" returns before any comparison. Without it a server whose
//     token were somehow empty would reach subtle.ConstantTimeCompare("", "")
//     == 1 and authorise a caller that sent an empty header — the same
//     whitespace-credential bypass the CONNECT leg once had. With a real token
//     configured it is still load-bearing for a different reason: it is what
//     makes an absent credential report gateway_token_required rather than
//     gateway_token_invalid.
//   - s.proxyToken == "" is a BACKSTOP, and cannot be killed by a test on its
//     own: NewServer rejects a blank resolved token, so a token mode always
//     carries a non-empty one, and with a non-empty presented value the
//     comparison already returns 0 against "". It stays because the failure it
//     guards is an unauthenticated funded relay.
func (s *Server) authorizeProxy(r *http.Request) proxyAuthRefusal {
	if s.proxyAuth == ProxyAuthOpen || s.proxyAuth == ProxyAuthLoopbackOnly {
		return proxyAuthOK
	}
	presented := strings.TrimSpace(r.Header.Get(GatewayTokenHeader))
	if presented == "" {
		if s.proxyAuth == ProxyAuthTokenLoopbackExempt && isLoopbackPeer(r.RemoteAddr) {
			return proxyAuthOK
		}
		return refusalTokenRequired
	}
	if s.proxyToken == "" {
		return refusalTokenInvalid
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.proxyToken)) != 1 {
		return refusalTokenInvalid
	}
	return proxyAuthOK
}

// denyUnauthenticated answers a caller refused BEFORE route matching.
//
// Refusing before the match is deliberate: writeNotFound's 404 body lists every
// enabled route name, so matching first would disclose the route table to a
// caller that is not allowed to use any of it. The body names the header to
// send and nothing else — never the expected token, never how close the
// presented one was.
func (s *Server) denyUnauthenticated(w http.ResponseWriter, r *http.Request, requestID string, start time.Time, refusal proxyAuthRefusal) {
	w.Header().Set("WWW-Authenticate", gatewayAuthChallenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":  string(refusal),
		"hint":   "the reverse-proxy leg requires a gateway token in the " + GatewayTokenHeader + " header; it is not the Authorization header and not the CONNECT channel token",
		"header": GatewayTokenHeader,
	})
	s.audit.Log(AuditEvent{
		Event: "proxy_denied", RequestID: requestID,
		Method: r.Method, Path: r.URL.Path,
		Status:     http.StatusUnauthorized,
		LatencyMS:  time.Since(start).Milliseconds(),
		ClientAddr: s.auditClientAddr(r), Error: string(refusal),
	})
}
