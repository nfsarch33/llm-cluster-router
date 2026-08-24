package channel

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Forwarder sends a proxied request to an upstream and returns its response.
//
// The HTTP handler depends on this interface rather than on net/http
// directly, so the handler can be tested without a network and a different
// transport (queued, retrying, circuit-broken) can be substituted without
// touching the handler.
type Forwarder interface {
	Forward(ctx context.Context, req *http.Request, rt *boundRoute) (*http.Response, error)
}

// boundRoute is a Route with its constructed dependencies. It is built once
// at startup so per-request work stays minimal.
type boundRoute struct {
	Route Route
	Auth  Authenticator
}

// httpForwarder is the default Forwarder: a plain HTTPS client.
type httpForwarder struct {
	client *http.Client
}

// NewHTTPForwarder returns the default Forwarder.
//
// Timeouts are set on the transport rather than the client so that streaming
// responses (server-sent events from chat completions) are not cut off
// mid-stream by a whole-request deadline; the per-request context supplies
// the overall bound.
func NewHTTPForwarder() Forwarder {
	return &httpForwarder{
		client: &http.Client{
			CheckRedirect: refuseRedirect,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 60 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				MaxIdleConnsPerHost:   8,
				ForceAttemptHTTP2:     true,
			},
		},
	}
}

// refuseRedirect is the http.Client.CheckRedirect policy for the gateway's
// outbound client. It follows NOTHING, on any auth mode, and hands the 3xx back
// to the caller instead.
//
// Leaving CheckRedirect nil — which is what this forwarder did, and what
// `rg CheckRedirect --type go .` found nowhere in the tree — selects the stdlib
// default: follow up to ten hops, REPLAYING the outbound headers on each. On an
// injecting route those headers carry the credential this gateway holds and the
// caller is never shown, so any upstream, or anything able to answer as one,
// could exfiltrate a server-held key by answering 302. Measured on this build
// with the provider and the attacker on DIFFERENT domains, so Go's own
// cross-domain strip was fully in force: the attacker received
// x-api-key="XAPIKEY-SERVER-SECRET" from a single-key header route and
// x-api-key="POOLKEY-SECRET-1" from a pooled one. Authorization survived only
// because net/http happens to strip that ONE header name across a domain change
// — an accident of the standard library rather than a property of this code, and
// no help at all on a same-domain redirect, where the bearer travels too. The
// shipped exa-pool route is exactly the leaking shape: auth header, key_header
// x-api-key.
//
// Three consequences share that single root cause, which is why one line fixes
// all three:
//
//   - EXFILTRATION, above: the gateway's own credential, to a host of the
//     upstream's choosing.
//   - SSRF: an unauthenticated caller drove the gateway to a host named in no
//     configuration and received the body back, while the audit line recorded
//     the CONFIGURED upstream — the forensic record asserted the request had
//     gone where it was supposed to. See AuditEvent.UpstreamHost for the other
//     half of that fix.
//   - SPEND: one caller request became up to nine further upstream round trips
//     inside a single Forward, all charged as one against the budget.
//
// passthrough refuses too, deliberately. The credential replayed there is the
// CALLER's, sent to a host the caller did not choose, and the SSRF and spend
// arguments do not care whose credential is on the wire. There is no per-mode
// exception, so there is no mode whose redirect behaviour has to be reasoned
// about separately.
//
// There is also no same-host exception. It would buy nothing: a same-host
// redirect still multiplies round trips, still charges them as one request, and
// still hands control of the request path to the upstream — and the "same host"
// test would then be a security control implemented in this function, which is
// how the class of bug this fixes gets reintroduced. An upstream that genuinely
// requires a redirect to be followed is a CONFIGURATION change: point the
// route's upstream at the redirect target.
//
// http.ErrUseLastResponse, not an error, because declining to follow is not a
// failure. The upstream answered; the answer was "go there instead", and a proxy
// relays that answer and lets the client decide. A client that follows it does
// so with its own connection and its own credentials, never with this gateway's
// key, which is the entire point. The outcome is not swallowed: handleProxy
// labels the audit line redirect_not_followed.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// redirectNotFollowed reports whether resp is a redirect the gateway declined to
// follow, so the audit stream NAMES that outcome instead of leaving an operator
// to infer it from a status code and the absence of a second event.
//
// The Location test, not the status class alone, is what makes this mean "we
// chose not to go there": 304 Not Modified is a 3xx that names no destination
// and was never a redirect anyone would follow.
func redirectNotFollowed(resp *http.Response) bool {
	if resp == nil || resp.StatusCode < 300 || resp.StatusCode > 399 {
		return false
	}
	return resp.Header.Get("Location") != ""
}

// contactedHost is the host the gateway ACTUALLY reached, read back from the
// request net/http attached to the response rather than from configuration.
//
// Every audit line used to carry rt.Route.Upstream alone: the host an operator
// CONFIGURED, which is the host contacted only for as long as nothing moves the
// connection elsewhere. That is precisely the assumption a redirect breaks, so
// the one event that most needed to say "this went somewhere else" was the one
// event structurally incapable of saying it. Recording both — intent in
// upstream, fact in upstream_host — makes a divergence an assertable and
// alertable signature rather than an invisible one.
//
// Empty when there is no response to read it from (a dial failure) or when a
// substituted Forwarder returned a hand-built response; omitempty then leaves
// those lines exactly as they were.
func contactedHost(resp *http.Response) string {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return ""
	}
	return resp.Request.URL.Host
}

// hopByHop headers are connection-scoped and must not be copied between the
// inbound and outbound connections (RFC 9110 §7.6.1).
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// callerCredentialHeaders is the DENY-SET: header names through which a CALLER
// can present its own upstream credential.
//
// On every auth mode where the gateway supplies the credential, an inbound
// header named here is dropped instead of forwarded. Without that, the provider
// received the caller value alongside the injected key and could honour either
// one — the gateway looked like a credential boundary while being a credential
// ADDER.
//
// It is DATA on purpose, and it is the extension seam for this behaviour:
// onboarding a provider whose key travels in a new header is one line here, not
// an edit to any Authenticator, to the handler, or to the forwarder body.
//
// Entries are matched case-insensitively, so spell them however reads best.
//
// Not every entry is independently provable, and that is recorded here so a
// later reader does not mistake redundancy for coverage. X-Api-Key, Api-Key,
// X-Goog-Api-Key and Cookie are each load-bearing: delete one and a caller
// value reaches the provider (each is mutation-killed by
// credential_strip_test.go). Authorization and Proxy-Authorization are NOT —
// the first is overwritten by bearerInjector and deleted by leasedInjector, the
// second is already dropped by the hopByHop table above. They are kept anyway,
// because those are DIFFERENT layers: a substituted Forwarder, or an edit to
// the hop-by-hop table, removes them and not this one. Two string comparisons
// is a cheap price for a guarantee that does not depend on code elsewhere.
var callerCredentialHeaders = []string{
	"Authorization",       // OpenAI, MiniMax, Qwen — every bearer provider
	"Proxy-Authorization", // also hop-by-hop; listed so the guarantee does not rest on that
	"X-Api-Key",           // Anthropic, Exa, Tavily
	"Api-Key",             // Azure OpenAI
	"X-Goog-Api-Key",      // Google Generative Language
	"Cookie",              // a provider session the caller is already logged into
}

// modesSupplyingTheirOwnCredential is the ALLOW-list of auth modes that carry
// the CALLER credential to the provider on purpose, and must therefore be
// exempt from the deny-set.
//
// It is an allow-list rather than a deny-list so the safe answer is the default
// one: a mode added later strips until someone deliberately exempts it.
var modesSupplyingTheirOwnCredential = map[AuthMode]bool{
	AuthPassthrough: true,
}

// isCallerCredential reports whether an inbound header name carries a caller
// credential, given the route configured key header.
//
// routeKeyHeader extends the static table with whatever the operator named in
// key_header. Mutation check: deleting this clause changes no observable
// behaviour today, because leasedInjector writes that exact header a moment
// later and Header.Set replaces every existing value. It is kept, and pinned by
// a direct predicate test rather than an end-to-end one, so the guarantee is a
// property of the header NAME rather than of the current write order — a future
// Authenticator that writes a different header cannot silently reopen the hole.
func isCallerCredential(name, routeKeyHeader string) bool {
	for _, deny := range callerCredentialHeaders {
		if strings.EqualFold(name, deny) {
			return true
		}
	}
	routeKeyHeader = strings.TrimSpace(routeKeyHeader)
	return routeKeyHeader != "" && strings.EqualFold(name, routeKeyHeader)
}

// Forward rewrites the inbound request onto the route's upstream and executes
// it. The route prefix is stripped, so "/minimax/v1/models" reaches the
// upstream as "/v1/models".
func (f *httpForwarder) Forward(ctx context.Context, req *http.Request, rt *boundRoute) (*http.Response, error) {
	upstreamPath := strings.TrimPrefix(req.URL.Path, strings.TrimSuffix(rt.Route.Prefix, "/"))
	if !strings.HasPrefix(upstreamPath, "/") {
		upstreamPath = "/" + upstreamPath
	}
	target := strings.TrimRight(rt.Route.Upstream, "/") + upstreamPath
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}

	// req.Body is streamed rather than buffered: chat completions can carry
	// large prompts, and buffering them would put the gateway's memory
	// ceiling at the mercy of the caller.
	outReq, err := http.NewRequestWithContext(ctx, req.Method, target, req.Body)
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	// A mode where the GATEWAY holds the credential must not ALSO hand the
	// provider the one the caller brought: a provider that accepts either would
	// let a caller bill its own account, or a stolen one, through this gateway.
	// The exemption is the whole point of passthrough, so it is read from the
	// mode allow-list rather than from a hardcoded comparison here.
	stripCaller := !modesSupplyingTheirOwnCredential[rt.Auth.Mode()]
	for k, vs := range req.Header {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		if stripCaller && isCallerCredential(k, rt.Route.KeyHeader) {
			continue
		}
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Set("User-Agent", "helixchannel-gateway/1")
	// ContentLength must be propagated explicitly: with a streamed body the
	// stdlib would otherwise fall back to chunked encoding, which some
	// upstreams reject on POST /v1/chat/completions.
	outReq.ContentLength = req.ContentLength

	if err := rt.Auth.Apply(outReq); err != nil {
		return nil, fmt.Errorf("apply credentials: %w", err)
	}
	return f.client.Do(outReq)
}

// copyResponse streams an upstream response back to the caller.
//
// It is a thin wrapper over copyResponseObserving so that every existing
// caller and test fake keeps compiling and behaving identically; rotation
// passes a usage extractor through the same path.
func copyResponse(w http.ResponseWriter, resp *http.Response) (int64, error) {
	return copyResponseObserving(w, resp, nil)
}
