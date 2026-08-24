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
// key_header. It is belt and braces on today code — leasedInjector overwrites
// that exact header a moment later — but it keeps the guarantee true of the
// NAME rather than of the current write order, so a future Authenticator that
// writes a different header cannot silently reopen the hole.
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
