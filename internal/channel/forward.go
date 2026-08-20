package channel

import (
	"context"
	"fmt"
	"io"
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
	for k, vs := range req.Header {
		if hopByHop[strings.ToLower(k)] {
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

// copyResponse streams an upstream response back to the caller, preserving
// status and headers and flushing incrementally so streamed completions
// arrive as they are produced rather than at the end.
func copyResponse(w http.ResponseWriter, resp *http.Response) (int64, error) {
	for k, vs := range resp.Header {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, canFlush := w.(http.Flusher)
	if !canFlush {
		return io.Copy(w, resp.Body)
	}
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			written, werr := w.Write(buf[:n])
			total += int64(written)
			flusher.Flush()
			if werr != nil {
				return total, werr
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
