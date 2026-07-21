package proxy

import "net/http"

// HelixChannel is the public, additive naming artifact shipped in
// v18712-1. It carries:
//
//   - a single response header "HelixChannel-Version" stamped on
//     every response so operators can prove the binary name without
//     re-reading the source tree;
//   - a stable channel identifier "HelixChannel" used in logs and
//     metric labels alongside the legacy "aes-mtls" listener tag.
//
// HelixChannel is the operator-facing name for the
// AES-256-GCM application-layer encryption channel introduced
// incrementally across v18704-v18710 and standardised by ADR-085.
// See the README "HelixChannel (encrypted dual-listener)" section
// for the full design.
const (
	// HelixChannelVersion is the response header value stamped by
	// WithHelixChannelHeader. It is the public proof-of-name for
	// the v18712 release and is bumped in lock-step with the
	// sprint id.
	HelixChannelVersion = "v18712-1"

	// HelixChannelHeader is the canonical response header name.
	// Tools that do not know about the header will ignore it.
	HelixChannelHeader = "HelixChannel-Version"
)

// WithHelixChannelHeader wraps next with a noop middleware that
// stamps the HelixChannel-Version response header on every reply.
// The wrapper preserves the wrapped handler's status code, body,
// and any other headers the inner handler set (e.g. Cache-Control
// or a custom X-Foo).
//
// This is additive: callers that do not install the middleware
// keep the original behaviour, and operators can verify the
// HelixChannel name in production by `curl -I https://host/`.
func WithHelixChannelHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HelixChannelHeader, HelixChannelVersion)
		next.ServeHTTP(w, r)
	})
}
