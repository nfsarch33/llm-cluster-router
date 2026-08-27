// v18774 -- unit tests for setUpstreamAuth, the one place outbound
// upstream credentials are attached.
//
// The function exists because doUpstream copies EVERY inbound header to
// the upstream request, including the caller's "Authorization: Bearer
// <router token>". On the default path that is overwritten by the
// node's own Bearer key. On the auth_header path nothing would
// overwrite it, so without an explicit scrub the router's OWN client
// token would leak to the upstream on every request -- and a key-pool
// exhaustion (Next() returning "") would leak it even on the default
// path's miss branch. These tests pin the scrub in all branches.
package main

import (
	"net/http"
	"testing"
)

func TestSetUpstreamAuth_DefaultBearerReplacesCallerToken(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer caller-router-token")

	setUpstreamAuth(h, "", "node-key")

	if got := h.Get("Authorization"); got != "Bearer node-key" {
		t.Fatalf("Authorization = %q, want the node's Bearer key", got)
	}
}

func TestSetUpstreamAuth_CustomHeaderScrubsAuthorization(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer caller-router-token")

	setUpstreamAuth(h, "X-HLXN-Token", "gw-secret")

	if got := h.Get("X-HLXN-Token"); got != "gw-secret" {
		t.Fatalf("X-HLXN-Token = %q, want gw-secret", got)
	}
	if got := h.Get("Authorization"); got != "" {
		t.Fatalf("caller Authorization leaked upstream: %q", got)
	}
}

func TestSetUpstreamAuth_CustomHeaderOverridesSpoofedInbound(t *testing.T) {
	// A caller may try to smuggle its own gateway token past the router.
	h := http.Header{}
	h.Set("X-HLXN-Token", "attacker-supplied")

	setUpstreamAuth(h, "X-HLXN-Token", "gw-secret")

	if vals := h.Values("X-HLXN-Token"); len(vals) != 1 || vals[0] != "gw-secret" {
		t.Fatalf("X-HLXN-Token values = %v, want exactly [gw-secret]", vals)
	}
}

func TestSetUpstreamAuth_EmptyKeyStillScrubsEverything(t *testing.T) {
	// Key pool exhausted (every key cooling): the request must go out
	// with NO credential at all -- neither the caller's router token nor
	// a stale spoofed gateway header.
	h := http.Header{}
	h.Set("Authorization", "Bearer caller-router-token")
	h.Set("X-HLXN-Token", "attacker-supplied")

	setUpstreamAuth(h, "X-HLXN-Token", "")

	if got := h.Get("Authorization"); got != "" {
		t.Fatalf("Authorization leaked on empty key: %q", got)
	}
	if got := h.Get("X-HLXN-Token"); got != "" {
		t.Fatalf("spoofed gateway header survived on empty key: %q", got)
	}
}

func TestSetUpstreamAuth_DefaultPathEmptyKeyLeavesCallerAuth(t *testing.T) {
	// Pinned EXISTING behaviour for keyless local nodes (no auth_header,
	// no api_key): the caller's bearer passes through untouched, which is
	// how tools authenticate to local llama-server style upstreams today.
	h := http.Header{}
	h.Set("Authorization", "Bearer caller-token")

	setUpstreamAuth(h, "", "")

	if got := h.Get("Authorization"); got != "Bearer caller-token" {
		t.Fatalf("keyless default path must not touch Authorization, got %q", got)
	}
}
