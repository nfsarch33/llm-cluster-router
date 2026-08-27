//go:build integration

// TestIT_AuthHeaderNode -- v18774 end-to-end pin for auth_header nodes.
//
// The upstream here is shaped like a token-gated egress gateway: EVERY
// path (health, models, completions) answers 401 unless the request
// carries the gateway token in its dedicated header, and completions
// additionally refuse any request that still carries an Authorization
// header at all (a passthrough-style gateway would forward it to the
// provider, so the correct number of Authorization headers arriving at
// the gateway is zero).
//
// That shape makes the test self-enforcing at three layers:
//   - if the HEALTH probe does not inject the header, the node never
//     becomes healthy and setup fails;
//   - if the PROXY does not inject the header, the completion is 401;
//   - if the proxy injects but does not SCRUB the caller's router
//     token, the completion is 403.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func itMockGatedGateway(t *testing.T, header, token string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	gate := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(header) != token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/health", gate(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/v1/models", gate(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"object":"list","data":[{"id":"MiniMax-M3","object":"model"}]}`)
	}))
	mux.HandleFunc("/v1/chat/completions", gate(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			// The caller's router token must never reach the gateway.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chatcmpl-it","object":"chat.completion","model":"MiniMax-M3","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	return httptest.NewServer(mux)
}

func TestIT_AuthHeaderNodeInjectsGatewayTokenAndScrubsCallerAuth(t *testing.T) {
	var hits atomic.Int64
	gw := itMockGatedGateway(t, "X-HLXN-Token", "gw-secret", &hits)
	defer gw.Close()

	// itSetupRouter's default nodes carry no auth config; override the
	// generated node with the gateway auth shape.
	srv, _ := itSetupRouter(t, []*httptest.Server{gw}, func(c *config) {
		c.Nodes[0].Models = []string{"MiniMax-M3"}
		c.Nodes[0].APIKey = "gw-secret"
		c.Nodes[0].AuthHeader = "X-HLXN-Token"
	})

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"MiniMax-M3","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The caller authenticates to the ROUTER; this must not leak upstream.
	req.Header.Set("Authorization", "Bearer caller-router-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion status = %d, want 200 (401=header not injected, 403=Authorization leaked)", resp.StatusCode)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("gateway completions hit %d times, want 1", got)
	}
}
