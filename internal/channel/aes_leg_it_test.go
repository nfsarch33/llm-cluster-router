//go:build integration

// Integration coverage for the AES-256-GCM leg (ServeWrapped): the second
// listener that carries the same reverse-proxy routes with application-layer
// AES nested inside the transport. These run over a REAL loopback listener the
// client reaches through a crypto.Wrap'd conn, because the properties under
// test — that HTTP survives the AES transport, that gateway_auth is enforced on
// this leg exactly as on the plain leg, and that the pre-shared key is
// load-bearing — cannot be seen by a handler-level test.
//
// Run: go test -race -tags integration -run 'TestIT_AESLeg' ./internal/channel/
package channel

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// aesLegTestKey is a distinct non-zero 32-byte key for the AES-leg tests.
func aesLegTestKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(0xA5 ^ i)
	}
	return k
}

// serveAESLeg binds a loopback listener and serves srv's AES leg over it with
// the given key, returning the address to dial. tokenEverywhere() is used by
// callers so the loopback client is not exempt and the token is actually
// exercised on this leg.
func serveAESLeg(t *testing.T, srv *Server, key [32]byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen aes leg: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ServeWrapped(ctx, ln, key) }()
	return ln.Addr().String()
}

// aesDialClient returns an http.Client whose transport dials addr over TCP and
// AES-wraps the connection with key, so http speaks over the encrypted stream.
// Keep-alives are disabled so each request is an independent, freshly-wrapped
// conn — a wrong-key conn cannot be reused to poison a later assertion.
func aesDialClient(addr string, key [32]byte) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				c, err := d.DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				return crypto.Wrap(c, key), nil
			},
		},
	}
}

// TestIT_AESLeg_TokenAuthAndInjectionOverAES proves the AES leg is functionally
// identical to the reverse-proxy leg: with the gateway token a request routes,
// the server-held key is injected, the placeholder never reaches the provider,
// and the token authenticates this hop only — all carried over AES. Without the
// token the request is refused 401 and never reaches the provider.
func TestIT_AESLeg_TokenAuthAndInjectionOverAES(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)
	key := aesLegTestKey()
	addr := serveAESLeg(t, srv, key)
	client := aesDialClient(addr, key)

	// With the token: routes, injects, succeeds.
	req, _ := http.NewRequest(http.MethodPost, "http://aes-leg/mm/v1/chat/completions",
		strings.NewReader(`{"model":"MiniMax-M3","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-placeholder")
	req.Header.Set(GatewayTokenHeader, gwAuthToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authorised request over AES failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", resp.StatusCode, body)
	}
	hits, seen := probe.seen()
	if hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}
	if got := seen.Get("Authorization"); got != "Bearer "+gwAuthRouteKey {
		t.Errorf("upstream Authorization = %q, want server-held key", got)
	}
	if strings.Contains(seen.Get("Authorization"), "placeholder") {
		t.Error("client placeholder reached the provider over the AES leg")
	}
	if got := seen.Get(GatewayTokenHeader); got != "" {
		t.Errorf("upstream saw %s = %q; the token authenticates this hop only", GatewayTokenHeader, got)
	}

	// Without the token: refused, provider never touched.
	noTok, _ := http.NewRequest(http.MethodPost, "http://aes-leg/mm/v1/chat/completions",
		strings.NewReader(`{"model":"MiniMax-M3","messages":[]}`))
	noTok.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(noTok)
	if err != nil {
		t.Fatalf("anonymous request over AES failed to complete: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp2.StatusCode)
	}
	if hits, _ := probe.seen(); hits != 1 {
		t.Fatalf("upstream hits = %d after anonymous call, want still 1", hits)
	}
}

// TestIT_AESLeg_WrongKeyCannotSpeak proves the pre-shared key is load-bearing:
// a client that AES-wraps with the wrong key cannot form a request the server
// will accept — the server's decrypt fails, the connection is dropped, and the
// provider is never reached. Confidentiality of the leg rests on the key, not
// on the outer transport.
func TestIT_AESLeg_WrongKeyCannotSpeak(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)
	key := aesLegTestKey()
	addr := serveAESLeg(t, srv, key)

	var wrong [32]byte
	for i := range wrong {
		wrong[i] = byte(i + 1) // different from aesLegTestKey
	}
	client := aesDialClient(addr, wrong)

	req, _ := http.NewRequest(http.MethodPost, "http://aes-leg/mm/v1/chat/completions",
		strings.NewReader(`{"model":"MiniMax-M3","messages":[]}`))
	req.Header.Set(GatewayTokenHeader, gwAuthToken) // even WITH the token, wrong key = no request
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("wrong-key client got a response (status %d); the key must gate the leg", resp.StatusCode)
	}
	if hits, _ := probe.seen(); hits != 0 {
		t.Fatalf("upstream hits = %d, want 0 (a wrong-key caller must never reach the provider)", hits)
	}
}
