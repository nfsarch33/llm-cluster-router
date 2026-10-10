//go:build integration

// End-to-end coverage of the whole nested stack: a plain-HTTP client (Kilo
// Code's shape) → the AESBridge on loopback → TCP → outer TLS → inner
// AES-256-GCM → the gateway AES leg → route match → server-side key injection →
// mock provider. If any layer of the nesting were wrong the request would not
// arrive intact with the injected key, so this one test exercises the feature
// as a user actually runs it.
//
// Run: go test -race -tags integration -run 'TestIT_AESBridge' ./internal/channel/
package channel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIT_AESBridge_FullNestedStackInjectsAndAuthenticates(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	srv := gwAuthServer(t, gwAuthConfig(upstream.URL, tokenEverywhere()), nil)
	key := aesLegTestKey()

	// Gateway AES leg over TCP → TLS(self-signed) → AES.
	cert, _ := selfSignedLoopbackTLS(t)
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen leg: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ServeWrapped(ctx, tlsLn, key) }()
	gwAddr := rawLn.Addr().String()

	// Client-side bridge pointed at the leg (self-signed → skip outer verify;
	// the inner AES is what this test is about).
	bridgeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen bridge: %v", err)
	}
	bridge := &AESBridge{Gateway: gwAddr, Key: key, InsecureSkipVerify: true}
	go func() { _ = bridge.Serve(ctx, bridgeLn) }()
	bridgeAddr := bridgeLn.Addr().String()

	// Kilo-style client: PLAIN HTTP to the loopback bridge, token in a header.
	req, _ := http.NewRequest(http.MethodPost, "http://"+bridgeAddr+"/mm/v1/chat/completions",
		strings.NewReader(`{"model":"MiniMax-M3","messages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-placeholder")
	req.Header.Set(GatewayTokenHeader, gwAuthToken)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request through bridge failed: %v", err)
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
		t.Errorf("upstream Authorization = %q, want server-held key (injection failed across the stack)", got)
	}
	if strings.Contains(seen.Get("Authorization"), "placeholder") {
		t.Error("placeholder reached the provider through the nested stack")
	}
}

// TestIT_AESBridge_RefusesNonLoopbackListen pins the guard that the
// unencrypted client→bridge hop cannot be bound off-host.
func TestIT_AESBridge_RefusesNonLoopbackListen(t *testing.T) {
	t.Parallel()
	bridge := &AESBridge{Listen: "0.0.0.0:0", Gateway: "edge.example.com:8444", Key: aesLegTestKey()}
	err := bridge.ListenAndServe(context.Background())
	if err == nil {
		t.Fatal("expected a refusal binding a non-loopback listen, got nil")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error = %v, want a loopback refusal", err)
	}
}
