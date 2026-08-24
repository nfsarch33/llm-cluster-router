//go:build integration

// Package channel integration cover for P1/R6.
//
// The unit suite drives Server.Handler directly with an httptest.Recorder. This
// file proves the same property over real TCP with a real net/http client, so
// nothing about header canonicalisation, the wire format or the recorder can be
// what makes the guarantee hold.
//
// Run: go test -race -tags integration -run TestIT_ ./internal/channel/
package channel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestIT_GatewayNeverForwardsACallerCredentialHeaderOverTheWire replays the
// shipped deploy/helixchannel/gateway.example.yml shape — auth: header with
// key_header: x-api-key, the exa-pool/tavily spelling — and has the caller
// present a COMPETING provider credential in every other credential header.
func TestIT_GatewayNeverForwardsACallerCredentialHeaderOverTheWire(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	}))
	defer upstream.Close()

	srv := credStripServer(t, upstream.URL, Route{
		Name: "exa", Auth: AuthHeaderInject, KeyHeader: "x-api-key",
		KeyFile: writeKeyFile(t, t.TempDir(), "exa.key", "gateway-exa-not-real\n"),
	})
	gateway := httptest.NewServer(srv.Handler())
	defer gateway.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gateway.URL+"/x/search", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for _, p := range credStripProbes {
		req.Header.Set(p.header, p.value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gateway status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	observed := seen
	mu.Unlock()
	if observed == nil {
		t.Fatal("upstream saw no request")
	}
	if leaks := credStripLeaks(observed); len(leaks) > 0 {
		t.Errorf("caller credentials crossed the gateway to the provider: %v\n"+
			"every one of these was sent on a single request, so the leak is not order-dependent", leaks)
	}
	if got := observed.Values("X-Api-Key"); len(got) != 1 || got[0] != "gateway-exa-not-real" {
		t.Errorf("upstream X-Api-Key = %v, want exactly one gateway credential", got)
	}
	if got := observed.Get("User-Agent"); !strings.HasPrefix(got, "helixchannel-gateway/") {
		t.Errorf("upstream User-Agent = %q, want the gateway one; the request must still be a normal forward", got)
	}
}
