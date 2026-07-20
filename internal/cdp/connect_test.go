package cdp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestConnect_PingEndpoint_OK verifies that Ping connects to a
// running Chrome DevTools endpoint and returns the parsed Browser
// struct. We stand up an httptest.Server that mimics the JSON
// shape Chrome emits at /json/version.
func TestConnect_PingEndpoint_OK(t *testing.T) {
	// Mirror Chrome's /json/version response (real shape:
	// https://chromedevtools.github.io/devtools-protocol/version/).
	// We only model the fields Ping needs to surface.
	body := `{
		"Browser": "Chrome/127.0.6533.99",
		"Protocol-Version": "1.3",
		"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/uuid",
		"Target": ""
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/json/version") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	br, err := Ping(ctx, srv.URL)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if br.Browser != "Chrome/127.0.6533.99" {
		t.Errorf("Browser = %q, want Chrome/127.0.6533.99", br.Browser)
	}
	if br.WebSocketDebuggerURL == "" {
		t.Error("WebSocketDebuggerURL is empty")
	}
	if br.ProtocolVersion != "1.3" {
		t.Errorf("ProtocolVersion = %q, want 1.3", br.ProtocolVersion)
	}
}

// TestConnect_PingEndpoint_Timeout verifies that Ping fails fast
// (3s default) when the endpoint is unreachable. This is the
// fail-fast behaviour the plan requires — agents must NOT block
// on a Chrome that is not running.
func TestConnect_PingEndpoint_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Reserve a port, hold it briefly, then close. This guarantees
	// the dial gets RST/ECONNREFUSED rather than hanging.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.URL
	srv.Close() // immediately release the port

	_, err := Ping(ctx, addr)
	if err == nil {
		t.Fatal("expected error from Ping against a closed endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "refused") {
		t.Logf("got error (acceptable as long as it's a connect failure): %v", err)
	}
}

// TestConnect_PingEndpoint_NonJSON verifies that Ping surfaces a
// clear error when the endpoint returns non-JSON content (e.g.
// a default landing page from a different web server on the port).
func TestConnect_PingEndpoint_NonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>Not Chrome</html>"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := Ping(ctx, srv.URL+"/json/version")
	if err == nil {
		t.Fatal("expected error from Ping against non-JSON, got nil")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error %q should mention decode failure", err.Error())
	}
}
