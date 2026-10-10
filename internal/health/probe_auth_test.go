package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// gatedServer answers 200 on every path only when the request carries
// header == want; otherwise 401. This is the shape of a token-gated
// egress gateway, where even the models/health listing is behind auth.
func gatedServer(t *testing.T, header, want string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(header) != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestProbeNodeAuth_SendsConfiguredHeader(t *testing.T) {
	srv := gatedServer(t, "X-HLXN-Token", "gw-secret")
	defer srv.Close()

	base := mustParse(t, srv.URL)
	if !ProbeNodeAuth(context.Background(), time.Second, "/health", base, "X-HLXN-Token", "gw-secret") {
		t.Fatal("probe with the configured header should pass a token-gated upstream")
	}
}

func TestProbeNodeAuth_WrongTokenFails(t *testing.T) {
	srv := gatedServer(t, "X-HLXN-Token", "gw-secret")
	defer srv.Close()

	base := mustParse(t, srv.URL)
	if ProbeNodeAuth(context.Background(), time.Second, "/health", base, "X-HLXN-Token", "nope") {
		t.Fatal("probe with a wrong token must fail")
	}
}

func TestProbeNode_UnchangedWithoutAuth(t *testing.T) {
	// A token-gated upstream refuses the legacy no-auth probe: this is
	// the exact behaviour that motivates ProbeNodeAuth, pinned so a
	// future "helpfully" auth-injecting default cannot sneak in.
	srv := gatedServer(t, "X-HLXN-Token", "gw-secret")
	defer srv.Close()

	base := mustParse(t, srv.URL)
	if ProbeNode(context.Background(), time.Second, "/health", base) {
		t.Fatal("legacy ProbeNode must not invent credentials")
	}
}

func TestProbeNodeAuth_EmptyHeaderNameDegradesToLegacy(t *testing.T) {
	// header name "" means "no auth configured" -- same request shape as
	// ProbeNode, so an open upstream still probes fine.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	base := mustParse(t, srv.URL)
	if !ProbeNodeAuth(context.Background(), time.Second, "/health", base, "", "ignored") {
		t.Fatal("empty header name should behave exactly like ProbeNode")
	}
}
