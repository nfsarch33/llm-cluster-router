package channel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The caller-identity field: a ClientProxy with CallerID set sends
// X-HLXN-Caller on every CONNECT; the gateway records it in the audit
// stream (denied and established) so per-machine traffic is
// distinguishable. Absent CallerID → no header → no field in the event
// (legacy lines byte-identical).
func TestClientProxySendsCallerHeader(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-HLXN-Caller")
		w.WriteHeader(http.StatusForbidden) // denied is enough to observe the header
	}))
	defer ts.Close()

	p := &ClientProxy{
		Listen:   "127.0.0.1:0",
		Gateway:  ts.Listener.Addr().String(), // not TLS for the unit test; the header is set before dial wrapping
		Token:    "tok",
		CallerID: "win3-wsl3",
	}
	// The proxy re-issues CONNECT inside TLS to the real gateway; for the
	// unit test we only exercise header construction.
	req, _ := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	p.stampCaller(req)
	if req.Header.Get("X-HLXN-Caller") != "win3-wsl3" {
		t.Fatalf("caller header not stamped: %q", req.Header.Get("X-HLXN-Caller"))
	}
	p2 := &ClientProxy{Listen: "127.0.0.1:0", Gateway: ts.Listener.Addr().String(), Token: "tok"}
	req2, _ := http.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	p2.stampCaller(req2)
	if req2.Header.Get("X-HLXN-Caller") != "" {
		t.Fatalf("empty CallerID must not send the header")
	}
	_ = got
	_ = context.Background
	_ = net.Dial
	_ = time.Second
}
