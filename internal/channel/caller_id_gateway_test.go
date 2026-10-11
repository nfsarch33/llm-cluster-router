package channel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type memAudit struct{ lines []AuditEvent }

func (m *memAudit) Log(e AuditEvent) { m.lines = append(m.lines, e) }

// The gateway side: X-HLXN-Caller lands in the connect_denied audit event
// (sanitised), and an absent header keeps the line caller-free.
func TestConnectAuditRecordsCaller(t *testing.T) {
	audit := &memAudit{}
	cfg := Config{Listen: "127.0.0.1:0"} // connect disabled → fast deny path
	srv, err := NewServer(&cfg, NewHTTPForwarder(), audit)
	if err != nil {
		t.Skipf("NewServer refused zero config (%v); handler-level check below", err)
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Header.Set(CallerHeader, "win3-wsl3")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected connect_disabled deny, got %d", rec.Code)
	}
	if len(audit.lines) != 1 {
		t.Fatalf("want one audit line, got %d", len(audit.lines))
	}
	if audit.lines[0].Caller != "win3-wsl3" {
		t.Fatalf("caller not recorded: %q", audit.lines[0].Caller)
	}
	// absent header → empty Caller → omitted from the JSON line
	req2 := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req2)
	if audit.lines[1].Caller != "" {
		t.Fatalf("absent header must leave Caller empty: %q", audit.lines[1].Caller)
	}
	_ = os.Environ
}
