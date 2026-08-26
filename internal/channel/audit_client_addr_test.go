package channel

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// auditClientAddr is an OBSERVABILITY function wearing a security-critical
// neighbourhood: it lives in proxy_auth.go, reads a peer address, and honours
// a header under a condition. Every test in this file exists to prove one of
// two things about it — that it changes AUDIT LOGGING and nothing else, or
// that admission is unaffected by trust_forwarded_for_audit no matter what
// the caller sends. A test that only checked the log line and never re-drove
// authorizeProxy would leave the actual risk (a caller talking its way into
// the loopback exemption) completely unproven.
// ---------------------------------------------------------------------------

func TestAuditClientAddr_Unit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		trust bool
		peer  string
		xff   string
		want  string
	}{
		{"trust off, loopback peer, valid XFF -> peer wins", false, gwAuthLoopback, "198.51.100.9", gwAuthLoopback},
		{"trust on, non-loopback peer, valid XFF -> peer wins", true, gwAuthRemotePeer, "198.51.100.9", gwAuthRemotePeer},
		{"trust on, loopback peer, no XFF -> peer wins", true, gwAuthLoopback, "", gwAuthLoopback},
		{"trust on, loopback peer, unparseable XFF -> peer wins (fail closed)", true, gwAuthLoopback, "not-an-ip", gwAuthLoopback},
		{"trust on, loopback peer, valid XFF -> XFF wins", true, gwAuthLoopback, "198.51.100.9", "198.51.100.9"},
		{"trust on, loopback peer, chained XFF -> FIRST entry wins", true, gwAuthLoopback, "198.51.100.9, 10.0.0.5, 127.0.0.1", "198.51.100.9"},
		{"trust on, loopback8 peer, valid XFF -> XFF wins", true, gwAuthLoopback8, "198.51.100.9", "198.51.100.9"},
		{"trust on, loopbackV6 peer, valid XFF -> XFF wins", true, gwAuthLoopbackV6, "2001:db8::1", "2001:db8::1"},
		{"trust on, loopback peer, whitespace-only XFF -> peer wins", true, gwAuthLoopback, "   ", gwAuthLoopback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &Server{trustForwardedForAudit: tc.trust}
			req := httptest.NewRequest("GET", "/mm/v1/models", nil)
			req.RemoteAddr = tc.peer
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := s.auditClientAddr(req); got != tc.want {
				t.Errorf("auditClientAddr() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAuditClientAddr_NeverInfluencesAdmission is the security-boundary
// regression test. It proves the property the doc comments assert:
// trust_forwarded_for_audit and X-Forwarded-For cannot move the admission
// decision in EITHER direction.
//
//  1. A non-loopback caller cannot buy the loopback exemption by spoofing
//     X-Forwarded-For: 127.0.0.1, even with trust_forwarded_for_audit: true.
//  2. A genuinely loopback caller's exemption is unaffected by a hostile or
//     malformed X-Forwarded-For value — admission never reads it either way.
//
// If this test is ever green with admission reading auditClientAddr instead
// of r.RemoteAddr directly, it has stopped proving anything; that is exactly
// the regression it exists to catch.
func TestAuditClientAddr_NeverInfluencesAdmission(t *testing.T) {
	t.Parallel()
	upstream, probe := newGWAuthUpstream(t)
	cfg := gwAuthConfig(upstream.URL, tokenExempt())
	cfg.TrustForwardedForAudit = true
	srv := gwAuthServer(t, cfg, nil)

	t.Run("non-loopback caller cannot spoof its way to the exemption", func(t *testing.T) {
		rec := gwAuthCall(t, srv, gwAuthRemotePeer, map[string]string{"X-Forwarded-For": "127.0.0.1"})
		if rec.Code != 401 {
			t.Fatalf("status = %d, want 401 — a spoofed X-Forwarded-For must not grant the loopback exemption", rec.Code)
		}
		if got := gwAuthErrorCode(t, rec); got != string(refusalTokenRequired) {
			t.Errorf("error = %q, want %q", got, refusalTokenRequired)
		}
		if hits, _ := probe.seen(); hits != 0 {
			t.Errorf("upstream contacted %d times; a spoofed exemption must be refused before any upstream call", hits)
		}
	})

	t.Run("genuine loopback caller keeps its exemption regardless of a hostile XFF", func(t *testing.T) {
		rec := gwAuthCall(t, srv, gwAuthLoopback, map[string]string{"X-Forwarded-For": "not-an-ip, also garbage"})
		if rec.Code != 200 {
			t.Fatalf("status = %d, want 200 — a malformed X-Forwarded-For must not cost a genuine loopback caller its exemption", rec.Code)
		}
	})
}

// TestAuditClientAddr_LogReflectsRealCallerBehindTrustedRelay is the positive
// case end to end: with the option enabled, the audit line for a request
// relayed through a same-host terminator names the real caller, not the
// terminator's own loopback connection — which is the whole reason the
// option exists (see the CHANGELOG entry it shipped with).
func TestAuditClientAddr_LogReflectsRealCallerBehindTrustedRelay(t *testing.T) {
	t.Parallel()
	upstream, _ := newGWAuthUpstream(t)
	cfg := gwAuthConfig(upstream.URL, tokenExempt())
	cfg.TrustForwardedForAudit = true
	var audit bytes.Buffer
	srv := gwAuthServer(t, cfg, &audit)

	rec := gwAuthCall(t, srv, gwAuthLoopback, map[string]string{"X-Forwarded-For": "203.0.113.44"})
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	line := strings.TrimSpace(audit.String())
	if line == "" {
		t.Fatalf("no audit line written")
	}
	var event struct {
		ClientAddr string `json:"client_addr"`
	}
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("decode audit line: %v (%q)", err, line)
	}
	if event.ClientAddr != "203.0.113.44" {
		t.Errorf("audit client_addr = %q, want the real caller %q, not the relay's own loopback connection",
			event.ClientAddr, "203.0.113.44")
	}
}

// TestAuditClientAddr_LogKeepsPeerAddrWhenOptionIsOff is the default-safe
// case: with trust_forwarded_for_audit left at its zero value (false), the
// audit line MUST NOT change behaviour at all, including under a same-host
// relay shape. This is what makes the option opt-in rather than a silent
// behaviour change for every existing loopback-fronted deployment.
func TestAuditClientAddr_LogKeepsPeerAddrWhenOptionIsOff(t *testing.T) {
	t.Parallel()
	upstream, _ := newGWAuthUpstream(t)
	cfg := gwAuthConfig(upstream.URL, tokenExempt()) // TrustForwardedForAudit left false
	var audit bytes.Buffer
	srv := gwAuthServer(t, cfg, &audit)

	rec := gwAuthCall(t, srv, gwAuthLoopback, map[string]string{"X-Forwarded-For": "203.0.113.44"})
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var event struct {
		ClientAddr string `json:"client_addr"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(audit.String())), &event); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	if event.ClientAddr != gwAuthLoopback {
		t.Errorf("audit client_addr = %q, want the raw peer %q with the option off", event.ClientAddr, gwAuthLoopback)
	}
}
