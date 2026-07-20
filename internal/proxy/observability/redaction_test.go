// Package observability redaction tests for ADR-083 Lightsail
// release readiness.
//
// Scope (v18710-2): ADR-083 C5 — upstream payload bytes that contain
// user PII or secrets MUST NOT appear verbatim in any agentrace
// NDJSON event unless redaction is applied first.
//
// The shipped AgentraceAppender (observability.go) emits
// AgentraceEvent via json.Encoder.Encode. There is no redaction
// today; v18710-2 adds a `Redact()` helper that scrubs known
// sensitive patterns before encoding.
//
// Owner: cursor-parent@win3-wsl3 (v18710-2).
// Machine-Id: win3-wsl3.
package observability

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// secretFixtures are byte sequences that MUST be redacted before
// any NDJSON event hits disk. These mirror the patterns documented
// in cursor-config/rules/drl-8.20-r7-credential-redaction.md
// (GitHub PATs, OpenAI/Anthropic API keys, 1Password service-account
// JWTs, AWS access key IDs).
var secretFixtures = []string{
	"ghp_FIXTURE_NOT_REAL_ghp_TOKEN_REPLACE_BEFORE_PUSH",   // GitHub PAT-shape (FIXTURE_NOT_REAL avoids secret-scanner)
	"sk-proj-FIXTURE_NOT_REAL_KEY_REPLACE_BEFORE_PUSH",     // OpenAI project key-shape (FIXTURE_NOT_REAL)
	"AKIAIOSFODNN7EXAMPLE",                                 // AWS access key ID (canonical allowlisted example)
	"ops_eyJ_FIXTURE_NOT_REAL_JWT_REPLACE_BEFORE_PUSH.sig", // 1Password service-account JWT-shape (FIXTURE_NOT_REAL)
}

// TestAgentraceRedaction_StripsSecretsFromEvent verifies that when
// an AgentraceEvent contains a secret-bearing string (here: in the
// Listener field as a stand-in for any text-bearing field), the
// emitted NDJSON does NOT contain the secret verbatim.
func TestAgentraceRedaction_StripsSecretsFromEvent(t *testing.T) {
	// Build a buffer + encoder mirroring NewAgentraceAppender's
	// internals, but writing to a buffer instead of a file so we
	// can inspect the bytes directly.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	for _, secret := range secretFixtures {
		buf.Reset()
		ev := AgentraceEvent{
			TS:       "2026-07-21T07:30:00+10:00",
			Event:    "test_redaction",
			Listener: "socks5",
		}
		// Inject the secret via the Listener field as a proxy for
		// "any text-bearing field that might carry upstream payload".
		// We expect Redact() to scrub it before Encode().
		ev.Listener = secret
		scrubbed := Redact(ev)
		if err := enc.Encode(&scrubbed); err != nil {
			t.Fatalf("Encode: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, secret) {
			t.Errorf("C5 violated: secret %q appeared verbatim in NDJSON output: %s", secret, out)
		}
		// Sanity: the redacted placeholder should appear instead.
		if !strings.Contains(out, "[REDACTED") {
			t.Errorf("expected [REDACTED placeholder in output, got: %s", out)
		}
	}
}

// TestAgentraceRedaction_LeavesBenignStringsAlone verifies that the
// redaction is conservative — non-sensitive strings pass through
// unchanged so the operator's audit trail stays useful.
func TestAgentraceRedaction_LeavesBenignStringsAlone(t *testing.T) {
	ev := AgentraceEvent{
		TS:         "2026-07-21T07:30:00+10:00",
		Event:      "test_benign",
		Listener:   "socks5",
		RemoteAddr: "127.0.0.1:54321",
	}
	scrubbed := Redact(ev)
	if scrubbed.Listener != "socks5" {
		t.Errorf("Listener = %q, want socks5 (benign string was over-redacted)", scrubbed.Listener)
	}
	if scrubbed.RemoteAddr != "127.0.0.1:54321" {
		t.Errorf("RemoteAddr = %q, want 127.0.0.1:54321 (benign string was over-redacted)", scrubbed.RemoteAddr)
	}
}
