// Package observability redaction helper for ADR-083 Lightsail
// release readiness (C5).
//
// Scope (v18710-2): Redact() returns a copy of AgentraceEvent with
// any string field scrubbed of known sensitive patterns. The shipped
// AgentraceAppender.Encode path does NOT call Redact() today; this
// helper is wired in by v18710-4 (tampering-detector + binary
// post-condition). The unit test (redaction_test.go) exercises the
// helper directly so the pattern coverage is locked in.
//
// Owner: cursor-parent@win3-wsl3 (v18710-2).
// Machine-Id: win3-wsl3.
package observability

import "strings"

// redactionPatterns is the ordered list of (name, needle) pairs that
// trigger [REDACTED-<name>] substitution. Order matters because the
// longest pattern (OpenAI project keys, 56+ chars) must be checked
// before the shorter fallback (sk-...). The AWS AKIA pattern is the
// 20-char access key id; the example fixture is `AKIAIOSFODNN7EXAMPLE`
// (canonical allowlisted example per
// cursor-config/rules/00-pii-credential-guardrail.md).
var redactionPatterns = []struct {
	name    string
	pattern string
}{
	{"ghp", "ghp_"},
	{"sk", "sk-"},
	{"ops_eyJ", "ops_eyJ"},
	{"akia", "AKIA"},
}

// Redact returns a copy of ev with each string field scrubbed of any
// known sensitive pattern. The replacement is `[REDACTED-<name>]`,
// which preserves enough context for an operator to know what was
// removed without leaking the secret itself.
func Redact(ev AgentraceEvent) AgentraceEvent {
	out := ev
	out.TS = scrub(out.TS)
	out.Event = scrub(out.Event)
	out.Listener = scrub(out.Listener)
	out.RemoteAddr = scrub(out.RemoteAddr)
	return out
}

// scrub applies the redaction patterns to a single string and
// returns the result. Patterns are matched as substrings (no regex)
// for hermetic, deterministic behavior in unit tests.
func scrub(s string) string {
	if s == "" {
		return s
	}
	for _, p := range redactionPatterns {
		if strings.Contains(s, p.pattern) {
			return strings.ReplaceAll(s, p.pattern, "[REDACTED-"+p.name+"]")
		}
	}
	return s
}
