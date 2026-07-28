// Tests for the HelixChannel hostname resolution helper added in
// v18714-11. The hostname `helixchannel.example.com` is the
// canonical public identity of the production wire (DNS A-record
// managed via DreamHost, TLS via Let's Encrypt on the Lightsail
// host). The helper exposes a precedence chain:
//
//  1. HELIXCHANNEL_BASE_URL env var (always wins)
//  2. --base-url flag (when fs.String is bound)
//  3. Default fallback `https://helixchannel.example.com`
//
// Tests pin the chain so a future refactor cannot silently change
// precedence or drop the default. The default is the binding contract
// for the v18714-11 story — replacing it requires a coordinated DNS +
// TLS rollover, not an arbitrary code change.
//
// Anti-shell-leak: the helper never echoes HELIXCHANNEL_KEY, never
// embeds credentials in URLs, and never logs the resolved URL to
// stderr (only return-value path).
package cli

import (
	"testing"
)

// TestResolveHelixChannelBaseURL_DefaultWhenEnvAndFlagEmpty asserts
// the canonical fallback when neither the env var nor the flag is
// set. This is the primary operator-facing path: `helixchannel
// endpoint-check` should "just work" against
// https://helixchannel.example.com without flags.
func TestResolveHelixChannelBaseURL_DefaultWhenEnvAndFlagEmpty(t *testing.T) {
	t.Setenv(EnvHelixChannelBaseURL, "")
	got := ResolveHelixChannelBaseURL("")
	want := DefaultHelixChannelBaseURL
	if got != want {
		t.Fatalf("ResolveHelixChannelBaseURL(\"\") = %q, want %q", got, want)
	}
}

// TestResolveHelixChannelBaseURL_FlagOverridesDefault asserts the
// --base-url flag wins over the default. This is the per-call
// override path:
// `helixchannel endpoint-check --base-url https://203.0.113.10`
// for emergency raw-IP fallback.
func TestResolveHelixChannelBaseURL_FlagOverridesDefault(t *testing.T) {
	t.Setenv(EnvHelixChannelBaseURL, "")
	got := ResolveHelixChannelBaseURL("https://203.0.113.10")
	want := "https://203.0.113.10"
	if got != want {
		t.Fatalf("flag override not honoured: got %q, want %q", got, want)
	}
}

// TestResolveHelixChannelBaseURL_EnvOverridesFlag asserts the env
// var is authoritative over both flag and default. This is the
// "always wins" rule that protects prod from a stray local flag
// during a cutover.
func TestResolveHelixChannelBaseURL_EnvOverridesFlag(t *testing.T) {
	t.Setenv(EnvHelixChannelBaseURL, "https://helixchannel-staging.example.com")
	got := ResolveHelixChannelBaseURL("https://203.0.113.10")
	want := "https://helixchannel-staging.example.com"
	if got != want {
		t.Fatalf("env did not override flag: got %q, want %q", got, want)
	}
}

// TestResolveHelixChannelBaseURL_EnvOverridesDefault asserts the
// env var beats the default when the flag is empty. Pin the
// precedence so a future refactor cannot move the default ahead
// of the env.
func TestResolveHelixChannelBaseURL_EnvOverridesDefault(t *testing.T) {
	t.Setenv(EnvHelixChannelBaseURL, "https://override.example.com")
	got := ResolveHelixChannelBaseURL("")
	want := "https://override.example.com"
	if got != want {
		t.Fatalf("env did not override default: got %q, want %q", got, want)
	}
}

// TestResolveHelixChannelBaseURL_TrimsTrailingSlash ensures the
// resolved URL does not carry a trailing slash, which would
// otherwise break downstream `url.Parse(base).JoinPath("/v1/models")`
// paths that produce `//v1/models`.
func TestResolveHelixChannelBaseURL_TrimsTrailingSlash(t *testing.T) {
	t.Setenv(EnvHelixChannelBaseURL, "")
	got := ResolveHelixChannelBaseURL("https://example.com/")
	want := "https://example.com"
	if got != want {
		t.Fatalf("trailing slash not trimmed: got %q, want %q", got, want)
	}
}

// TestResolveHelixChannelBaseURL_TrimsTrailingSlashFromEnv covers
// the env-var path of the trailing-slash trim. Same defensive
// guarantee as the flag path — both inputs flow through the same
// trim and the test ensures the env branch is exercised.
func TestResolveHelixChannelBaseURL_TrimsTrailingSlashFromEnv(t *testing.T) {
	t.Setenv(EnvHelixChannelBaseURL, "https://staging.example.com/")
	got := ResolveHelixChannelBaseURL("")
	want := "https://staging.example.com"
	if got != want {
		t.Fatalf("trailing slash not trimmed from env: got %q, want %q", got, want)
	}
}

// TestHostFromBaseURL_ExtractsHost asserts the host extraction
// helper. Operators can write `helixchannel endpoint-check` (no
// flags) and have it derive the host from the canonical base URL
// automatically.
func TestHostFromBaseURL_ExtractsHost(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "default canonical host",
			in:   "https://helixchannel.example.com",
			want: "helixchannel.example.com",
		},
		{
			name: "raw IP override",
			in:   "https://203.0.113.10",
			want: "203.0.113.10",
		},
		{
			name: "non-default port",
			in:   "https://example.com:8443",
			want: "example.com:8443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HostFromBaseURL(tc.in)
			if err != nil {
				t.Fatalf("HostFromBaseURL(%q) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("HostFromBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHostFromBaseURL_RejectsMalformed ensures the helper fails
// loud on unparseable input rather than silently producing a
// wrong host. This guards against an operator accidentally
// setting HELIXCHANNEL_BASE_URL=example.com (no scheme) — the
// binary should fail with a clear error message.
func TestHostFromBaseURL_RejectsMalformed(t *testing.T) {
	_, err := HostFromBaseURL("example.com")
	if err == nil {
		t.Fatalf("HostFromBaseURL(\"example.com\") should error on missing scheme")
	}
}

// TestHostFromBaseURL_RejectsEmpty guards against a misconfigured
// HELIXCHANNEL_BASE_URL="" silently producing an empty host.
func TestHostFromBaseURL_RejectsEmpty(t *testing.T) {
	_, err := HostFromBaseURL("")
	if err == nil {
		t.Fatalf("HostFromBaseURL(\"\") should error on empty input")
	}
}
