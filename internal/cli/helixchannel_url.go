// Package cli contains small operator-facing CLI helpers shared by
// the daemon and the cmd/helixchannel binary. The package is
// intentionally tiny (target < 100 LOC) so the daemon stays
// the canonical implementation while cmd/helixchannel picks up
// parity without dragging in the full proxy/router symbols.
//
// v18714-11 / helixchannel.example.com: ResolveHelixChannelBaseURL
// is the single source of truth for "what hostname should the
// HelixChannel tooling probe by default?" The precedence chain is:
//
//  1. HELIXCHANNEL_BASE_URL env var (always wins; protects prod
//     from a stray local flag during a cutover).
//  2. The flag value (per-call override; default empty).
//  3. The hardcoded fallback `https://helixchannel.example.com`
//     (the canonical Lightsail-backed public hostname managed via
//     DreamHost DNS).
//
// Changing the default is a coordinated DNS + TLS rollover and
// requires an operator-approved story. Tests pin the precedence so
// a refactor cannot silently shift it.
package cli

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// DefaultHelixChannelBaseURL is the canonical public hostname of the
// HelixChannel production wire. It MUST resolve to the Lightsail
// instance behind `203.0.113.10` (DreamHost A-record `helixchannel`
// in the `example.com` zone, terminated by Let's Encrypt via certbot
// on the Lightsail host, nginx reverse-proxying to 127.0.0.1:8742).
//
// Replacing this constant requires the corresponding DreamHost
// A-record update + Let's Encrypt cert rollover documented in
// docs/helixchannel-deployment.md.
const DefaultHelixChannelBaseURL = "https://helixchannel.example.com"

// EnvHelixChannelBaseURL is the env-var name operators may set to
// override the canonical base URL during a cutover. Set to a
// staging or canary hostname to redirect every CLI invocation
// without code changes.
const EnvHelixChannelBaseURL = "HELIXCHANNEL_BASE_URL"

// ResolveHelixChannelBaseURL returns the effective base URL for
// HelixChannel CLI tooling, applying the precedence:
//
//	HELIXCHANNEL_BASE_URL env -> flagBaseURL -> DefaultHelixChannelBaseURL
//
// Trailing slashes are stripped so downstream `url.JoinPath` calls
// don't produce `//v1/models` paths. Empty env values are treated
// as unset (t.Setenv-style clear).
func ResolveHelixChannelBaseURL(flagBaseURL string) string {
	if v := strings.TrimSpace(os.Getenv(EnvHelixChannelBaseURL)); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(flagBaseURL); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultHelixChannelBaseURL
}

// HostFromBaseURL extracts the host[:port] portion of a base URL
// for use with TCP-reachability probes (e.g. `endpoint-check --host`).
// Returns an error if the input does not parse as an absolute URL with
// a host component; this guards against operators setting
// HELIXCHANNEL_BASE_URL=example.com (no scheme) — the CLI must fail
// loud rather than silently derive an empty host.
func HostFromBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty base URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("base URL %q has no host component (missing scheme?)", raw)
	}
	return u.Host, nil
}
