// Package channel implements HelixChannel: the encrypted, config-driven
// egress path that carries LLM API traffic from an agent (Kilo Code, Cursor,
// Claude Code, Codex CLI, any OpenAI-compatible client) to an upstream
// provider without exposing provider credentials to the client or the
// intervening network.
//
// Design (SOLID):
//
//   - Route         — a single upstream binding. Pure configuration data (SRP).
//   - Authenticator — strategy for applying credentials to an outbound request
//     (OCP: new auth modes are new implementations, not edits to the handler;
//     LSP: every mode is substitutable at the call site).
//   - Forwarder     — abstraction the HTTP handler depends on (DIP), so the
//     handler is testable without a network and swappable for a
//     streaming/queueing implementation later.
//   - Registry      — resolves an inbound path to a Route.
//
// Adding a provider (for example OpenAI Codex) is a configuration change:
// append a route with its upstream, auth mode and enabled flag. No code
// change, no redeploy of new logic.
package channel

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AuthMode selects how upstream credentials are applied to a proxied request.
type AuthMode string

const (
	// AuthInject replaces the caller's Authorization header with the
	// server-held API key. The client never sees the real credential; a
	// placeholder bearer is sufficient. Used for API-key upstreams
	// (MiniMax, Qwen, OpenAI/Codex).
	AuthInject AuthMode = "inject"

	// AuthPassthrough forwards the caller's Authorization header unchanged.
	// Used for upstreams where the client holds its own session credential
	// (for example Claude Code's OAuth session against api.anthropic.com),
	// where injecting a server-side key would break authentication.
	AuthPassthrough AuthMode = "passthrough"
)

// Route binds an inbound path prefix to an upstream provider.
type Route struct {
	// Name identifies the route in logs, metrics and the audit trail.
	Name string `yaml:"name"`
	// Prefix is the inbound path prefix, for example "/minimax/". The
	// prefix is stripped before the request is sent upstream, so
	// "/minimax/v1/models" reaches the upstream as "/v1/models".
	Prefix string `yaml:"prefix"`
	// Upstream is the provider base URL, for example "https://api.minimaxi.com".
	Upstream string `yaml:"upstream"`
	// Auth selects the credential strategy (see AuthMode).
	Auth AuthMode `yaml:"auth"`
	// KeyEnv names an environment variable holding the upstream API key.
	// Only consulted when Auth is AuthInject.
	KeyEnv string `yaml:"key_env"`
	// KeyFile is a path holding the upstream API key. Only consulted when
	// Auth is AuthInject and KeyEnv is empty or unset. A trailing newline
	// is trimmed. Keeping keys in root-owned files (rather than argv or a
	// client config) is what keeps them off the wire and out of process
	// listings.
	KeyFile string `yaml:"key_file"`
	// Enabled is the per-route feature flag. A disabled route is not
	// registered; requests to its prefix return 404. This is the switch
	// that makes "turn Codex on" a config edit.
	Enabled bool `yaml:"enabled"`
	// Timeout bounds a single upstream round trip. Zero means the server
	// default.
	Timeout time.Duration `yaml:"timeout"`
}

// ConnectConfig configures the CONNECT (tunnel) leg used by clients whose
// traffic cannot be reverse-proxied because they hold their own session
// credential and require an end-to-end TLS path — Claude Code being the
// motivating case. The gateway opens a raw TCP tunnel to an allowlisted host
// and copies bytes; it never terminates the inner TLS, so the payload stays
// opaque to the gateway and to every hop in between.
type ConnectConfig struct {
	// Enabled is the feature flag for the CONNECT leg.
	Enabled bool `yaml:"enabled"`
	// AllowedHosts is the exact-match allowlist of "host:port" targets the
	// gateway will dial. An empty list denies everything: a CONNECT proxy
	// without an allowlist is an open relay.
	AllowedHosts []string `yaml:"allowed_hosts"`
	// TokenEnv names an environment variable holding the shared token that
	// clients must present in Proxy-Authorization. Required when Enabled.
	TokenEnv string `yaml:"token_env"`
	// TokenFile is a path holding the shared token, used when TokenEnv is
	// empty or unset.
	TokenFile string `yaml:"token_file"`
	// DialTimeout bounds the outbound dial to the target host.
	DialTimeout time.Duration `yaml:"dial_timeout"`
}

// TLSConfig terminates TLS on the gateway itself.
//
// Needed when the CONNECT leg is exposed publicly: a CONNECT request cannot
// be relayed by a normal HTTP reverse proxy, so the gateway must own the
// socket that clients dial. Leave empty when a terminator (nginx) fronts the
// reverse-proxy routes on loopback.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether a certificate pair is configured.
func (t TLSConfig) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// Config is the gateway's on-disk configuration.
type Config struct {
	// Listen is the gateway bind address. Bind loopback when a TLS
	// terminator (nginx) fronts the gateway on the same host.
	Listen string `yaml:"listen"`
	// Timeout is the default per-request upstream budget for routes that
	// do not set their own.
	Timeout time.Duration `yaml:"timeout"`
	// AuditLog is a path for NDJSON audit events. Empty means stdout.
	AuditLog string `yaml:"audit_log"`
	// Routes are the upstream bindings.
	Routes []Route `yaml:"routes"`
	// Connect configures the CONNECT tunnel leg.
	Connect ConnectConfig `yaml:"connect"`
	// TLS optionally terminates TLS on the gateway itself.
	TLS TLSConfig `yaml:"tls"`
}

// DefaultTimeout is applied when neither the route nor the config sets one.
const DefaultTimeout = 90 * time.Second

// LoadConfig reads and validates a YAML gateway configuration.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate reports configuration errors that would otherwise surface as
// confusing runtime behaviour. Disabled routes are validated too: a typo in a
// route that is switched off today must not become an outage the day it is
// switched on.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen: required")
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	seenName := map[string]bool{}
	seenPrefix := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		switch {
		case r.Name == "":
			return fmt.Errorf("routes[%d]: name is required", i)
		case seenName[r.Name]:
			return fmt.Errorf("routes[%d]: duplicate route name %q", i, r.Name)
		case r.Prefix == "":
			return fmt.Errorf("route %q: prefix is required", r.Name)
		case !strings.HasPrefix(r.Prefix, "/") || !strings.HasSuffix(r.Prefix, "/"):
			return fmt.Errorf("route %q: prefix must start and end with %q (got %q)", r.Name, "/", r.Prefix)
		case seenPrefix[r.Prefix]:
			return fmt.Errorf("route %q: duplicate prefix %q", r.Name, r.Prefix)
		case r.Upstream == "":
			return fmt.Errorf("route %q: upstream is required", r.Name)
		case !strings.HasPrefix(r.Upstream, "https://") && !strings.HasPrefix(r.Upstream, "http://"):
			return fmt.Errorf("route %q: upstream must be an http(s) URL (got %q)", r.Name, r.Upstream)
		}
		switch r.Auth {
		case AuthInject:
			if r.KeyEnv == "" && r.KeyFile == "" {
				return fmt.Errorf("route %q: auth %q requires key_env or key_file", r.Name, AuthInject)
			}
		case AuthPassthrough:
			if r.KeyEnv != "" || r.KeyFile != "" {
				return fmt.Errorf("route %q: auth %q must not set key_env/key_file", r.Name, AuthPassthrough)
			}
		default:
			return fmt.Errorf("route %q: auth must be %q or %q (got %q)", r.Name, AuthInject, AuthPassthrough, r.Auth)
		}
		seenName[r.Name] = true
		seenPrefix[r.Prefix] = true
		if r.Timeout == 0 {
			r.Timeout = c.Timeout
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf("tls: cert_file and key_file must be set together")
	}
	if c.Connect.Enabled {
		if len(c.Connect.AllowedHosts) == 0 {
			return fmt.Errorf("connect: allowed_hosts is required when connect is enabled (an empty allowlist would be an open relay)")
		}
		if c.Connect.TokenEnv == "" && c.Connect.TokenFile == "" {
			return fmt.Errorf("connect: token_env or token_file is required when connect is enabled")
		}
		for _, h := range c.Connect.AllowedHosts {
			if !strings.Contains(h, ":") {
				return fmt.Errorf("connect: allowed_hosts entry %q must be host:port", h)
			}
		}
		if c.Connect.DialTimeout == 0 {
			c.Connect.DialTimeout = 10 * time.Second
		}
	}
	return nil
}

// EnabledRoutes returns only the routes whose feature flag is on.
func (c *Config) EnabledRoutes() []Route {
	out := make([]Route, 0, len(c.Routes))
	for _, r := range c.Routes {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

// readSecret resolves a credential from an environment variable first, then a
// file. The value is never logged or returned in an error message.
func readSecret(envName, filePath string) (string, error) {
	if envName != "" {
		if v := os.Getenv(envName); v != "" {
			return strings.TrimSpace(v), nil
		}
	}
	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read secret file %s: %w", filePath, err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", fmt.Errorf("secret file %s is empty", filePath)
		}
		return v, nil
	}
	return "", fmt.Errorf("no credential source configured (key_env unset/empty and key_file absent)")
}
