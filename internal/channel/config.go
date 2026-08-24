// Package channel implements HelixChannel: the encrypted, config-driven
// egress path that carries LLM API traffic from an agent (Kilo Code, Cursor,
// Claude Code, Codex CLI, any OpenAI-compatible client) to an upstream
// provider without exposing provider credentials to the client or the
// intervening network.
//
// Design (SOLID):
//
//   - Route          — a single upstream binding. Pure configuration data (SRP).
//   - SecretProvider — strategy for turning a reference into a credential. A
//     new backend is a new implementation, never an edit to a caller (OCP).
//   - Authenticator  — strategy for applying credentials to an outbound request
//     (OCP: new auth modes are new implementations, not edits to the handler;
//     LSP: every mode is substitutable at the call site).
//   - RotationPolicy — strategy for choosing among a route's selectable keys.
//   - Forwarder      — abstraction the HTTP handler depends on (DIP), so the
//     handler is testable without a network and swappable for a
//     streaming/queueing implementation later.
//   - Registry       — resolves an inbound path to a Route.
//
// Adding a provider (for example OpenAI Codex) is a configuration change:
// append a route with its upstream, auth mode and enabled flag. No code
// change, no redeploy of new logic.
package channel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AuthMode selects how upstream credentials are applied to a proxied request.
type AuthMode string

const (
	// AuthInject replaces the caller's Authorization header with the
	// server-held API key, and STRIPS every other caller-supplied credential
	// header (see callerCredentialHeaders) so the upstream sees exactly one
	// credential. The client never sees the real one; a placeholder bearer is
	// sufficient. Used for API-key upstreams (MiniMax, Qwen, OpenAI/Codex).
	AuthInject AuthMode = "inject"

	// AuthPassthrough forwards the caller's credential headers unchanged. It
	// is the ONLY mode exempt from the caller-credential strip, because
	// carrying the client's own credential is the whole point: it is used for
	// upstreams where the client holds a session credential (for example Claude
	// Code's OAuth session against api.anthropic.com), where injecting a
	// server-side key would break authentication.
	AuthPassthrough AuthMode = "passthrough"

	// AuthHeaderInject places the server-held credential in an operator-named
	// header instead of "Authorization: Bearer". It exists for providers whose
	// API key is not a bearer token (the Exa "x-api-key" / Tavily shape). Like
	// AuthInject it strips every caller-supplied credential header — including
	// key_header itself, whatever it is named — before writing its own.
	AuthHeaderInject AuthMode = "header"
)

// Route binds an inbound path prefix to an upstream provider.
//
// Singular (KeyEnv/KeyFile/KeyRef) and plural (KeyEnvs/KeyFiles/KeyRefs)
// credential sources are mutually exclusive: silently preferring one over the
// other is how a route ends up serving from a key the operator thought was
// retired.
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
	// Enabled is the per-route feature flag. A disabled route is not
	// registered; requests to its prefix return 404. This is the switch
	// that makes "turn Codex on" a config edit.
	Enabled bool `yaml:"enabled"`
	// Timeout bounds a single upstream round trip. Zero means the server
	// default.
	Timeout time.Duration `yaml:"timeout"`

	// KeyEnv names an environment variable holding the upstream API key.
	KeyEnv string `yaml:"key_env"`
	// KeyFile is a path holding the upstream API key. Surrounding whitespace
	// is trimmed. Keeping keys in root-owned files (rather than argv or a
	// client config) is what keeps them off the wire and out of process
	// listings.
	KeyFile string `yaml:"key_file"`
	// KeyRef is a scheme-qualified credential reference — "env:NAME",
	// "file:/path" or "op://<vault>/<item>/<field>". It is consulted BEFORE
	// KeyEnv and KeyFile, so an explicit reference always wins. Absent from a
	// config it is the empty string and nothing changes.
	KeyRef string `yaml:"key_ref"`

	// KeyEnvs names environment variables, each holding ONE upstream key.
	// A nil slice means "not configured"; a present-but-empty slice is a
	// validation error, so a truncated config cannot silently produce a
	// zero-key pool.
	//
	// Slot order across the three plural fields is FROZEN: KeyEnvs, then
	// KeyFiles, then KeyRefs. That is what makes the key_index in an audit
	// line mean the same account on every node running the same config.
	KeyEnvs []string `yaml:"key_envs"`
	// KeyFiles are paths, each holding ONE upstream key.
	KeyFiles []string `yaml:"key_files"`
	// KeyRefs are scheme-qualified references, each yielding ONE upstream
	// key. Any scheme the Resolver understands is accepted. A reference is an
	// identifier, not a secret, so it is safe in config and in error
	// messages; its resolved value never is.
	KeyRefs []string `yaml:"key_refs"`

	// KeyHeader is the header name written by AuthHeaderInject. Required
	// for, and legal only on, that mode.
	KeyHeader string `yaml:"key_header"`
	// KeyPrefix is prepended to the credential by AuthHeaderInject (for
	// example "Token "). Legal only on that mode; AuthInject's prefix is
	// fixed at "Bearer ".
	KeyPrefix string `yaml:"key_prefix"`

	// Rotation configures multi-key selection and per-key budgets. It is
	// legal ONLY on a pooled route: a budget on a single-key route would be
	// advertised and never enforced. A nil pointer means "no rotation block",
	// which must stay distinguishable from "rotation: {}".
	Rotation *RotationConfig `yaml:"rotation"`
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
	// TokenRef is a scheme-qualified reference to the CONNECT shared token,
	// consulted before TokenEnv and TokenFile.
	TokenRef string `yaml:"token_ref"`
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
		if err := validateRouteAuth(r); err != nil {
			return err
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
	return c.validateConnect()
}

// validateRouteAuth is the SINGLE entry point for a route's credential, auth
// mode and rotation rules.
//
// The order is load-bearing. Key-source shape is checked before the auth mode,
// so "you named both a single key and a pool" is reported as the structural
// mistake it is rather than as a mode complaint; rotation is checked last,
// because its central rule ("rotation needs a pool") is only meaningful once
// the sources are known to be coherent.
func validateRouteAuth(r *Route) error {
	if err := validateKeySources(r); err != nil {
		return err
	}
	if err := validateAuthMode(r); err != nil {
		return err
	}
	return validateRotation(r)
}

// hasSingularKeys reports whether the route uses the one-key fields.
func hasSingularKeys(r Route) bool { return r.KeyEnv != "" || r.KeyFile != "" || r.KeyRef != "" }

// hasPluralKeys reports whether the route declares a key pool. A nil slice is
// "not configured"; a present-but-empty slice is configured and invalid, which
// is why this tests for nil rather than for length.
func hasPluralKeys(r Route) bool {
	return r.KeyEnvs != nil || r.KeyFiles != nil || r.KeyRefs != nil
}

// validateKeySources enforces the rules that apply to credential declarations
// regardless of auth mode: singular and plural are mutually exclusive, a
// declared list must not be empty or blank, no source may appear twice, and
// every reference must be syntactically resolvable.
func validateKeySources(r *Route) error {
	if hasSingularKeys(*r) && hasPluralKeys(*r) {
		return fmt.Errorf("route %q: singular (key_env/key_file/key_ref) and plural (key_envs/key_files/key_refs) credential sources are mutually exclusive", r.Name)
	}
	lists := []struct {
		field string
		items []string
		clean bool
	}{
		{"key_envs", r.KeyEnvs, false},
		{"key_files", r.KeyFiles, true},
		{"key_refs", r.KeyRefs, false},
	}
	for _, l := range lists {
		if l.items == nil {
			continue
		}
		if len(l.items) == 0 {
			return fmt.Errorf("route %q: %s is declared with no entries and must not be empty (a truncated list is a different mistake from a missing credential)", r.Name, l.field)
		}
		if err := rejectDuplicateSources(r.Name, l.field, l.items, l.clean); err != nil {
			return err
		}
	}
	if err := validateSecretRef(r.KeyRef); err != nil {
		return fmt.Errorf("route %q: %w", r.Name, err)
	}
	for i, ref := range r.KeyRefs {
		if err := validateSecretRef(ref); err != nil {
			return fmt.Errorf("route %q: key_refs[%d]: %w", r.Name, i, err)
		}
	}
	return nil
}

// rejectDuplicateSources refuses a list that names the same source twice. Key
// file paths are compared after filepath.Clean, so two spellings of one path
// cannot inflate a pool. Source names (env vars, refs, paths) are identifiers,
// never secrets, so naming the offender in the error is safe.
//
// This is the CONFIG-level dedup. The value-level dedup —
// rejectDuplicateCredentials — runs at startup on the resolved keys and reports
// slot labels only. Two distinct sources can still name one account, and only
// the second check can see that.
func rejectDuplicateSources(route, field string, items []string, clean bool) error {
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("route %q: %s contains a blank entry", route, field)
		}
		k := item
		if clean {
			k = filepath.Clean(item)
		}
		if seen[k] {
			return fmt.Errorf("route %q: duplicate key source %q in %s", route, item, field)
		}
		seen[k] = true
	}
	return nil
}

// validateAuthMode enforces the per-mode rules and keeps the auth enum message
// a superset of the one operators (and the existing tests) already read.
func validateAuthMode(r *Route) error {
	if r.Auth != AuthHeaderInject {
		if r.KeyHeader != "" {
			return fmt.Errorf("route %q: key_header is only valid with auth: header", r.Name)
		}
		if r.KeyPrefix != "" {
			return fmt.Errorf("route %q: key_prefix is only valid with auth: header", r.Name)
		}
	}
	switch r.Auth {
	case AuthInject, AuthHeaderInject:
		if !hasSingularKeys(*r) && !hasPluralKeys(*r) {
			return fmt.Errorf("route %q: auth %q requires key_env or key_file or key_ref, or key_envs/key_files/key_refs", r.Name, r.Auth)
		}
		if r.Auth == AuthHeaderInject {
			return validateKeyHeader(r)
		}
		return nil
	case AuthPassthrough:
		if hasSingularKeys(*r) || hasPluralKeys(*r) {
			return fmt.Errorf("route %q: auth %q must not set key_env/key_file/key_ref or key_envs/key_files/key_refs", r.Name, AuthPassthrough)
		}
		return nil
	default:
		return fmt.Errorf("route %q: auth must be %q, %q or %q (got %q)", r.Name, AuthInject, AuthHeaderInject, AuthPassthrough, r.Auth)
	}
}

// validateKeyHeader rejects a header name that would fail only when the
// outbound request was written, turning an operator typo into a per-request
// 502 instead of a startup error.
func validateKeyHeader(r *Route) error {
	if r.KeyHeader == "" {
		return fmt.Errorf("route %q: auth %q: key_header is required: %q is not a valid header name", r.Name, AuthHeaderInject, r.KeyHeader)
	}
	if !validHeaderName(r.KeyHeader) {
		return fmt.Errorf("route %q: key_header %q is not a valid header name", r.Name, r.KeyHeader)
	}
	if hopByHop[strings.ToLower(r.KeyHeader)] {
		return fmt.Errorf("route %q: key_header %q is a hop-by-hop header; credentials are applied after the forwarder strips those, so it would corrupt the upstream connection", r.Name, r.KeyHeader)
	}
	if strings.EqualFold(r.KeyHeader, "Host") {
		return fmt.Errorf("route %q: key_header %q cannot be injected; net/http derives Host from the upstream URL and would misroute or ignore it", r.Name, r.KeyHeader)
	}
	return nil
}

// validHeaderName reports whether name is a legal RFC 9110 field-name.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validateRotation is the ONE rotation-block validator. It checks the block and
// fills in its defaults, so a route that merely says "rotation: {}" behaves
// exactly like the round-robin default.
func validateRotation(r *Route) error {
	rot := r.Rotation
	if rot == nil {
		return nil
	}
	if r.Auth == AuthPassthrough {
		return fmt.Errorf("route %q: auth %q must not set rotation: passthrough forwards the caller's own credential, so there is nothing to rotate", r.Name, AuthPassthrough)
	}
	if !hasPluralKeys(*r) {
		return fmt.Errorf("route %q: rotation requires a key pool; set key_envs/key_files/key_refs (a rotation block on a single-key route would advertise a budget that is never enforced)", r.Name)
	}
	if _, err := NewPolicy(rot.Policy); err != nil {
		return fmt.Errorf("route %q: %w", r.Name, err)
	}
	if rot.Policy == "" {
		rot.Policy = PolicyRoundRobin
	}
	// A header-auth upstream reports no usage.total_tokens, so every sample on
	// such a route is an estimate and least_tokens degenerates into least_used
	// while still claiming to balance tokens. Reject the combination at load
	// rather than let it look like it is working.
	if r.Auth == AuthHeaderInject && rot.Policy == PolicyLeastTokens {
		return fmt.Errorf("route %q: rotation.policy %q is not supported with auth %q: a header-auth upstream reports no usage.total_tokens, so every sample is an estimate and this policy would silently behave as %q",
			r.Name, PolicyLeastTokens, AuthHeaderInject, PolicyLeastUsed)
	}
	if err := validateBudget(r.Name, &rot.Budget); err != nil {
		return err
	}
	if rot.MaxRetryAfter < 0 {
		return fmt.Errorf("route %q: rotation.max_retry_after must not be negative", r.Name)
	}
	if rot.MaxRetryAfter == 0 {
		rot.MaxRetryAfter = DefaultMaxRetryAfter
	}
	return nil
}

func validateBudget(name string, b *Budget) error {
	switch {
	case b.SoftRatio < 0 || b.SoftRatio > 1:
		return fmt.Errorf("route %q: rotation.budget.soft_ratio must be in (0, 1] (got %v); 0 selects the %v default", name, b.SoftRatio, DefaultSoftRatio)
	case b.Window < 0:
		return fmt.Errorf("route %q: rotation.budget.window must not be negative", name)
	case b.Window == 0 && (b.Tokens > 0 || b.Requests > 0):
		return fmt.Errorf("route %q: rotation.budget.window is required when tokens or requests is set, or the caps would never reset", name)
	case b.Tokens > 0 && b.EstimateTokens <= 0:
		return fmt.Errorf("route %q: rotation.budget.estimate_tokens is required when tokens is set: streaming responses report no usage and would never charge the cap", name)
	}
	if b.SoftRatio == 0 {
		b.SoftRatio = DefaultSoftRatio
	}
	return nil
}

// validateConnect checks the CONNECT leg and applies its defaults.
func (c *Config) validateConnect() error {
	if !c.Connect.Enabled {
		return nil
	}
	if len(c.Connect.AllowedHosts) == 0 {
		return fmt.Errorf("connect: allowed_hosts is required when connect is enabled (an empty allowlist would be an open relay)")
	}
	if c.Connect.TokenEnv == "" && c.Connect.TokenFile == "" && c.Connect.TokenRef == "" {
		return fmt.Errorf("connect: token_env or token_file is required when connect is enabled (token_ref is accepted too)")
	}
	if err := validateSecretRef(c.Connect.TokenRef); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	for _, h := range c.Connect.AllowedHosts {
		if !strings.Contains(h, ":") {
			return fmt.Errorf("connect: allowed_hosts entry %q must be host:port", h)
		}
	}
	if c.Connect.DialTimeout == 0 {
		c.Connect.DialTimeout = 10 * time.Second
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
