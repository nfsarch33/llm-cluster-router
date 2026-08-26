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
	"errors"
	"fmt"
	"net"
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

// Bounds for the CONNECT leg, applied by validateConnect when the operator
// leaves the corresponding key unset.
//
// ZERO MEANS "THE DEFAULT", NOT "UNLIMITED", for both of them, and that choice
// is the whole point rather than a convention: every gateway config written
// before these keys existed omits them, so a zero that meant "no bound" would
// leave exactly the deployments this bound exists for running unbounded while
// the config file looks like it has been reviewed. A negative value is refused
// outright instead of being read as an opt-out, because "turn the bound off"
// is not a thing an operator should be able to say by accident.
const (
	// DefaultConnectMaxConcurrent is the ceiling on tunnels alive at once.
	// A few hundred: high enough that no plausible fleet of agents reaches
	// it in normal operation, low enough that the worst case is arithmetic
	// an operator can do -- at 256 tunnels the copy buffers alone are
	// 256 * 2 * 32KiB = 16MiB, against the ~640MiB an unbounded 10k would
	// have cost.
	DefaultConnectMaxConcurrent = 256

	// DefaultConnectIdleTimeout is how long a tunnel may carry no bytes in
	// EITHER direction before it is reaped. Five minutes is chosen against
	// the traffic this leg actually carries: a long-running agent response
	// is a stream, and a stream that has produced nothing for five minutes
	// has failed rather than paused. It is deliberately not seconds --
	// see ConnectConfig.IdleTimeout for why this one is operator-tunable
	// and the half-close linger is not.
	DefaultConnectIdleTimeout = 5 * time.Minute
)

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

	// MaxConcurrent is the number of CONNECT tunnels this gateway will carry
	// at once. It is the only thing standing between one leaked CONNECT
	// token and resource exhaustion: each tunnel costs two sockets, two copy
	// goroutines plus the handler goroutine that waits on them, and two
	// 32KiB copy buffers, and nothing else in the admission chain counts
	// them. A caller arriving when the gateway is full is refused with 503
	// and a Retry-After BEFORE the outbound dial, so a saturated gateway
	// stops being an outbound amplifier rather than merely a slow one.
	//
	// 0 selects DefaultConnectMaxConcurrent. Negative is a config error.
	MaxConcurrent int `yaml:"max_concurrent"`

	// IdleTimeout reaps a tunnel that has carried no bytes in either
	// direction for this long.
	//
	// It is a CONFIG KEY, whereas the half-close linger backstop is a
	// constant, and the difference is which tunnels each one can kill. The
	// linger only ever fires on a tunnel whose peer has already been sent a
	// FIN and has answered neither with bytes nor with a close -- there is
	// no healthy tunnel for it to get wrong. This one can kill a tunnel that
	// is merely quiet, so the right value depends on the workload behind it
	// and the operator is the only one who knows that.
	//
	// 0 selects DefaultConnectIdleTimeout. Negative is a config error: there
	// is deliberately no spelling for "never reap", because that is the
	// state this key was added to make unreachable.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

// ProxyAuthMode is the caller-authentication posture of the REVERSE-PROXY leg,
// derived from GatewayAuthConfig rather than configured directly.
//
// It is derived and not typed in by the operator because every one of these
// four states is already implied by two facts an operator does write down — is
// a token source named, and is unauthenticated operation explicitly accepted —
// and a fifth, hand-written spelling of the same thing is a way for the posture
// a gateway reports to disagree with the posture it enforces.
type ProxyAuthMode string

const (
	// ProxyAuthToken requires the gateway token from EVERY caller, loopback
	// included.
	ProxyAuthToken ProxyAuthMode = "token"
	// ProxyAuthTokenLoopbackExempt requires the gateway token from every
	// caller whose TCP peer is not loopback. It is the default whenever a
	// token is configured, so a cutover does not break the local clients that
	// were the only supported deployment before there was a token at all.
	ProxyAuthTokenLoopbackExempt ProxyAuthMode = "token_loopback_exempt"
	// ProxyAuthLoopbackOnly is the pre-existing behaviour: NO caller
	// authentication whatever. Validate refuses to let it bind a non-loopback
	// address, so the bind address is the boundary and the name says which one.
	ProxyAuthLoopbackOnly ProxyAuthMode = "loopback_only"
	// ProxyAuthOpen is ProxyAuthLoopbackOnly with the bind restriction waived
	// by an explicit allow_unauthenticated. It exists for the one legitimate
	// shape — an authenticating terminator (mTLS, an OIDC proxy) in front of a
	// gateway that must therefore bind an address that terminator can reach —
	// and it is a written-down declaration precisely so that shape and the
	// accident it is indistinguishable from stop looking the same in a config.
	ProxyAuthOpen ProxyAuthMode = "open"
)

// GatewayAuthConfig authenticates callers of the REVERSE-PROXY leg.
//
// This is a SEPARATE credential from ConnectConfig's token, and the separation
// is the point rather than an oversight: the CONNECT token opens a byte tunnel
// bounded by an exact-match allowlist, whereas this one authorises spending
// every key on every enabled route. One secret gating both would silently grant
// whichever power the operator was not thinking about.
//
// The token is named the same way every other credential is — token_env,
// token_file or a scheme-qualified token_ref — so it resolves through the one
// SecretProvider seam and a vault item shared with a route is fetched once.
type GatewayAuthConfig struct {
	// TokenEnv names an environment variable holding the gateway token.
	TokenEnv string `yaml:"token_env"`
	// TokenFile is a path holding the gateway token. Surrounding whitespace is
	// trimmed.
	TokenFile string `yaml:"token_file"`
	// TokenRef is a scheme-qualified reference — "env:NAME", "file:/path" or
	// "op://<vault>/<item>/<field>" — consulted BEFORE TokenEnv and TokenFile.
	TokenRef string `yaml:"token_ref"`

	// ExemptLoopback serves a caller whose TCP peer is 127.0.0.0/8 or ::1
	// without a token. It defaults to TRUE, which is why it is a *bool: an
	// absent key and an explicit `false` must not mean the same thing, and the
	// default has to be the one that keeps every existing local client working
	// at cutover.
	//
	// The exemption is decided from the accepted connection's peer address and
	// from nothing else — see isLoopbackPeer, which reads no header.
	ExemptLoopback *bool `yaml:"exempt_loopback"`

	// AllowUnauthenticated is the explicit acceptance an operator must write
	// down to bind a non-loopback address with no token. It is not a
	// convenience: without it, "no token" plus a wide bind is refused at
	// startup, which is the whole of turning that footgun into an error.
	AllowUnauthenticated bool `yaml:"allow_unauthenticated"`
}

// hasToken reports whether any token source is named. A named-but-unresolvable
// source is a startup error from NewServer, not an absent token.
func (g GatewayAuthConfig) hasToken() bool {
	return g.TokenRef != "" || g.TokenEnv != "" || g.TokenFile != ""
}

// exemptsLoopback reports the effective exemption: absent means exempt.
func (g GatewayAuthConfig) exemptsLoopback() bool {
	return g.ExemptLoopback == nil || *g.ExemptLoopback
}

// Mode reports the posture this configuration selects. It is the single place
// the four states are derived, so the startup log, /healthz and the request
// path cannot describe the gateway differently from one another.
func (g GatewayAuthConfig) Mode() ProxyAuthMode {
	switch {
	case g.hasToken() && g.exemptsLoopback():
		return ProxyAuthTokenLoopbackExempt
	case g.hasToken():
		return ProxyAuthToken
	case g.AllowUnauthenticated:
		return ProxyAuthOpen
	default:
		return ProxyAuthLoopbackOnly
	}
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
	// GatewayAuth authenticates callers of the reverse-proxy leg. Absent, that
	// leg authenticates nobody and Validate refuses to bind anything but a
	// loopback address.
	GatewayAuth GatewayAuthConfig `yaml:"gateway_auth"`
	// TLS optionally terminates TLS on the gateway itself.
	TLS TLSConfig `yaml:"tls"`

	// TrustForwardedForAudit records the AUDIT LOG's client_addr from
	// X-Forwarded-For instead of the accepted TCP peer, when (and only when)
	// that peer is loopback. It exists for exactly one shape: a same-host
	// TLS terminator (nginx) relaying the public internet to a gateway bound
	// on 127.0.0.1, where every peer is "loopback" and the real caller
	// address would otherwise be lost from every audit line.
	//
	// SECURITY BOUNDARY, stated plainly because this field sits one line
	// away from code that decides who gets served: it is read in exactly one
	// place (auditClientAddr in server.go) and written to exactly one field
	// (AuditEvent.ClientAddr). authorizeProxy, isLoopbackPeer and every other
	// admission decision keep reading r.RemoteAddr directly and never call
	// auditClientAddr. A header cannot buy a caller anything by setting it —
	// at most it buys a more accurate audit line, and an unparseable or
	// multi-hop header falls back to the peer address unchanged rather than
	// failing open to something this process never verified.
	TrustForwardedForAudit bool `yaml:"trust_forwarded_for_audit"`
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
	if err := c.validateConnect(); err != nil {
		return err
	}
	// LAST, and it has to stay last: it is the check that turns `listen` into
	// the gateway's whole admission posture, so raising it first would mask the
	// route and connect mistakes an operator is far likelier to have actually
	// made. validateConnect reads `listen` too, but only to ask whether an
	// allowlist entry points back at this machine, and that IS a connect
	// mistake — it belongs with the block the operator got wrong.
	return c.validateGatewayAuth()
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
	// Every entry must be a well-formed host:port AND must not name this
	// machine. The second half is the CONNECT leg's half of a two-leg defect:
	// handleConnect dials the target verbatim, so a gateway that allowlists its
	// own address will dial ITSELF, and the tunnelled request then arrives over
	// the loopback interface where gateway_auth's loopback exemption serves it
	// without a token. That turns the CONNECT token — whose blast radius is
	// supposed to be bounded by this very list — into the gateway token. See
	// connectSelfReference for exactly which spellings are decided here, and
	// connectDialRefusal for the ones that can only be decided after a dial.
	for _, h := range c.Connect.AllowedHosts {
		host, port, err := net.SplitHostPort(h)
		if err != nil {
			return fmt.Errorf("connect: allowed_hosts entry %q must be host:port", h)
		}
		// The ADVISORY half: isLoopbackListen is a prediction, so this is an
		// early refusal of what is decidable from the text and nothing more.
		// Server.bindRefusal re-runs the same rule once the socket exists.
		if why := connectSelfReference(host, port, c.Listen, isLoopbackListen(c.Listen)); why != "" {
			return fmt.Errorf("connect: allowed_hosts entry %q %s. Remove the entry, or run the service it names on a different host", h, why)
		}
	}
	if c.Connect.DialTimeout == 0 {
		c.Connect.DialTimeout = 10 * time.Second
	}
	if c.Connect.MaxConcurrent < 0 {
		return fmt.Errorf("connect: max_concurrent must not be negative (got %d); omit the key or set 0 for the default of %d, and note there is no spelling for \"unlimited\"", c.Connect.MaxConcurrent, DefaultConnectMaxConcurrent)
	}
	if c.Connect.MaxConcurrent == 0 {
		c.Connect.MaxConcurrent = DefaultConnectMaxConcurrent
	}
	if c.Connect.IdleTimeout < 0 {
		return fmt.Errorf("connect: idle_timeout must not be negative (got %v); omit the key or set 0 for the default of %v, and note there is no spelling for \"never reap\"", c.Connect.IdleTimeout, DefaultConnectIdleTimeout)
	}
	if c.Connect.IdleTimeout == 0 {
		c.Connect.IdleTimeout = DefaultConnectIdleTimeout
	}
	return nil
}

// validateGatewayAuth checks the reverse-proxy leg's caller authentication.
//
// Its central rule is the one that turns a deployment accident into a startup
// error: a gateway with NO caller authentication must not bind an address other
// hosts can reach. Before this existed, `listen: 0.0.0.0:14443` and no token
// was a funded, unauthenticated relay to every provider whose key the process
// held, and nothing in the config, the logs or /healthz said so.
//
// The two contradictions it also refuses are refused rather than resolved
// because each has two plausible readings and picking one silently is how an
// operator ends up with the posture they did not choose.
func (c *Config) validateGatewayAuth() error {
	g := &c.GatewayAuth
	if err := validateSecretRef(g.TokenRef); err != nil {
		return fmt.Errorf("gateway_auth: %w", err)
	}
	if g.hasToken() && g.AllowUnauthenticated {
		return fmt.Errorf("gateway_auth: allow_unauthenticated must not be set together with a token source: it declares that the reverse-proxy leg authenticates nobody, which is the opposite of what token_env/token_file/token_ref configure")
	}
	if g.hasToken() {
		return nil
	}
	if g.ExemptLoopback != nil && !*g.ExemptLoopback {
		return fmt.Errorf("gateway_auth: exempt_loopback: false requires a token source (token_env/token_file/token_ref); without one it would refuse every caller, loopback included")
	}
	// ADVISORY, and only that. isLoopbackListen predicts; it does not decide.
	// Server.bindRefusal asks the same question of the socket the kernel
	// actually opened, before a single request is served, and THAT is what a
	// tokenless configuration is permitted by. This check exists so the common
	// mistakes die at LoadConfig, where an operator is still reading the file.
	if !g.AllowUnauthenticated && !isLoopbackListen(c.Listen) {
		msg := fmt.Sprintf("gateway_auth: listen %q is not a loopback address and no gateway token is configured; the reverse-proxy leg would authenticate nobody while reachable from other hosts, so anyone able to open a TCP connection could spend every key on every enabled route. Set gateway_auth.token_env/token_file/token_ref, bind a loopback address, or — only behind an authenticating terminator — set gateway_auth.allow_unauthenticated: true", c.Listen)
		if hint := loopbackListenHint(c.Listen); hint != "" {
			msg += ". " + hint
		}
		return errors.New(msg)
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
