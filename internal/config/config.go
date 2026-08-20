// Package config defines the YAML-backed configuration types and
// loading logic for llm-cluster-router. The types are exported so
// they can be consumed by the router, health, and proxy packages.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level router configuration loaded from YAML.
type Config struct {
	Listen      string `yaml:"listen"`
	MetricsAddr string `yaml:"metrics_addr"`
	DebugAddr   string `yaml:"debug_addr"`
	LogLevel    string `yaml:"log_level"`
	AuthToken   string `yaml:"auth_token"`
	// SlackWebhookURL, when non-empty, is the Slack Incoming Webhook URL the
	// router posts quota-fallback alerts to. The webhook URL is loaded from
	// the LLM_ROUTER_SLACK_WEBHOOK_URL env var at startup; the YAML field is
	// reserved for future first-class config support.
	SlackWebhookURL string `yaml:"slack_webhook_url"`
	// SlackChannel, when non-empty, overrides the Slack Incoming Webhook's
	// default channel. Empty means use the webhook's default.
	SlackChannel string          `yaml:"slack_channel"`
	Defaults     Defaults        `yaml:"defaults"`
	HealthCheck  HealthConfig    `yaml:"health_check"`
	FairShare    FairShareConfig `yaml:"fair_share"`
	Nodes        []NodeConfig    `yaml:"nodes"`
	// SmartRoute enables task-aware model/parameter routing and per-agent
	// route gates. Both fields must be set for the feature to activate;
	// absent or disabled means the router behaves exactly as before.
	SmartRoute SmartRouteConfig `yaml:"smart_route"`
}

// SmartRouteConfig points the router at a smartroute policy file.
type SmartRouteConfig struct {
	Enabled    bool   `yaml:"enabled"`
	PolicyFile string `yaml:"policy_file"`
}

// FairShareConfig controls per-user rate limiting. When Enabled is
// false (the default), the scheduler is not instantiated and all
// requests pass through to the global semaphore only.
type FairShareConfig struct {
	Enabled            bool          `yaml:"enabled"`
	MaxRequestsPerUser int           `yaml:"max_requests_per_user"`
	Window             DurationValue `yaml:"window"`
	Burst              int           `yaml:"burst"`
}

// Defaults holds global default limits for queue depth, concurrency,
// request timeout, and body size.
type Defaults struct {
	MaxQueueDepth  int           `yaml:"max_queue_depth"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	RequestTimeout DurationValue `yaml:"request_timeout"`
	MaxBodySize    int64         `yaml:"max_body_size"`
	// Circuit tunes the per-upstream circuit breaker fleet-wide. It was
	// previously hardcoded to 5 failures / 30s in main.go; exposing it here
	// lets operators retune the breaker for a single-tier provider (e.g.
	// MiniMax) without a code change. Per-node overrides live on NodeConfig.
	Circuit CircuitConfig `yaml:"circuit"`
}

// CircuitConfig tunes a per-upstream circuit breaker. Threshold is the
// consecutive-failure count that opens the breaker; Cooldown is how long it
// stays open before allowing a half-open probe. Zero values fall back to the
// breaker defaults (5 failures / 30s) so existing configs keep working.
type CircuitConfig struct {
	Threshold int           `yaml:"threshold"`
	Cooldown  DurationValue `yaml:"cooldown"`
}

// Default circuit-breaker tuning, matching the historical hardcoded values so
// behaviour is unchanged when the config omits a circuit block.
const (
	DefaultCircuitThreshold = 5
	DefaultCircuitCooldown  = 30 * time.Second
)

// HealthConfig controls the upstream health-check loop.
type HealthConfig struct {
	Interval           DurationValue `yaml:"interval"`
	Timeout            DurationValue `yaml:"timeout"`
	Path               string        `yaml:"path"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold"`
	HealthyThreshold   int           `yaml:"healthy_threshold"`
}

// DurationValue wraps time.Duration for YAML unmarshalling from a
// string like "30s" or "2m".
type DurationValue struct {
	time.Duration
}

func (d *DurationValue) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

// NodeConfig describes a single upstream LLM node.
type NodeConfig struct {
	Name    string   `yaml:"name"`
	URL     string   `yaml:"url"`
	Tier    string   `yaml:"tier"`
	Enabled string   `yaml:"enabled"`
	Weight  int      `yaml:"weight"`
	Models  []string `yaml:"models"`
	APIKey  string   `yaml:"api_key"`
	APIKeys []string `yaml:"api_keys"`
	// Vendor is the canonical upstream type. Empty (or "openai_compat") means the
	// existing LocalOpenAICompatible path; values like "minimax" toggle the
	// vendor-specific URL builder, auth header, and quota classifier.
	//
	// This field is additive and ignored by older router builds, so adding a
	// `vendor:` line to an existing YAML never breaks existing peers.
	Vendor string `yaml:"vendor"`
	// APIKeyEnv, when non-empty, is the env var the router reads at request
	// time to construct the Authorization header for this peer. This avoids
	// embedding raw API keys in the YAML config. The env var should be set
	// via 1Password op-secret or a secrets manager; the router process
	// inherits the env at startup.
	APIKeyEnv string `yaml:"api_key_env"`
	// EnabledVendor (string, not bool, matches the rest of this struct)
	// toggles participation when Vendor is non-empty. Set to "true" to
	// register the vendor peer in the active routing pool; "false" (or
	// omitted) leaves the peer unreachable but parseable.
	EnabledVendor string `yaml:"enabled_vendor"`
	// QuotaDetectRegex, when non-empty, is the regular expression applied to
	// 4xx/5xx response bodies to flag the response as a quota event. A quota
	// event triggers the route's fallback chain and increments
	// `quota_fallback_total` so an operator can alert on a flat line.
	QuotaDetectRegex string `yaml:"quota_detect_regex"`
	Priority         int    `yaml:"priority"`
	// Circuit optionally overrides the global Defaults.Circuit tuning for this
	// single upstream. Unset (zero) fields inherit the global default.
	Circuit CircuitConfig `yaml:"circuit"`
	// HealthCheckDisabled, when true, removes this upstream from the active
	// health-probe loop. It defaults to false (probe enabled).
	//
	// FOOTGUN: disabling the probe is what made the MiniMax-M3 bridge "never
	// recover" — the proxy marks a node unhealthy on a transport error, and
	// ONLY the health loop flips it back. With the probe disabled the node is
	// stuck out of rotation until a process restart, so a single transient
	// blip becomes a permanent outage. Leave this false for any upstream that
	// can self-recover (the circuit breaker already absorbs short error
	// bursts and re-probes the upstream half-open after its cooldown). Only
	// set it true for an upstream that legitimately has no health endpoint
	// AND whose liveness is asserted by other means.
	HealthCheckDisabled bool `yaml:"health_check_disabled"`

	// Tunnel, when set, sends this node's outbound traffic through an
	// SSH local-port forward to a Helixon "tunneld" jump (see `tunnel`
	// package). The zero value means "no tunnel; route directly to
	// URL". Per-node rather than global because most upstreams are
	// served directly from the router host and only sensitive ones
	// (e.g. audit-logged corporate endpoints) need the SSH leg.
	//
	// Operators wire the identity file via a side channel (the
	// ssh-add daemon, or strict mode 0600 on the worker) — we do not
	// embed key material in config so the file can stay
	// operator-readable.
	Tunnel TunnelConfig `yaml:"tunnel"`
}

// TunnelConfig is the YAML subset of tunnel.SSHTunnelConfig. Keeping
// the config surface independent from the runtime type lets the
// tunnel package own its own validation and lets us tighten the
// router's binding without breaking existing YAML.
type TunnelConfig struct {
	// Enabled, when true, routes this node through the tunnel
	// described below. Defaults to false.
	Enabled bool `yaml:"enabled"`
	// Host is the remote jump (e.g. Lightsail host). Required when
	// Enabled is true.
	Host string `yaml:"host"`
	// Port is the remote SSH port. Defaults to 22 when zero.
	Port int `yaml:"port"`
	// User is the SSH login on the jump. Required when Enabled.
	User string `yaml:"user"`
	// IdentityFile is the absolute path of the SSH private key.
	// Required when Enabled.
	IdentityFile string `yaml:"identity_file"`
	// LocalPort is the port tunneld (or another HTTP server) is
	// listening on INSIDE the jump's loopback. Traffic relayed
	// through the SSH -L forward lands here. Required when Enabled
	// and must be 1..65535.
	LocalPort int `yaml:"local_port"`
	// ConnectTimeout is the per-dial SSH timeout. Defaults to 10s.
	ConnectTimeout DurationValue `yaml:"connect_timeout"`
}

// ToRuntime converts the YAML-time config into the package-local
// representation consumed by `tunnel.DialContext`. It returns an
// error if the config is invalid so the router can refuse to start
// with a broken tunnel rather than fail at first request.
func (t TunnelConfig) ToRuntime() (SSHTunnelRuntime, error) {
	if !t.Enabled {
		return SSHTunnelRuntime{}, ErrTunnelDisabled
	}
	if t.Host == "" || t.User == "" || t.IdentityFile == "" {
		return SSHTunnelRuntime{}, errTunnelMissingField{field: "host/user/identity_file"}
	}
	if t.LocalPort <= 0 || t.LocalPort > 65535 {
		return SSHTunnelRuntime{}, errTunnelMissingField{field: "local_port"}
	}
	ct := t.ConnectTimeout.Duration
	if ct == 0 {
		ct = 10 * time.Second
	}
	return SSHTunnelRuntime{
		Host:           t.Host,
		Port:           t.Port,
		User:           t.User,
		IdentityFile:   t.IdentityFile,
		LocalPort:      t.LocalPort,
		ConnectTimeout: ct,
	}, nil
}

// SSHTunnelRuntime is the runtime SSH-tunnel config attached to a
// routed node. It mirrors tunnel.SSHTunnelConfig to keep the config
// package free of an import cycle, then convert() in the router.
type SSHTunnelRuntime struct {
	Host           string
	Port           int
	User           string
	IdentityFile   string
	LocalPort      int
	ConnectTimeout time.Duration
}

// ErrTunnelDisabled signals the caller asked for ToRuntime on a
// disabled TunnelConfig; not a hard error.
var ErrTunnelDisabled = errors.New("tunnel: not enabled")

// errTunnelMissingField is wrapped into a friendly message for the
// operator; we use an unexported type to avoid callers doing
// branchy string matching.
type errTunnelMissingField struct{ field string }

func (e errTunnelMissingField) Error() string { return "tunnel: missing/invalid " + e.field }

// ResolvedCircuit returns the effective breaker threshold and cooldown for
// this node: a positive per-node override wins, otherwise the global default
// (which LoadConfig has already populated). It never returns non-positive
// values, so callers can pass the result straight to the breaker constructor.
func (n NodeConfig) ResolvedCircuit(def Defaults) (threshold int, cooldown time.Duration) {
	threshold = def.Circuit.Threshold
	if n.Circuit.Threshold > 0 {
		threshold = n.Circuit.Threshold
	}
	if threshold <= 0 {
		threshold = DefaultCircuitThreshold
	}
	cooldown = def.Circuit.Cooldown.Duration
	if n.Circuit.Cooldown.Duration > 0 {
		cooldown = n.Circuit.Cooldown.Duration
	}
	if cooldown <= 0 {
		cooldown = DefaultCircuitCooldown
	}
	return threshold, cooldown
}

// ForbiddenUpstreamHostSuffixes is the locked list of hostnames the
// router refuses to route to. Suffix matching is case-insensitive.
var ForbiddenUpstreamHostSuffixes = []string{
	"zende.sk",
	"zendesk.com",
}

// LoadConfig reads the YAML configuration from path, applies
// defaults, expands environment variables, and validates upstream
// URLs. It returns the fully-resolved Config or an error.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.MetricsAddr == "" {
		cfg.MetricsAddr = ":9091"
	}
	if cfg.Defaults.MaxQueueDepth <= 0 {
		cfg.Defaults.MaxQueueDepth = 8
	}
	if cfg.Defaults.MaxConcurrency <= 0 {
		cfg.Defaults.MaxConcurrency = 2
	}
	if cfg.Defaults.RequestTimeout.Duration <= 0 {
		cfg.Defaults.RequestTimeout.Duration = 120 * time.Second
	}
	if cfg.Defaults.MaxBodySize <= 0 {
		cfg.Defaults.MaxBodySize = 1 << 20
	}
	if cfg.Defaults.Circuit.Threshold <= 0 {
		cfg.Defaults.Circuit.Threshold = DefaultCircuitThreshold
	}
	if cfg.Defaults.Circuit.Cooldown.Duration <= 0 {
		cfg.Defaults.Circuit.Cooldown.Duration = DefaultCircuitCooldown
	}
	if cfg.HealthCheck.Interval.Duration <= 0 {
		cfg.HealthCheck.Interval.Duration = 15 * time.Second
	}
	if cfg.HealthCheck.Timeout.Duration <= 0 {
		cfg.HealthCheck.Timeout.Duration = 5 * time.Second
	}
	if cfg.HealthCheck.Path == "" {
		cfg.HealthCheck.Path = "/health"
	}
	if cfg.HealthCheck.UnhealthyThreshold <= 0 {
		cfg.HealthCheck.UnhealthyThreshold = 3
	}
	if cfg.HealthCheck.HealthyThreshold <= 0 {
		cfg.HealthCheck.HealthyThreshold = 1
	}
	if cfg.FairShare.Enabled {
		if cfg.FairShare.MaxRequestsPerUser <= 0 {
			cfg.FairShare.MaxRequestsPerUser = 10
		}
		if cfg.FairShare.Window.Duration <= 0 {
			cfg.FairShare.Window.Duration = 60 * time.Second
		}
		if cfg.FairShare.Burst <= 0 {
			cfg.FairShare.Burst = 3
		}
	}
	if len(cfg.Nodes) == 0 {
		return cfg, errors.New("config must define at least one node")
	}
	cfg.AuthToken = ExpandEnvValue(cfg.AuthToken)
	for i := range cfg.Nodes {
		cfg.Nodes[i].APIKey = ExpandEnvValue(cfg.Nodes[i].APIKey)
		for j := range cfg.Nodes[i].APIKeys {
			cfg.Nodes[i].APIKeys[j] = ExpandEnvValue(cfg.Nodes[i].APIKeys[j])
		}
		cfg.Nodes[i].Enabled = ExpandEnvValue(cfg.Nodes[i].Enabled)
		if err := ValidateUpstreamURL(cfg.Nodes[i].Name, cfg.Nodes[i].URL); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// ValidateUpstreamURL parses rawURL and rejects it when the host
// matches a ForbiddenUpstreamHostSuffixes entry.
func ValidateUpstreamURL(nodeName, rawURL string) error {
	if rawURL == "" {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return nil
	}
	for _, suffix := range ForbiddenUpstreamHostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return fmt.Errorf(
				"node %q: forbidden upstream host %q (matches %q); "+
					"see router.sample.yml — this router is for self-hosted clusters only",
				nodeName, host, suffix,
			)
		}
	}
	return nil
}

// ExpandEnvValue resolves a ${VAR} pattern to the environment value.
// If the string is not wrapped in ${...}, it is returned unchanged.
func ExpandEnvValue(s string) string {
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return s
	}
	key := s[2 : len(s)-1]
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return ""
}
