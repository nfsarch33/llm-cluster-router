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
	Listen      string          `yaml:"listen"`
	MetricsAddr string          `yaml:"metrics_addr"`
	DebugAddr   string          `yaml:"debug_addr"`
	LogLevel    string          `yaml:"log_level"`
	AuthToken   string          `yaml:"auth_token"`
	Defaults    Defaults        `yaml:"defaults"`
	HealthCheck HealthConfig    `yaml:"health_check"`
	FairShare   FairShareConfig `yaml:"fair_share"`
	Nodes       []NodeConfig    `yaml:"nodes"`
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
}

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
	Name     string   `yaml:"name"`
	URL      string   `yaml:"url"`
	Tier     string   `yaml:"tier"`
	Enabled  string   `yaml:"enabled"`
	Weight   int      `yaml:"weight"`
	Models   []string `yaml:"models"`
	APIKey   string   `yaml:"api_key"`
	APIKeys  []string `yaml:"api_keys"`
	Priority int      `yaml:"priority"`
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
