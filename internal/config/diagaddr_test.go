package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nfsarch33/llm-cluster-router/internal/health"
)

func TestDiagnosticListenAddr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"host-less port binds loopback", ":6060", "127.0.0.1:6060"},
		{"host-less metrics port binds loopback", ":9091", "127.0.0.1:9091"},
		{"explicit wildcard is honoured", "0.0.0.0:6060", "0.0.0.0:6060"},
		{"explicit v6 wildcard is honoured", "[::]:6060", "[::]:6060"},
		{"explicit loopback is unchanged", "127.0.0.1:9091", "127.0.0.1:9091"},
		{"explicit v6 loopback is unchanged", "[::1]:9091", "[::1]:9091"},
		{"explicit routable address is honoured", "10.0.0.5:9091", "10.0.0.5:9091"},
		{"explicit hostname is honoured", "metrics.example:9091", "metrics.example:9091"},
		{"port zero still binds loopback", ":0", "127.0.0.1:0"},
		{"unparseable is returned unchanged", "not-an-address", "not-an-address"},
		{"too many colons is returned unchanged", "1:2:3", "1:2:3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DiagnosticListenAddr(tc.in); got != tc.want {
				t.Fatalf("DiagnosticListenAddr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// DiagnosticListenAddr must be idempotent: runServe re-applies it over an
// address LoadConfig already resolved, so a second pass must not move it.
func TestDiagnosticListenAddr_Idempotent(t *testing.T) {
	for _, in := range []string{"", ":6060", "0.0.0.0:9091", "[::]:6060", "127.0.0.1:9091", "junk"} {
		once := DiagnosticListenAddr(in)
		if twice := DiagnosticListenAddr(once); twice != once {
			t.Fatalf("not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "router.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const minimalNodes = `
nodes:
  - name: n1
    url: http://127.0.0.1:9999
    tier: t
    models: [m]
`

func TestLoadConfig_DiagnosticAddrDefaults(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantMetrics string
		wantDebug   string
	}{
		{
			name:        "omitted metrics_addr defaults to loopback, pprof stays off",
			yaml:        minimalNodes,
			wantMetrics: DefaultMetricsAddr,
			wantDebug:   "",
		},
		{
			name:        "host-less addresses resolve to loopback",
			yaml:        "metrics_addr: \":9091\"\ndebug_addr: \":6060\"\n" + minimalNodes,
			wantMetrics: "127.0.0.1:9091",
			wantDebug:   "127.0.0.1:6060",
		},
		{
			name:        "an explicit address still wins",
			yaml:        "metrics_addr: \"0.0.0.0:9091\"\ndebug_addr: \"0.0.0.0:6060\"\n" + minimalNodes,
			wantMetrics: "0.0.0.0:9091",
			wantDebug:   "0.0.0.0:6060",
		},
		{
			name:        "an explicit routable address still wins",
			yaml:        "metrics_addr: \"10.0.0.5:9091\"\ndebug_addr: \"[::]:6060\"\n" + minimalNodes,
			wantMetrics: "10.0.0.5:9091",
			wantDebug:   "[::]:6060",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeCfg(t, tc.yaml))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.MetricsAddr != tc.wantMetrics {
				t.Fatalf("MetricsAddr = %q, want %q", cfg.MetricsAddr, tc.wantMetrics)
			}
			if cfg.DebugAddr != tc.wantDebug {
				t.Fatalf("DebugAddr = %q, want %q", cfg.DebugAddr, tc.wantDebug)
			}
		})
	}
}

// The default must be loopback, not a wildcard, and this asserts the
// property rather than the literal so a future retune of the port cannot
// quietly reopen the interface.
func TestDefaultMetricsAddr_IsLoopback(t *testing.T) {
	if !strings.HasPrefix(DefaultMetricsAddr, LoopbackHost+":") {
		t.Fatalf("DefaultMetricsAddr = %q, want a %s address", DefaultMetricsAddr, LoopbackHost)
	}
	host, _, found := strings.Cut(DefaultMetricsAddr, ":")
	if !found || host == "" {
		t.Fatalf("DefaultMetricsAddr = %q has no explicit host; a host-less default binds every interface", DefaultMetricsAddr)
	}
}

func TestLoadConfig_LiveProbeBounds(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		wantErr      string
		wantInterval string
		wantBurst    int
	}{
		{
			name:      "omitted leaves zeroes for the health package default",
			yaml:      minimalNodes,
			wantBurst: 0,
		},
		{
			name:         "explicit values are preserved",
			yaml:         "health_check:\n  live_probe:\n    interval: 45s\n    burst: 7\n" + minimalNodes,
			wantInterval: "45s",
			wantBurst:    7,
		},
		{
			name:    "negative interval is a startup error",
			yaml:    "health_check:\n  live_probe:\n    interval: -5s\n" + minimalNodes,
			wantErr: "interval must not be negative",
		},
		{
			name:    "negative burst is a startup error",
			yaml:    "health_check:\n  live_probe:\n    burst: -1\n" + minimalNodes,
			wantErr: "burst must not be negative",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeCfg(t, tc.yaml))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadConfig succeeded; want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadConfig error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			got := cfg.HealthCheck.LiveProbe
			if tc.wantInterval != "" && got.Interval.String() != tc.wantInterval {
				t.Fatalf("live_probe.interval = %v, want %s", got.Interval.Duration, tc.wantInterval)
			}
			if got.Burst != tc.wantBurst {
				t.Fatalf("live_probe.burst = %d, want %d", got.Burst, tc.wantBurst)
			}
		})
	}
}

// A zero from config must reach the limiter as the bounded default, not
// as "unbounded". This pins the seam between the two packages: config
// leaves zeroes alone, health resolves them.
func TestLoadConfig_ZeroLiveProbeStillBounded(t *testing.T) {
	cfg, err := LoadConfig(writeCfg(t, minimalNodes))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	lp := cfg.HealthCheck.LiveProbe
	l := health.NewProbeLimiter(lp.Interval.Duration, lp.Burst)
	if l.Interval() != health.DefaultLiveProbeInterval || l.Burst() != health.DefaultLiveProbeBurst {
		t.Fatalf("limiter from an omitted live_probe = %v/%d, want the package defaults %v/%d",
			l.Interval(), l.Burst(), health.DefaultLiveProbeInterval, health.DefaultLiveProbeBurst)
	}
}
