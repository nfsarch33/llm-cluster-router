package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/nfsarch33/llm-cluster-router/internal/channel"
)

// runGateway serves the HelixChannel gateway: the config-driven reverse proxy
// that carries agent traffic to upstream providers, plus the optional CONNECT
// tunnel used by agents that hold their own session credential.
//
// This is the server-side half of HelixChannel. It replaces the pair of
// single-upstream daemons the pilot ran by hand: one process, one config file,
// any number of routes, each with its own feature flag.
func runGateway(args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	configPath := fs.String("config", envOrDefault("HELIXCHANNEL_GATEWAY_CONFIG", "/etc/helixchannel/gateway.yml"),
		"path to the gateway YAML config")
	listen := fs.String("listen", "", "override the config's listen address")
	printRoutes := fs.Bool("print-routes", false, "print the enabled route table as JSON and exit")
	if err := fs.Parse(filterTestFlags(args)); err != nil {
		return err
	}

	cfg, err := channel.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	auditWriter := io.Writer(os.Stdout)
	if cfg.AuditLog != "" {
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		defer func() { _ = f.Close() }()
		auditWriter = f
	}

	srv, err := channel.NewServer(cfg, channel.NewHTTPForwarder(), channel.NewAuditor(auditWriter))
	if err != nil {
		return err
	}

	if *printRoutes {
		names := srv.RouteNames()
		sort.Strings(names)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"listen": cfg.Listen, "routes": names, "connect": cfg.Connect.Enabled,
		})
	}

	fmt.Fprintf(os.Stderr, "helixchannel gateway listening on %s routes=%v connect=%t\n",
		cfg.Listen, srv.RouteNames(), cfg.Connect.Enabled)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.ListenAndServe(ctx)
}

// runProxy serves the loopback client proxy that lets an agent route through
// HelixChannel by setting HTTPS_PROXY — the path for agents (Claude Code being
// the motivating one) whose own credential must reach the provider intact and
// whose functionality degrades when pointed at a rewritten base URL.
func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	listen := fs.String("listen", envOrDefault("HELIXCHANNEL_PROXY_LISTEN", "127.0.0.1:47820"),
		"loopback listen address for the agent to point HTTPS_PROXY at")
	gateway := fs.String("gateway", envOrDefault("HELIXCHANNEL_GATEWAY", ""),
		"channel edge as host:port (TLS), e.g. helixchannel.example.com:8443")
	tokenEnv := fs.String("token-env", "HELIXCHANNEL_CONNECT_TOKEN",
		"environment variable holding the CONNECT token")
	tokenFile := fs.String("token-file", "", "file holding the CONNECT token")
	insecure := fs.Bool("insecure", false,
		"skip verification of the gateway certificate (pilot edges with self-signed certs only; the agent's own TLS to the provider is still verified end to end)")
	printEnv := fs.Bool("print-env", false, "print the environment variables an agent needs, then exit")
	if err := fs.Parse(filterTestFlags(args)); err != nil {
		return err
	}

	if *printEnv {
		env := channel.ProxyEnv(*listen)
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%s=%s\n", k, env[k])
		}
		return nil
	}

	if *gateway == "" {
		return fmt.Errorf("--gateway is required (or set HELIXCHANNEL_GATEWAY)")
	}
	token, err := resolveConnectToken(*tokenEnv, *tokenFile)
	if err != nil {
		return err
	}

	p := &channel.ClientProxy{
		Listen:             *listen,
		Gateway:            *gateway,
		Token:              token,
		InsecureSkipVerify: *insecure,
		Audit:              channel.NewAuditor(os.Stdout),
	}
	fmt.Fprintf(os.Stderr, "helixchannel proxy listening on %s -> %s\n", *listen, *gateway)
	fmt.Fprintf(os.Stderr, "point the agent at it with: helixchannel proxy --listen %s --print-env\n", *listen)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return p.ListenAndServe(ctx)
}

// resolveConnectToken reads the CONNECT token from an environment variable or
// a file. The value is never echoed.
func resolveConnectToken(envName, filePath string) (string, error) {
	if envName != "" {
		if v := os.Getenv(envName); v != "" {
			return v, nil
		}
	}
	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		if v := trimSpace(string(b)); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("token file %s is empty", filePath)
	}
	return "", fmt.Errorf("no CONNECT token: set %s or pass --token-file", envName)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// filterTestFlags drops flags injected by "go test" from an argv slice.
//
// Subcommands build their own flag.FlagSet, and a FlagSet errors on unknown
// flags. When a test binary runs a subcommand in-process, the harness's own
// -test.* flags are still on os.Args and would abort parsing. Every
// flag-bearing subcommand must route argv through this helper first.
func filterTestFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-test.") || strings.HasPrefix(a, "--test.") {
			continue
		}
		out = append(out, a)
	}
	return out
}
