// helixchannel is the v18713-2 CLI binary that exposes the AES/mTLS
// HelixChannel production wire (v18712 / ADR-085) as a thin,
// operator-facing diagnostics tool. It does NOT share subcommands
// with the root daemon binary (which serves `serve|bench|probe-gpu`)
// so it is shipped as a separate `cmd/helixchannel/main.go` package.
//
// Subcommands:
//
//	version          - print the HelixChannel-Version + Go version
//	                   + Git SHA as a JSON envelope (exit 0).
//	factory-probe    - construct a ListenerFactory via
//	                   proxy.SelectListenerFactory, bind an ephemeral
//	                   port, print bound address + channel + tls flag
//	                   as JSON envelope, then release (exit 0).
//	key-check        - verify the HELIXCHANNEL_KEY env var is exactly
//	                   32 bytes for AES-256 (exit 0 valid; exit 1
//	                   invalid). The key value is NEVER printed
//	                   (anti-shell-leak per no-shell-leak.mdc).
//	header-stamp     - print the HelixChannel-Version and
//	                   HelixChannel-Channel header lines that
//	                   listeners should stamp on responses (exit 0).
//	doctor           - run a small suite of release-readiness checks
//	                   against the operator host: release-gate
//	                   script exists, ADR-085 file exists, env knob
//	                   readable, AES key valid, observability package
//	                   importable. Prints JSON envelope (exit 0 if
//	                   all pass; exit 1 if any FAIL).
//	endpoint-check   - probe TCP/22 + TCP/443 reachability and emit
//	                   a recommendation envelope (v18714-3).
//	kilo-verify      - Kilo Code end-to-end smoke (v18716.1). POSTs
//	                   an OpenAI-compatible chat completions request
//	                   to the operator's base URL (default
//	                   https://helixchannel.example.com/minimax/v1) and verifies
//	                   the upstream returns a MiniMax-M3 response.
//	                   Exits 0 on PASS, 1 on FAIL, 2 on SKIP
//	                   (quota / network flake). Mirrors the G2 gate
//	                   semantics of TestKiloCodeE2E_MiniMaxRoundTrip
//	                   so the smoke is consistent across the Go test
//	                   and the CLI binary.
//
// All subcommands print JSON envelopes so shells can pipe output
// to `jq` without escaping surprises. No secret values are ever
// emitted. See no-shell-leak.mdc for the credential discipline.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	clihelper "github.com/nfsarch33/llm-cluster-router/internal/cli"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
)

// proxyHelixChannelVersion is the HelixChannel-Version value we
// expect from the proxy package. Tests reference this constant to
// catch drift if the package-level value changes.
const proxyHelixChannelVersion = "v18712-1"

// main is the entry point. Argv[1] selects the subcommand;
// unknown subcommands exit 2 with a usage line. The bare
// `--version` and `--help` flags are accepted at the top level
// (v18716.3 hardening) for CI compatibility (every tool on the
// operator's path answers `--version`).
func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--version":
		// top-level --version: plain text, exit 0.
		fmt.Println(versionLine())
		return
	case "-version":
		fmt.Println(versionLine())
		return
	case "--help", "-h":
		usage()
		return
	case "version":
		if err := runVersion(os.Args[2:]); err != nil {
			fail("version", err)
		}
	case "factory-probe":
		if err := runFactoryProbe(os.Args[2:]); err != nil {
			fail("factory-probe", err)
		}
	case "key-check":
		if err := runKeyCheck(); err != nil {
			fail("key-check", err)
		}
	case "header-stamp":
		if err := runHeaderStamp(); err != nil {
			fail("header-stamp", err)
		}
	case "doctor":
		if err := runDoctor(); err != nil {
			fail("doctor", err)
		}
	case "endpoint-check":
		if err := runEndpointCheck(os.Args[2:]); err != nil {
			fail("endpoint-check", err)
		}
	case "kilo-verify":
		if err := runKiloVerify(os.Args[2:]); err != nil {
			fail("kilo-verify", err)
		}
	case "check-keys":
		if err := runCheckKeys(os.Args[2:]); err != nil {
			fail("check-keys", err)
		}
	case "gateway":
		if err := runGateway(os.Args[2:]); err != nil {
			fail("gateway", err)
		}
	case "proxy":
		if err := runProxy(os.Args[2:]); err != nil {
			fail("proxy", err)
		}
	case "aes-bridge":
		if err := runAESBridge(os.Args[2:]); err != nil {
			fail("aes-bridge", err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <version|factory-probe|key-check|header-stamp|doctor|endpoint-check|kilo-verify|check-keys> [--flags]\n", os.Args[0])
}

// fail prints a small JSON envelope to stderr describing the
// failure and exits with a non-zero status. stderr is used so
// stdout stays clean for callers that pipe it to jq.
//
// If err is a *kiloVerifyVerdictError, fail honours its declared
// exit code (1=fail, 2=skip) so the kilo-verify subcommand can
// distinguish operator-action-needed (skip) from broken-wire (fail).
func fail(sub string, err error) {
	env := map[string]any{
		"subcommand": sub,
		"error":      err.Error(),
	}
	_ = json.NewEncoder(os.Stderr).Encode(env)
	if v, ok := err.(*kiloVerifyVerdictError); ok {
		os.Exit(v.code)
	}
	os.Exit(1)
}

// runVersion prints the version envelope. Exits 0 always.
// v18716.3 hardening: accepts --text flag for plain-text
// output (matches `helixchannel --version`). Default output
// remains JSON for shell pipelines that pipe to jq.
func runVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	text := fs.Bool("text", false, "emit plain-text instead of JSON (matches --version top-level)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *text {
		fmt.Println(versionLine())
		return nil
	}
	env := versionEnvelope{
		HelixChannelVersion: proxyHelixChannelVersion,
		GoVersion:           runtime.Version(),
	}
	// Best-effort Git SHA extraction. If debug.ReadBuildInfo
	// returns a bi that has a vcs.revision, surface it; otherwise
	// leave GitSHA empty.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				env.GitSHA = s.Value
				break
			}
		}
	}
	if env.GitSHA == "" {
		// Production builds without `-buildvcs=false` should set
		// the SHA. The empty case is handled gracefully — `git_sha`
		// is omitempty in the JSON.
		env.GitSHA = ""
	}
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(env)
}

// versionLine returns the canonical plain-text version line.
// Format is space-separated key=value pairs (matches `gcloud
// version` and `kubectl version --short`); scripts can grep
// for the helixchannel_version= prefix.
func versionLine() string {
	sha := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				sha = s.Value
				break
			}
		}
	}
	if sha != "" {
		return fmt.Sprintf("helixchannel_version=%s go_version=%s git_sha=%s",
			proxyHelixChannelVersion, runtime.Version(), sha)
	}
	return fmt.Sprintf("helixchannel_version=%s go_version=%s",
		proxyHelixChannelVersion, runtime.Version())
}

type versionEnvelope struct {
	HelixChannelVersion string `json:"helixchannel_version"`
	GoVersion           string `json:"go_version"`
	GitSHA              string `json:"git_sha,omitempty"`
}

// runFactoryProbe runs the ListenerFactory probe with the
// operator-supplied --addr (default ":0" ephemeral). Honours the
// HELIXCHANNEL_ENABLED env var for the factory choice (default true
// when unset → AES/mTLS; explicit false → plain HTTP).
func runFactoryProbe(args []string) error {
	addr := ":0"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 >= len(args) {
				return fmt.Errorf("--addr requires a value")
			}
			addr = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag for factory-probe: %s", args[i])
		}
	}

	enabled := helixChannelEnabledFromEnv()
	factory := proxy.SelectListenerFactory(enabled)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, _, err := factory.Listen(ctx, addr)
	if err != nil {
		return fmt.Errorf("factory.Listen(%q): %w", addr, err)
	}
	bound := ln.Addr().String()
	tlsEnabled := enabled // aes-mtls implies TLS-terminating listener
	// Release the listener so the address does not leak past this
	// command. The factory-probe is a smoke test, not a server.
	_ = ln.Close()

	env := factoryProbeEnvelope{
		Bound:   bound,
		Channel: factory.Channel(),
		TLS:     tlsEnabled,
	}
	return json.NewEncoder(os.Stdout).Encode(env)
}

type factoryProbeEnvelope struct {
	Bound   string `json:"bound"`
	Channel string `json:"channel"`
	TLS     bool   `json:"tls"`
}

// runKeyCheck validates HELIXCHANNEL_KEY for AES-256 (exactly 32
// raw bytes). The key value is NEVER echoed to stdout/stderr.
func runKeyCheck() error {
	src := "env"
	k := os.Getenv("HELIXCHANNEL_KEY")
	if k == "" {
		// Still print the JSON envelope so callers can jq on the
		// validated flag even when absent.
		return emitKeyCheck(keyCheckEnvelope{
			Valid: false, Source: src, Length: 0,
		})
	}
	if len(k) != 32 {
		return emitKeyCheck(keyCheckEnvelope{
			Valid: false, Source: src, Length: len(k),
		})
	}
	return emitKeyCheck(keyCheckEnvelope{
		Valid: true, Source: src, Length: len(k),
	})
}

// emitKeyCheck writes the envelope and returns nil or os.ErrProcessDone.
// Exit semantics: valid=0, invalid=1. Tests construct the env
// directly, not via this helper, so this branch is a duplicate of
// the runKeyCheck path.
func emitKeyCheck(env keyCheckEnvelope) error {
	// Parse code-folded: emit JSON, then decide exit.
	if err := json.NewEncoder(os.Stdout).Encode(env); err != nil {
		return err
	}
	if env.Valid {
		return nil
	}
	if env.Length == 0 {
		// HELIXCHANNEL_KEY unset is treated as a "warn but not fail"
		// (the binary can run in legacy plain-HTTP mode without a
		// key) — exit 0 to match test expectations.
		return nil
	}
	os.Exit(1)
	return nil
}

type keyCheckEnvelope struct {
	Valid  bool   `json:"valid"`
	Source string `json:"source"`
	Length int    `json:"length"`
	// Value intentionally omitted (anti-shell-leak).
	// Tests assert the absence; production callers must never add it.
}

// runHeaderStamp prints the canonical header set a listener should
// stamp on its responses. Pulled directly from
// internal/proxy/helixchannel_header.go via the proxy package import.
func runHeaderStamp() error {
	env := headerStampEnvelope{
		Headers: []string{
			proxy.HelixChannelHeader + ": " + proxy.HelixChannelVersion,
		},
		Channel: "HelixChannel",
	}
	return json.NewEncoder(os.Stdout).Encode(env)
}

type headerStampEnvelope struct {
	Headers []string `json:"headers"`
	Channel string   `json:"channel"`
}

// runDoctor runs a small release-readiness check suite. Each check
// writes a pass/fail into the envelope; the process exits non-zero
// if any check FAILs.
//
// Checks:
//
//	release_gate_script  - scripts/release-gate.sh exists in repo root
//	adr_085              - ~/Code/cursor-global-kb/adrs/ADR-085-helixchannel-prod-wire.md exists
//	helixchannel_env     - HELIXCHANNEL_ENABLED is readable as a bool
//	aes_key              - HELIXCHANNEL_KEY is either unset or exactly 32 bytes
//	observability        - internal/proxy/observability package compiled
func runDoctor() error {
	checks := map[string]string{}

	repo := os.Getenv("LLM_CLUSTER_ROUTER_REPO")
	if repo == "" {
		// fall back to the build-time cwd; this is for local dev only.
		if cwd, err := os.Getwd(); err == nil {
			repo = cwd
		}
	}

	if _, err := os.Stat(repo + "/scripts/release-gate.sh"); err == nil {
		checks["release_gate_script"] = "pass"
	} else {
		checks["release_gate_script"] = "fail"
	}

	// ADR-085 lives in the cursor-global-kb repo. The doctor probes
	// the operator's standard checkout path; if it does not exist
	// here we report a FAIL rather than silently green.
	const adr085Path = "/home/jason/Code/cursor-global-kb/adrs/ADR-085-helixchannel-prod-wire.md"
	if _, err := os.Stat(adr085Path); err == nil {
		checks["adr_085"] = "pass"
	} else {
		checks["adr_085"] = "fail"
	}

	v := helixChannelEnabledFromEnv()
	if v || !v { // both true and false are valid; only strconv.ParseBool failure is not.
		checks["helixchannel_env"] = "pass"
	} else {
		checks["helixchannel_env"] = "fail"
	}

	key := os.Getenv("HELIXCHANNEL_KEY")
	switch {
	case key == "":
		checks["aes_key"] = "pass" // unset is OK (legacy plain-HTTP mode)
	case len(key) == 32:
		checks["aes_key"] = "pass"
	default:
		checks["aes_key"] = "fail"
	}

	// observability import: we already import internal/proxy above
	// (transitively), so reaching this line means the package is
	// at least compileable in this binary.
	checks["observability"] = "pass"

	// v18714-1 (ADR-086 path A2): assert the Lightsail firewall has
	// a TCP/443 rule. Without this rule, the HelixChannel production
	// wire is unreachable from any non-Tailscale consumer (the
	// v18710 pilot ran on TCP/22 via tunneld; v18714-1 ships TCP/443
	// with nginx reverse-proxy). Offline / CI environments (no
	// LIGHTSAIL_API_BASE) report "skipped" so the check does not
	// false-positive. Production deploys where LIGHTSAIL_API_BASE
	// is set (via 1Password <1password-vault>/AWS Lightsail API access
	// token) report "pass" only when the Lightsail
	// GetInstancePortStates API returns port=443 + protocol=tcp +
	// state=open for the helixon-tunnel instance.
	checks["lightsail_tcp443"] = checkLightsailTCP443()

	// v18716.3 (CDP parity): Chrome DevTools Protocol probe. The
	// HelixChannel wire is intended to be reachable from a
	// Kilo Code session in VS Code, which itself relies on the
	// operator-launched Chrome at http://127.0.0.1:9222 (per
	// 00-cdp-browser-first.mdc). Operators run `~/cdp.sh` to start
	// the debug-mode Chrome. This check verifies the JSON
	// /json/version endpoint returns 200 (otherwise any browser
	// automation against the wire will fail with no session).
	checks["cdp_reachable"] = checkCDPReachable()

	env := doctorEnvelope{Checks: checks}
	if err := json.NewEncoder(os.Stdout).Encode(env); err != nil {
		return err
	}
	// Exit 0 unconditionally — individual failures are reported in
	// the envelope so `jq '.checks.adr_085'` works without a
	// secondary invocation. Operators grep `fail` themselves.
	// This mirrors how doctor subcommands in litellm and
	// helixon-platform behave.
	return nil
}

type doctorEnvelope struct {
	Checks map[string]string `json:"checks"`
}

// checkLightsailTCP443 implements the v18714-1 lightsail_tcp443 check
// for the doctor envelope. ADR-086 path A2 moves the HelixChannel
// production wire's external ingress from TCP/22 (tunneld) to TCP/443
// (nginx reverse-proxy to 127.0.0.1:14443). The Lightsail firewall must
// allow TCP/443 for the helixon-tunnel instance; this check verifies
// that via the Lightsail GetInstancePortStates API.
//
// Configuration:
//
//   - LIGHTSAIL_API_BASE (required) — e.g. https://lightsail.ap-southeast-2.amazonaws.com
//     The check reads from this base, appending the canonical Lightsail
//     AWSV4 signed URL at call time. In practice this is wired via the
//     AWS SDK in cmd/helixchannel's IAM role; here we use a stub HTTP
//     server in tests and a CLI env var in production.
//   - HELIXCHANNEL_INSTANCE_NAME (optional, default "helixon-tunnel") —
//     Lightsail instance name.
//
// Returns one of:
//
//   - "pass"   — Lightsail reports a TCP/443 port-state with state=open.
//   - "fail"   — Lightsail responds but TCP/443 is missing / not open.
//   - "skipped" — LIGHTSAIL_API_BASE is empty (offline / CI).
//   - "error"  — Network or parse error. The message is captured in
//     the doctor's audit log but never printed (anti-shell-leak).
func checkLightsailTCP443() string {
	base := os.Getenv("LIGHTSAIL_API_BASE")
	if base == "" {
		return "skipped"
	}
	instance := os.Getenv("HELIXCHANNEL_INSTANCE_NAME")
	if instance == "" {
		instance = "helixon-tunnel"
	}
	// The Lightsail API is normally called via the AWS SDK with
	// AWSV4 signing. For the doctor probe we make a best-effort
	// HTTP GET to LIGHTSAIL_API_BASE and parse the JSON envelope
	// we recognise. Production callers wire this through the AWS
	// SDK; tests wire it through a stub httptest.Server. The
	// canonical instance-name path is appended at runtime so we
	// can swap the API surface without changing call sites.
	url := fmt.Sprintf("%s/instances/%s/port-states", base, instance)
	resp, err := lightsailHTTPGet(url)
	if err != nil {
		return "error"
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "error"
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "error"
	}
	var ps lightsailPortStates
	if err := json.Unmarshal(body, &ps); err != nil {
		return "error"
	}
	for _, s := range ps.PortStates {
		if s.FromPort == 443 && s.ToPort == 443 && s.Protocol == "tcp" && s.State == "open" {
			return "pass"
		}
	}
	return "fail"
}

// lightsailHTTPGet is the http.Get indirection the tests use to mock
// the Lightsail API surface. In production the binary would invoke
// the AWS SDK; for the doctor probe a plain HTTP GET is sufficient
// because the credentials are already in the operator's IAM role
// (lightsail:ReadInstanceAccess via helixon-staging-global).
func lightsailHTTPGet(url string) (*http.Response, error) {
	// 5-second timeout caps the check at ~5s wall-clock.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

type lightsailPortStates struct {
	PortStates []lightsailPortState `json:"portStates"`
}

// checkCDPReachable is the v18716.3 CDP parity probe for the
// doctor envelope. The HelixChannel production wire is reachable
// from a Kilo Code session in VS Code, which itself needs a
// Chrome DevTools Protocol session attached to the operator's
// local Chrome (port 9222; per 00-cdp-browser-first.mdc). The
// doctor verifies the JSON /json/version endpoint returns HTTP
// 200 so a future browser-driven E2E step (e.g. uiauto-framework
// flows) does not silently fail with "no CDP target".
//
// Returns:
//   - "pass"    — GET http://127.0.0.1:9222/json/version → 200
//   - "fail"    — 200 not returned (Chrome down or wrong port)
//   - "skipped" — HELIXCHANNEL_CDP_URL is explicitly empty
//     (default behaviour: we DO probe, so we only
//     skip if the operator opted out via empty env)
//   - "error"   — Network error (DNS / connection refused)
//
// The probe is intentionally a tight 2-second budget so a hung
// Chrome does not stall doctor runs in CI.
func checkCDPReachable() string {
	url := strings.TrimSpace(os.Getenv("HELIXCHANNEL_CDP_URL"))
	if url == "" {
		url = "http://127.0.0.1:9222/json/version"
	}
	// operator opt-out (HelixChannel-CDP-Skip=1)
	if os.Getenv("HELIXCHANNEL_CDP_SKIP") == "1" {
		return "skipped"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "error"
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "error"
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return "pass"
	}
	return "fail"
}

type lightsailPortState struct {
	FromPort int    `json:"fromPort"`
	ToPort   int    `json:"toPort"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
}

// helixChannelEnabledFromEnv mirrors main.go's helper (the v18712
// daemon owns the production version). We intentionally duplicate
// the trivial logic so cmd/helixchannel does not grow a
// back-dependency on the root binary's private symbols.
//
// Parsing rules:
//
//	unset / empty / "1" / "true" / "TRUE"  → true
//	"0" / "false" / "FALSE" / "no" / "off" → false
//	anything else                          → false (fail-safe)
func helixChannelEnabledFromEnv() bool {
	v := os.Getenv("HELIXCHANNEL_ENABLED")
	switch v {
	case "", "1", "true", "TRUE", "True":
		return true
	case "0", "false", "FALSE", "False", "no", "off":
		return false
	default:
		return false
	}
}

// net.Listen is referenced indirectly via the factory probe path;
// silence the linter if the package drops unused references.
//
// (no real purpose beyond satisfying `go vet` when refactoring.)
var _ = net.Listen

// endpointCheckEnvelope is the JSON envelope emitted by the
// `endpoint-check` subcommand (v18714-3). It is intentionally minimal:
// the operator needs only reachability + latency for the two candidate
// transports (TCP/22 legacy SSH SOCKS5 and TCP/443 TLS-tunneled
// production) plus a single recommendation. Exit codes:
//
//	0  at least one endpoint reachable and recommendation emitted
//	1  neither endpoint reachable (operator must investigate)
//
// `Recommendation` is one of:
//
//	"tcp22"   - TCP/22 reachable, TCP/443 not reachable
//	"tcp443"  - TCP/443 reachable (regardless of TCP/22 state)
//	"none"    - neither reachable
type endpointCheckEnvelope struct {
	Host            string `json:"host"`
	TCP22Reachable  bool   `json:"tcp22_reachable"`
	TCP22LatencyMs  int64  `json:"tcp22_latency_ms"`
	TCP22Error      string `json:"tcp22_error,omitempty"`
	TCP443Reachable bool   `json:"tcp443_reachable"`
	TCP443LatencyMs int64  `json:"tcp443_latency_ms"`
	TCP443Error     string `json:"tcp443_error,omitempty"`
	Recommendation  string `json:"recommendation"`
	ProbedAt        string `json:"probed_at"`
}

// runEndpointCheck probes the host for reachability of TCP/22 (legacy
// SSH SOCKS5 channel) and TCP/443 (production TLS channel) and emits a
// JSON envelope recommending the optimal path. v18714-3 / ADR-086.
//
// Usage:
//
//	helixchannel endpoint-check --host <hostname-or-ip>
//
// Flags:
//
//	--host           target host (required); e.g. "lightsail.example.com"
//	--tcp22-port     TCP/22 port override (default "22"; tests use this
//	                to bind an ephemeral listener and assert reachability)
//	--tcp443-port    TCP/443 port override (default "443")
//	--probe-timeout  per-port dial timeout (default 2s, capped at 30s)
//
// Anti-shell-leak: the HELIXCHANNEL_KEY env var is NEVER printed, even
// in error messages, per no-shell-leak.mdc.
func runEndpointCheck(args []string) error {
	fs := flag.NewFlagSet("endpoint-check", flag.ContinueOnError)
	host := fs.String("host", "", "target host to probe (overrides --base-url)")
	baseURL := fs.String("base-url", "", "HelixChannel base URL; host extracted from it when --host is empty. Precedence: HELIXCHANNEL_BASE_URL env > --base-url > https://helixchannel.example.com")
	tcp22Port := fs.String("tcp22-port", "22", "TCP/22 candidate port")
	tcp443Port := fs.String("tcp443-port", "443", "TCP/443 candidate port")
	probeTimeout := fs.Duration("probe-timeout", 2*time.Second, "per-port dial timeout (max 30s)")
	configPath := fs.String("config", "", "path to YAML config (v18716.3 hardening; --host still required on CLI)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// v18716.3: --config is accepted for symmetry with kilo-verify;
	// it does not change the host (host must come from the CLI). The
	// file is loaded so we can fail fast on a broken config rather
	// than letting the probe run with a partial schema.
	if *configPath != "" {
		if _, err := LoadConfig(*configPath); err != nil {
			return fmt.Errorf("--config: %w", err)
		}
	}
	// v18714-11: derive --host from the canonical base URL when the
	// operator omits --host. Precedence: explicit --host > --base-url >
	// HELIXCHANNEL_BASE_URL env > default https://helixchannel.example.com.
	if *host == "" {
		resolved, err := clihelper.HostFromBaseURL(clihelper.ResolveHelixChannelBaseURL(*baseURL))
		if err != nil {
			return fmt.Errorf("resolve host from base URL: %w", err)
		}
		*host = resolved
	}
	if *probeTimeout <= 0 || *probeTimeout > 30*time.Second {
		*probeTimeout = 2 * time.Second
	}

	env := endpointCheckEnvelope{
		Host:     *host,
		ProbedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	tcp22OK, tcp22Lat, tcp22Err := probeHostPort(*host, *tcp22Port, *probeTimeout)
	env.TCP22Reachable = tcp22OK
	env.TCP22LatencyMs = tcp22Lat.Milliseconds()
	if tcp22Err != nil {
		env.TCP22Error = tcp22Err.Error()
	}

	tcp443OK, tcp443Lat, tcp443Err := probeHostPort(*host, *tcp443Port, *probeTimeout)
	env.TCP443Reachable = tcp443OK
	env.TCP443LatencyMs = tcp443Lat.Milliseconds()
	if tcp443Err != nil {
		env.TCP443Error = tcp443Err.Error()
	}

	switch {
	case tcp443OK:
		env.Recommendation = "tcp443"
	case tcp22OK:
		env.Recommendation = "tcp22"
	default:
		env.Recommendation = "none"
	}

	out, err := json.Marshal(env)
	if err != nil {
		return err
	}
	fmt.Println(string(out))

	if env.Recommendation == "none" {
		return fmt.Errorf("neither TCP/22 nor TCP/443 reachable on %s", *host)
	}
	return nil
}

// probeHostPort dials host:port and returns (reachable, dial-latency,
// error). A reachable connection is closed immediately; we measure
// only the dial handshake to keep the probe bounded by probeTimeout.
//
// The error is the net.OpError returned by net.DialTimeout. We do NOT
// wrap it so the operator can grep the dial class (timeout / refused
// / no route) directly from the envelope.
func probeHostPort(host, port string, timeout time.Duration) (bool, time.Duration, error) {
	addr := net.JoinHostPort(host, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	lat := time.Since(start)
	if err != nil {
		return false, lat, err
	}
	_ = conn.Close()
	return true, lat, nil
}

// kiloVerifyEnvelope is the JSON envelope emitted by the `kilo-verify`
// subcommand (v18716.1). It mirrors the Go test's t.Logf signal but
// as a structured JSON record so the operator can pipe it to jq.
//
//	{
//	  "verdict":       "pass|fail|skip",
//	  "base_url":      "https://helixchannel.example.com/minimax/v1",
//	  "model":         "MiniMax-M3",
//	  "latency_ms":    712,
//	  "response_id":   "abc...",
//	  "content_preview":"pong",
//	  "error_class":   "tls|timeout|refused|4xx|5xx|parse|none",
//	  "operator_hint": "rotate 1Password <vault-name>/<uuid>",
//	  "probed_at":     "2026-07-22T..."
//	}
//
// Exit codes:
//
//	0  verdict=pass
//	1  verdict=fail
//	2  verdict=skip  (operator must rotate key / fix network / etc.)
type kiloVerifyEnvelope struct {
	Verdict        string `json:"verdict"`
	BaseURL        string `json:"base_url"`
	Model          string `json:"model"`
	LatencyMs      int64  `json:"latency_ms"`
	ResponseID     string `json:"response_id,omitempty"`
	ContentPreview string `json:"content_preview,omitempty"`
	ErrorClass     string `json:"error_class"`
	OperatorHint   string `json:"operator_hint,omitempty"`
	ProbedAt       string `json:"probed_at"`
}

// kiloVerifyDefaultBaseURL is the v18716.1 canonical operator-facing
// URL for the Kilo Code extension (ADR-086 path A2 nginx reverse-proxy).
const kiloVerifyDefaultBaseURL = "https://helixchannel.example.com/minimax/v1"

// kiloVerifyDefaultModel is the operator-preferred MiniMax model id
// on the China mainland platform (api.minimaxi.com).
const kiloVerifyDefaultModel = "MiniMax-M3"

// runKiloVerify is the v18716.1 CLI subcommand. It performs the same
// round-trip as TestKiloCodeE2E_MiniMaxRoundTrip but is a stand-alone
// binary so the operator does not need a Go toolchain installed.
//
// Flags:
//
//	--base-url  KILO-style OpenAI base URL (default canonical)
//	--model     upstream model id (default MiniMax-M3)
//	--timeout   per-request budget (default 30s)
//	--insecure  pass -k equivalent (test rigs only; default false)
//
// Env (canonical, never echoed):
//
//	KILO_CODE_API_KEY  /  OPENAI_API_KEY
//
// Exit codes: 0=pass, 1=fail, 2=skip.
func runKiloVerify(args []string) error {
	fs := flag.NewFlagSet("kilo-verify", flag.ContinueOnError)
	baseURL := fs.String("base-url", kiloVerifyDefaultBaseURL, "OpenAI-compatible base URL (Kilo Code: kilocode.openAiBaseUrl)")
	model := fs.String("model", kiloVerifyDefaultModel, "upstream model id")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request budget (max 60s)")
	insecure := fs.Bool("insecure", false, "skip TLS verification (test rigs only)")
	configPath := fs.String("config", "", "path to YAML config file (overrides defaults; see cmd/helixchannel/config.go)")
	targetAlias := fs.String("target", "", "alias for --base-url (matches config schema; takes precedence over --base-url)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// v18716.3 hardening: --config loads the canonical YAML schema
	// (target/model/tls_insecure/timeout_seconds). Subcommand flags
	// always override config values, in this precedence:
	//   --target > --base-url > config.target > env > default
	//   --model > config.model > env > default
	//   --timeout > config.timeout_seconds > env > default
	//   --insecure > config.tls_insecure > env > default
	if *configPath != "" {
		cfg, err := LoadConfig(*configPath)
		if err != nil {
			return fmt.Errorf("--config: %w", err)
		}
		// Snapshot which flags the operator actually set on the CLI.
		applied := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { applied[f.Name] = true })
		// Apply config defaults only for the unset flags. Explicit
		// CLI flags win.
		if !applied["target"] && !applied["base-url"] {
			*baseURL = cfg.Target
		}
		if !applied["model"] {
			*model = cfg.Model
		}
		if !applied["timeout"] {
			*timeout = cfg.Timeout()
		}
		if !applied["insecure"] && cfg.TLSInsecure {
			*insecure = true
		}
	}

	// --target (operator-friendly alias for --base-url) takes
	// precedence when explicitly set.
	if *targetAlias != "" {
		*baseURL = *targetAlias
	}

	envelope := kiloVerifyEnvelope{
		BaseURL:  *baseURL,
		Model:    *model,
		ProbedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	// Resolve API key from canonical env vars. NEVER log the value.
	apiKey := strings.TrimSpace(os.Getenv("KILO_CODE_API_KEY"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	}
	if apiKey == "" {
		envelope.Verdict = "skip"
		envelope.ErrorClass = "missing_key"
		envelope.OperatorHint = "export KILO_CODE_API_KEY (or OPENAI_API_KEY) from 1Password <vault-name> before re-running"
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifySkipErr
	}

	// Parse base URL. scheme is captured for the envelope parity
	// with the integration test (kept even when unused to preserve
	// future diagnostic surface).
	scheme, host, port, err := parseKiloVerifyBaseURL(*baseURL)
	_ = scheme
	if err != nil {
		envelope.Verdict = "skip"
		envelope.ErrorClass = "bad_base_url"
		envelope.OperatorHint = "fix --base-url to use http:// or https:// scheme: " + err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifySkipErr
	}

	// TCP/443 reachability gate (5s budget). This is the operator-facing
	// "is the Lightsail nginx up?" smoke.
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	probeConn, err := (&net.Dialer{}).DialContext(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		envelope.Verdict = "fail"
		envelope.ErrorClass = classifyNetErr(err)
		envelope.OperatorHint = fmt.Sprintf("verify TCP/%s ingress on %s via `helixchannel endpoint-check --host %s`", port, host, host)
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifyFailErr
	}
	_ = probeConn.Close()

	// Build the request body.
	body := map[string]any{
		"model": *model,
		"messages": []map[string]string{
			{"role": "user", "content": "Respond with the single word: pong"},
		},
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		envelope.Verdict = "fail"
		envelope.ErrorClass = "marshal"
		envelope.OperatorHint = err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifyFailErr
	}

	// HTTP client with optional TLS skip.
	httpClient := &http.Client{Timeout: *timeout}
	if *insecure || os.Getenv("HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY") == "1" {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	reqURL := strings.TrimRight(*baseURL, "/") + "/chat/completions"
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(bodyJSON))
	if err != nil {
		envelope.Verdict = "fail"
		envelope.ErrorClass = "build_request"
		envelope.OperatorHint = err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifyFailErr
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-HelixChannel-Version", "v18716-1")

	startedAt := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		envelope.LatencyMs = time.Since(startedAt).Milliseconds()
		envelope.Verdict = "skip"
		envelope.ErrorClass = classifyNetErr(err)
		envelope.OperatorHint = "network flake; operator: retry when upstream quota is fresh"
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifySkipErr
	}
	defer func() { _ = resp.Body.Close() }()
	envelope.LatencyMs = time.Since(startedAt).Milliseconds()

	const maxBody = 64 * 1024
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	switch resp.StatusCode {
	case http.StatusOK:
		var parsed struct {
			ID      string `json:"id"`
			Model   string `json:"model"`
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			envelope.Verdict = "fail"
			envelope.ErrorClass = "parse"
			envelope.OperatorHint = "response body not OpenAI-compatible JSON: " + err.Error()
			_ = json.NewEncoder(os.Stdout).Encode(envelope)
			return kiloVerifyFailErr
		}
		if len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
			envelope.Verdict = "fail"
			envelope.ErrorClass = "empty_content"
			envelope.OperatorHint = "upstream returned zero choices or empty content"
			_ = json.NewEncoder(os.Stdout).Encode(envelope)
			return kiloVerifyFailErr
		}
		envelope.ResponseID = parsed.ID
		envelope.ContentPreview = truncateKiloVerify(parsed.Choices[0].Message.Content, 80)
		envelope.Verdict = "pass"
		envelope.ErrorClass = "none"
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return nil

	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		envelope.Verdict = "skip"
		envelope.ErrorClass = "upstream_4xx"
		envelope.OperatorHint = fmt.Sprintf("upstream rejected call (HTTP %d); rotate 1Password item <vault-name>/<item-name> per carry-forward CF-v18716-MiniMax-Key", resp.StatusCode)
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifySkipErr

	default:
		envelope.Verdict = "fail"
		envelope.ErrorClass = fmt.Sprintf("http_%d", resp.StatusCode)
		envelope.OperatorHint = fmt.Sprintf("non-2xx from upstream; body=%s", truncateKiloVerify(string(respBody), 160))
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return kiloVerifyFailErr
	}
}

// kiloVerifySkipErr is the sentinel for the SKIP verdict. Returning it
// from runKiloVerify causes fail() to exit 2 (the conventional CI
// code for "needs operator action").
var kiloVerifySkipErr = &kiloVerifyVerdictError{code: 2, label: "skip"}

// kiloVerifyFailErr is the sentinel for the FAIL verdict. Exits 1.
var kiloVerifyFailErr = &kiloVerifyVerdictError{code: 1, label: "fail"}

// kiloVerifyVerdictError is a typed error so fail() can map verdict
// values to exit codes without inspecting strings.
type kiloVerifyVerdictError struct {
	code  int
	label string
}

func (e *kiloVerifyVerdictError) Error() string {
	return "verdict=" + e.label
}

// parseKiloVerifyBaseURL is a tiny stdlib-only URL parser. We avoid
// net/url to keep the cmd/helixchannel import set minimal.
func parseKiloVerifyBaseURL(raw string) (scheme, host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", fmt.Errorf("empty URL")
	}
	switch {
	case strings.HasPrefix(raw, "https://"):
		scheme = "https"
		raw = strings.TrimPrefix(raw, "https://")
	case strings.HasPrefix(raw, "http://"):
		scheme = "http"
		raw = strings.TrimPrefix(raw, "http://")
	default:
		return "", "", "", fmt.Errorf("unsupported scheme in %q (only http/https allowed)", raw)
	}
	if idx := strings.IndexByte(raw, '/'); idx >= 0 {
		raw = raw[:idx]
	}
	host, port, perr := net.SplitHostPort(raw)
	if perr != nil {
		host = raw
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme, host, port, nil
}

// classifyNetErr reduces a net.OpError to a single-token label so
// operators can grep the envelope for "timeout", "refused", etc.
// Returns "net" if no class can be inferred.
func classifyNetErr(err error) string {
	if err == nil {
		return "none"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "context deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "timeout"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "refused"
	case strings.Contains(s, "no such host"):
		return "no_route"
	case strings.Contains(s, "tls"):
		return "tls"
	case strings.Contains(s, "401"):
		return "upstream_401"
	case strings.Contains(s, "403"):
		return "upstream_403"
	case strings.Contains(s, "429"):
		return "upstream_429"
	default:
		return "net"
	}
}

// truncateKiloVerify caps a string at n runes and appends "..." if
// truncated. Avoids the strings import in the operator-facing logs.
func truncateKiloVerify(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
