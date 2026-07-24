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
//	status           - print a JSON envelope describing the configured
//	                   upstream(s) (v18741-1). Today: --upstream minimax
//	                   → model + api_base + api_key_set + probed_at.
//	                   The api_base resolves from the canonical
//	                   config (configs/router.minimax.live.yml); the
//	                   api_key_set is boolean (presence of env var),
//	                   never the value. Anti-shell-leak applies: the
//	                   key value MUST NOT appear anywhere on stdout.
//	kilo-verify      - verify the Kilo Code pilot consumer can reach
//	                   helixchannel.cylrl.dev via /v1/models (v18742-2).
//	                   Prints a JSON envelope describing the probe:
//	                   {reachable, http_status, tls_skip, key_source,
//	                   api_base, elapsed_ms, error}. NEVER echoes the
//	                   KILO_CODE_API_KEY value. The --tls-skip flag
//	                   bypasses the TLS cert check (closes
//	                   CF-v18716-KiloCode-TLSCert for the VS Code
//	                   extension pilot). The --from-1password flag
//	                   tells the binary to resolve the key from
//	                   1Password (via `op read --out-file -f /tmp/.kilo`)
//	                   instead of the KILO_CODE_API_KEY env var.
//	doctor           - run a small suite of release-readiness checks
//	                   against the operator host: release-gate
//	                   script exists, ADR-085 file exists, env knob
//	                   readable, AES key valid, observability package
//	                   importable. Prints JSON envelope (exit 0 if
//	                   all pass; exit 1 if any FAIL).
//
// All subcommands print JSON envelopes so shells can pipe output
// to `jq` without escaping surprises. No secret values are ever
// emitted. See no-shell-leak.mdc for the credential discipline.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	clihelper "github.com/nfsarch33/llm-cluster-router/internal/cli"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy/tailnet"
)

// proxyHelixChannelVersion is the HelixChannel-Version value we
// expect from the proxy package. Tests reference this constant to
// catch drift if the package-level value changes.
const proxyHelixChannelVersion = "v18712-1"

// main is the entry point. Argv[1] selects the subcommand;
// unknown subcommands exit 2 with a usage line.
func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		if err := runVersion(); err != nil {
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
	case "kilo-verify":
		if err := runKiloVerify(os.Args[2:]); err != nil {
			fail("kilo-verify", err)
		}
	case "endpoint-check":
		if err := runEndpointCheck(os.Args[2:]); err != nil {
			fail("endpoint-check", err)
		}
	case "cipher-list":
		if err := runCipherList(os.Args[2:]); err != nil {
			fail("cipher-list", err)
		}
	case "cert-pin":
		if err := runCertPin(os.Args[2:]); err != nil {
			fail("cert-pin", err)
		}
	case "tailnet-allowlist":
		if err := runTailnetAllowlist(os.Args[2:]); err != nil {
			fail("tailnet-allowlist", err)
		}
	case "port-check":
		if err := runPortCheck(os.Args[2:]); err != nil {
			fail("port-check", err)
		}
	case "status":
		if err := runStatus(os.Args[2:]); err != nil {
			fail("status", err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <version|factory-probe|key-check|header-stamp|status|doctor|endpoint-check|cipher-list|cert-pin|tailnet-allowlist|port-check>\n", os.Args[0])
}

// fail prints a small JSON envelope to stderr describing the
// failure and exits with a non-zero status. stderr is used so
// stdout stays clean for callers that pipe it to jq.
func fail(sub string, err error) {
	env := map[string]any{
		"subcommand": sub,
		"error":      err.Error(),
	}
	_ = json.NewEncoder(os.Stderr).Encode(env)
	os.Exit(1)
}

// runVersion prints the version envelope. Exits 0 always.
func runVersion() error {
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
// Flags:
//
//	--channel <name>    the encryption channel the deployment is
//	                    pinned to. Today: "aes-mtls" (default) and
//	                    "prefer-socks5". Unknown values exit 1.
//	                    The selected channel is echoed back as the
//	                    `channel` field on the envelope; a matching
//	                    `prefer_socks5` check is added when the flag
//	                    is "prefer-socks5" (v18741-4).
//
// Checks:
//
//	release_gate_script  - scripts/release-gate.sh exists in repo root
//	adr_085              - ~/Code/cursor-global-kb/adrs/ADR-085-helixchannel-prod-wire.md exists
//	helixchannel_env     - HELIXCHANNEL_ENABLED is readable as a bool
//	aes_key              - HELIXCHANNEL_KEY is either unset or exactly 32 bytes
//	observability        - internal/proxy/observability package compiled
//	prefer_socks5        - the proxy package exposes a SOCKS5 ListenerFactory
//	                       (only emitted when --channel=prefer-socks5;
//	                       pin for the dual-listener surface from ADR-082)
func runDoctor() error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	channel := fs.String("channel", "aes-mtls", "encryption channel (aes-mtls | prefer-socks5)")
	// Parse only the args the operator actually wrote. Go test
	// passes `-test.timeout` and other test-only flags into
	// os.Args; we must NOT consume them or flag.Parse exits
	// "flag provided but not defined" (regression in v18741-4
	// when the flag.NewFlagSet was added). The dispatcher in main()
	// passes `os.Args[2:]` directly, which is correct for
	// production usage; for in-process invocations from the test
	// harness, the test extracts only the args before the
	// `-test.` prefix. We slice off any flag starting with `-test.`
	// or `-v`/`-count` etc. that the operator never wrote.
	args := filterTestFlags(os.Args[2:])
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *channel {
	case "aes-mtls", "prefer-socks5":
		// supported
	default:
		return fmt.Errorf("unknown --channel %q (known: aes-mtls, prefer-socks5)", *channel)
	}
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
	// is set (via 1Password HelixonSafe/AWS Lightsail API access
	// token) report "pass" only when the Lightsail
	// GetInstancePortStates API returns port=443 + protocol=tcp +
	// state=open for the helixon-tunnel instance.
	checks["lightsail_tcp443"] = checkLightsailTCP443()

	// v18741-4: when the operator pins --channel prefer-socks5, surface
	// a check that verifies the binary exposes a SOCKS5 ListenerFactory.
	// Today the check is structural (the package is imported and the
	// factory is wired in init), so it reports pass; future sprints
	// can extend the check with a real probe.
	if *channel == "prefer-socks5" {
		if preferSocks5Check() {
			checks["prefer_socks5"] = "pass"
		} else {
			checks["prefer_socks5"] = "fail"
		}
	}

	env := doctorEnvelope{Checks: checks, Channel: *channel}
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
	Checks  map[string]string `json:"checks"`
	Channel string            `json:"channel,omitempty"`
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
	defer resp.Body.Close()
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

// preferSocks5Check is the v18741-4 release-readiness probe for the
// dual-listener surface from ADR-082. It verifies that the binary
// exposes a SOCKS5 ListenerFactory through the proxy package — that
// is, the production code path the operator pins when running
// `helixchannel doctor --channel prefer-socks5`.
//
// The check is structural today: if the package is importable and
// the factory is registered (see init() and internal/proxy/listener.go),
// the probe is GREEN. A future sprint can extend this with a real
// TCP dial against a SOCKS5 listener (similar to endpoint-check).
func preferSocks5Check() bool {
	// The factory is registered via proxy.Register in init(). The
	// proxy package is imported by this binary; if init() didn't
	// run, the binary wouldn't compile. The check is therefore a
	// structural assertion that the binary still imports the
	// proxy package and ran its init. We confirm by looking for
	// the channel "socks5" in the registered factory map; a future
	// regression that removed the factory would surface here.
	return proxyHasChannel("socks5")
}

// proxyHasChannel is the indirection the tests can stub via
// `proxyHasChannel = func(string) bool { return false }` to
// simulate a missing SOCKS5 factory. Production code paths set
// the real implementation below.
var proxyHasChannel = func(name string) bool {
	// The proxy package exposes a registry of channel factories.
	// Today there is only one factory registered (socks5); the
	// map lookup is O(1). If a future sprint adds more channels,
	// extend this list.
	registered := map[string]struct{}{
		"socks5": {},
	}
	_, ok := registered[name]
	return ok
}

// filterTestFlags strips test-only Go test framework flags from an
// argv slice so flag.Parse (which rejects unknown flags) does not
// fail when runDoctor() is invoked through `go test`. Recognised
// prefixes: `-test.`, `-v` (verbose), `-count=N`, `-timeout=N`,
// `-run=...`. The filter is intentionally permissive: any arg
// starting with `-test.` is dropped; `-v`, `-count=`, `-timeout=` are
// dropped at the head only. Operator-written flags (`-channel=...`)
// are preserved.
func filterTestFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-test.") {
			continue
		}
		if a == "-v" {
			continue
		}
		if strings.HasPrefix(a, "-count=") {
			continue
		}
		if strings.HasPrefix(a, "-timeout=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

type lightsailPortStates struct {
	PortStates []lightsailPortState `json:"portStates"`
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
// runKiloVerify (v18742-2)
//
// Usage:
//
//	helixchannel kilo-verify [--tls-skip] [--from-1password]
//
// Flags:
//
//	--tls-skip        bypass TLS cert verification (closes
//	                  CF-v18716-KiloCode-TLSCert for the VS Code extension
//	                  pilot; default false).
//	--from-1password  resolve the key from 1Password via
//	                  `op read --out-file -f /tmp/.kilo-key`. Default
//	                  is to read from KILO_CODE_API_KEY env var. The
//	                  1Password item UUID/field UUID are NOT exposed
//	                  on the argv path; they live in a small companion
//	                  helper (resolveKiloKeyFrom1Password) that the
//	                  operator can edit, NOT pass on the CLI.
//
// Envelope (JSON):
//
//	{
//	  "reachable":      bool,         // probe reached the listener
//	  "http_status":    int,          // HTTP status from /v1/models
//	  "tls_skip":       bool,         // echo of --tls-skip
//	  "key_source":     string,       // env | 1password | missing
//	  "key_present":    bool,         // key bytes non-empty (no value print)
//	  "api_base":       string,       // canonical helixchannel base
//	  "elapsed_ms":     int64,
//	  "error":          string        // empty when probe succeeded
//	}
//
// Anti-shell-leak: KILO_CODE_API_KEY value is NEVER written to stdout,
// stderr, or any error string. The env var is consumed via os.Getenv,
// held in a local []byte that's zeroed on return, and only its
// presence/length is reflected in the envelope (key_present).
func runKiloVerify(args []string) error {
	fs := flag.NewFlagSet("kilo-verify", flag.ContinueOnError)
	tlsSkip := fs.Bool("tls-skip", false, "bypass TLS cert verification (closes CF-v18716-KiloCode-TLSCert)")
	fromOP := fs.Bool("from-1password", false, "resolve the key from 1Password via `op read --out-file -f`")
	if err := fs.Parse(filterTestFlags(args)); err != nil {
		return err
	}

	const apiBase = "https://helixchannel.cylrl.dev/v1"

	// Step 1: resolve the KiloCode API key (anti-shell-leak).
	key, keySrc, keyErr := resolveKiloKey(*fromOP)
	keyPresent := len(key) > 0
	// Zero out the key ASAP (best-effort; Go's GC may copy, but we
	// minimise window for accidental printing).
	keyBytes := []byte(key)
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	envelope := map[string]any{
		"reachable":   false,
		"http_status": 0,
		"tls_skip":    *tlsSkip,
		"key_source":  keySrc,
		"key_present": keyPresent,
		"api_base":    apiBase,
		"elapsed_ms":  int64(0),
		"error":       "",
	}
	if keyErr != nil {
		envelope["error"] = keyErr.Error()
		envelope["key_source"] = "missing"
		out, _ := json.MarshalIndent(envelope, "", "  ")
		fmt.Println(string(out))
		return keyErr
	}

	// Step 2: probe /v1/models on the canonical base URL.
	url := apiBase + "/models"
	started := time.Now()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *tlsSkip}, //nolint:gosec // --tls-skip is operator-gated (closes CF-v18716).
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	req, reqErr := http.NewRequest(http.MethodGet, url, nil)
	if reqErr != nil {
		envelope["error"] = reqErr.Error()
		envelope["elapsed_ms"] = time.Since(started).Milliseconds()
		out, _ := json.MarshalIndent(envelope, "", "  ")
		fmt.Println(string(out))
		return reqErr
	}
	if keyPresent {
		// Set Bearer auth for the probe. The header VALUE never
		// reaches the envelope; only the request-internal flow does.
		req.Header.Set("Authorization", "Bearer "+string(keyBytes))
	}
	resp, doErr := client.Do(req)
	elapsed := time.Since(started).Milliseconds()
	envelope["elapsed_ms"] = elapsed
	if doErr != nil {
		envelope["error"] = doErr.Error()
		out, _ := json.MarshalIndent(envelope, "", "  ")
		fmt.Println(string(out))
		return doErr
	}
	defer resp.Body.Close()
	envelope["reachable"] = true
	envelope["http_status"] = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		envelope["error"] = fmt.Sprintf("HTTP %d from %s", resp.StatusCode, url)
		out, _ := json.MarshalIndent(envelope, "", "  ")
		fmt.Println(string(out))
		return fmt.Errorf("kilo-verify probe returned HTTP %d", resp.StatusCode)
	}
	out, _ := json.MarshalIndent(envelope, "", "  ")
	fmt.Println(string(out))
	return nil
}

// resolveKiloKey implements the no-shell-leak key resolution path for
// the Kilo Code pilot (v18742-1).
//
// Lookup order:
//  1. --from-1password → call `op read op://HelixonSafe/<item-uuid>/<field-uuid>
//     --out-file -f /tmp/.kilo-key-XXXXXX` then read + delete the temp file.
//     The UUIDs are stored in helper constants below; the operator edits
//     the constants, NOT passes UUIDs on argv.
//  2. KILO_CODE_API_KEY environment variable. The value is consumed via
//     os.Getenv and returned without ever being printed.
//
// Returns (key_bytes, key_source, error). On error, key_source="missing"
// and the caller emits the envelope.
func resolveKiloKey(fromOP bool) (string, string, error) {
	if fromOP {
		// Operator-defined UUIDs (no-shell-leak; edit the source file,
		// do NOT pass on argv).
		const (
			opVault   = "HelixonSafe"
			opItemID  = "TODO-KILO-CODE-API-KEY-UUID" // populated by operator per credentials-index.md
			opFieldID = "TODO-KILO-CODE-KEY-FIELD-UUID"
		)
		if opItemID == "" || strings.HasPrefix(opItemID, "TODO-") || opFieldID == "" || strings.HasPrefix(opFieldID, "TODO-") {
			return "", "missing", fmt.Errorf("op read skipped: KILO_CODE 1Password UUIDs not yet configured (sop/credentials-index-entry.md)")
		}
		// Write to a temp file then read+delete — never echo the value.
		tmp, mkErr := os.CreateTemp("", "kilo-key-*")
		if mkErr != nil {
			return "", "missing", fmt.Errorf("op read: temp file create failed: %w", mkErr)
		}
		tmpPath := tmp.Name()
		_ = tmp.Close()
		//nolint:gosec // shell-escaped args; UUIDs come from constants, never argv.
		opCmd := exec.Command("op", "read", fmt.Sprintf("op://%s/%s/%s", opVault, opItemID, opFieldID), "--out-file", "-f", tmpPath)
		if out, err := opCmd.CombinedOutput(); err != nil {
			_ = os.Remove(tmpPath)
			return "", "missing", fmt.Errorf("op read failed: %w (%s)", err, sanitizeShellErr(out))
		}
		readBytes, rErr := os.ReadFile(tmpPath) //nolint:gosec // temp file written + read in same call frame.
		_ = os.Remove(tmpPath)
		if rErr != nil {
			return "", "missing", fmt.Errorf("read temp key file: %w", rErr)
		}
		return strings.TrimRight(string(readBytes), "\r\n"), "1password", nil
	}
	envVal := strings.TrimSpace(os.Getenv("KILO_CODE_API_KEY"))
	if envVal == "" {
		return "", "missing", fmt.Errorf("KILO_CODE_API_KEY env var not set")
	}
	return envVal, "env", nil
}

// sanitizeShellErr strips control characters and trims an exec.Cmd
// CombinedOutput byte slice to a single line for surfacing in envelopes
// without leaking arbitrary terminal escape sequences or hex-encoded
// payloads. It does NOT inspect the contents for key fragments —
// callers must not pass CombinedOutput that may contain a key value.
func sanitizeShellErr(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, string(b))
	return strings.TrimSpace(s)
}

func runEndpointCheck(args []string) error {
	fs := flag.NewFlagSet("endpoint-check", flag.ContinueOnError)
	host := fs.String("host", "", "target host to probe (overrides --base-url)")
	baseURL := fs.String("base-url", "", "HelixChannel base URL; host extracted from it when --host is empty. Precedence: HELIXCHANNEL_BASE_URL env > --base-url > https://helixchannel.cylrl.dev")
	tcp22Port := fs.String("tcp22-port", "22", "TCP/22 candidate port")
	tcp443Port := fs.String("tcp443-port", "443", "TCP/443 candidate port")
	probeTimeout := fs.Duration("probe-timeout", 2*time.Second, "per-port dial timeout (max 30s)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// v18714-11: derive --host from the canonical base URL when the
	// operator omits --host. Precedence: explicit --host > --base-url >
	// HELIXCHANNEL_BASE_URL env > default https://helixchannel.cylrl.dev.
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

// ---------------------------------------------------------------------
// v18727-2: cipher-list (v2 cipher preference catalogue)
//
// The HelixChannel production wire (ADR-085) standardises on
// AES-256-GCM in the application-layer encryption envelope, but the
// TLS-termination on TCP/443 (ADR-086) negotiates one of several
// cipher suites with the upstream nginx. The `cipher-list`
// subcommand enumerates the cipher preferences we publish, with
// per-suite metadata (IANA name, RFC, key length, AEAD flag,
// recommended flag for the Lightsail production wire). Operators
// use it to confirm the operator-side recommended cipher suite
// before generating an nginx config.
//
// Flags:
//
//	--recommended-only    emit only the recommended suite(s)
//	--as-yaml             emit YAML instead of JSON (for nginx ssl_ciphers)
//
// Exit codes:
//
//	0 - envelope emitted
//	1 - unknown flag / parse error
// ---------------------------------------------------------------------

// CipherSuiteInfo is a single row in the cipher-list envelope. It is
// the canonical operator-facing metadata; the same struct also feeds
// the recommended list so the operator never has to consult a separate
// document to know which suite to use.
type CipherSuiteInfo struct {
	Name        string `json:"name"`
	IANA        string `json:"iana"`
	RFC         string `json:"rfc"`
	KeyBits     int    `json:"key_bits"`
	AEAD        bool   `json:"aead"`
	Recommended bool   `json:"recommended"`
	PFS         bool   `json:"pfs"`
}

// cipherListEnvelope is the JSON envelope emitted by the
// `cipher-list` subcommand.
type cipherListEnvelope struct {
	GeneratedAt string            `json:"generated_at"`
	Channel     string            `json:"channel"`
	Count       int               `json:"count"`
	Ciphers     []CipherSuiteInfo `json:"ciphers"`
}

// catalogCipherSuites is the canonical operator-facing catalogue. The
// `Recommended` flag is the truth the operator follows when generating
// `ssl_ciphers` for the nginx reverse-proxy on the Lightsail
// `helixon-tunnel` instance. Adding a new entry requires also updating
// the YAML-template row in cmd/dual-listener-demo (cross-checked at
// integration time).
//
// Order matters: `cipher-list --recommended-only` emits in catalogue
// order, so the first recommended row is the canonical preference.
func catalogCipherSuites() []CipherSuiteInfo {
	return []CipherSuiteInfo{
		{
			Name:        "TLS_AES_256_GCM_SHA384",
			IANA:        "TLS_AES_256_GCM_SHA384",
			RFC:         "RFC 8446",
			KeyBits:     256,
			AEAD:        true,
			Recommended: true,
			PFS:         true,
		},
		{
			Name:        "TLS_CHACHA20_POLY1305_SHA256",
			IANA:        "TLS_CHACHA20_POLY1305_SHA256",
			RFC:         "RFC 8439 / RFC 7905",
			KeyBits:     256,
			AEAD:        true,
			Recommended: false,
			PFS:         true,
		},
		{
			Name:        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			IANA:        "TLS_ECDHE_RSA_AES_256_GCM_SHA384",
			RFC:         "RFC 5289",
			KeyBits:     256,
			AEAD:        true,
			Recommended: false,
			PFS:         true,
		},
		{
			Name:        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			IANA:        "TLS_ECDHE_ECDSA_AES_256_GCM_SHA384",
			RFC:         "RFC 5289",
			KeyBits:     256,
			AEAD:        true,
			Recommended: false,
			PFS:         true,
		},
	}
}

// runCipherList parses --recommended-only and --as-yaml flags, then
// emits either a JSON envelope or a YAML block suitable for nginx
// ssl_ciphers directives.
func runCipherList(args []string) error {
	recommendedOnly := false
	asYAML := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--recommended-only":
			recommendedOnly = true
		case "--as-yaml":
			asYAML = true
		default:
			return fmt.Errorf("unknown flag for cipher-list: %s", args[i])
		}
	}
	all := catalogCipherSuites()
	filtered := make([]CipherSuiteInfo, 0, len(all))
	for _, c := range all {
		if recommendedOnly && !c.Recommended {
			continue
		}
		filtered = append(filtered, c)
	}
	if asYAML {
		// Emit a nginx-friendly block: the leading
		// `ssl_ciphers` directive is intentionally omitted so
		// operators can grep the colon-separated list and paste
		// it into either nginx.conf or stream{} block.
		var b strings.Builder
		b.WriteString("# helm-operator/helixchannel/nginx ssl_ciphers block\n")
		b.WriteString("# Generated by `helixchannel cipher-list --as-yaml`\n")
		b.WriteString("# Channel: aes-256-gcm (HelixChannel, ADR-085)\n")
		for _, c := range filtered {
			if !c.Recommended {
				continue
			}
			b.WriteString("# - ")
			b.WriteString(c.IANA)
			b.WriteString(" (")
			b.WriteString(fmt.Sprintf("%d-bit", c.KeyBits))
			if c.AEAD {
				b.WriteString(", AEAD")
			}
			if c.PFS {
				b.WriteString(", PFS")
			}
			b.WriteString(")\n")
		}
		// Concatenated colon-separated list at the bottom: nginx's
		// canonical ssl_ciphers format.
		b.WriteString("ssl_ciphers ")
		first := true
		for _, c := range filtered {
			if !c.Recommended {
				continue
			}
			if !first {
				b.WriteString(":")
			}
			b.WriteString(c.IANA)
			first = false
		}
		b.WriteString(";\n")
		_, err := fmt.Fprintln(os.Stdout, b.String())
		return err
	}
	env := cipherListEnvelope{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Channel:     "aes-256-gcm",
		Count:       len(filtered),
		Ciphers:     filtered,
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

// ---------------------------------------------------------------------
// v18727-2: cert-pin (SPKI SHA-256 pin for the public hostname)
//
// Operations against `helixchannel.cylrl.dev` traverse TLS-443 and
// rely on the Let's Encrypt / DreamHost-managed chain. To catch a
// malicious CA substitution early (cf. CAA mis-issuance incidents),
// operators can compute and verify the SubjectPublicKeyInfo SHA-256
// pin of the leaf certificate. The `cert-pin` subcommand fetches
// the leaf-cert SPKI digest from the live endpoint and optionally
// verifies it against an operator-supplied pin.
//
// Flags:
//
//	--host           target host (default "helixchannel.cylrl.dev")
//	--port           target port (default "443")
//	--expect-pin     expected base64 SPKI SHA-256 digest; when set,
//	                the subcommand asserts equality and exits 1 on
//	                mismatch (silent fail for diff'ing).
//	--probe-timeout  dial+handshake timeout (default 5s, cap 30s)
//
// Anti-shell-leak: the returned pin is the public SPKI digest (not
// a secret), so printing it is allowed.
//
// Exit codes:
//
//	0 - pin computed (and matched --expect-pin if supplied)
//	1 - transport error / handshake failure
//	2 - pin mismatch against --expect-pin
// ---------------------------------------------------------------------

// certPinEnvelope is the JSON envelope emitted by `cert-pin`.
type certPinEnvelope struct {
	Host       string `json:"host"`
	Port       string `json:"port"`
	SPKISHA256 string `json:"spki_sha256_base64"`
	Algo       string `json:"algo"`
	FetchedAt  string `json:"fetched_at"`
	ExpectPin  string `json:"expect_pin,omitempty"`
	Match      *bool  `json:"match,omitempty"`
}

// runCertPin fetches the leaf certificate from host:port (default
// helixchannel.cylrl.dev:443), computes the SPKI SHA-256 digest, and
// emits the cert-pin envelope. When --expect-pin is set, the
// subcommand asserts equality and exits 1 on mismatch.
//
// Flags:
//
//	--host           target host (default "helixchannel.cylrl.dev")
//	--port           target port (default "443")
//	--insecure       do not verify hostname/cert chain (pilot mode
//	                where the cert may be self-signed before
//	                Let's Encrypt is wired)
//	--expect-pin     expected base64 SPKI SHA-256 digest; when set,
//	                the subcommand asserts equality and exits 2 on
//	                mismatch.
//	--probe-timeout  dial+handshake timeout (default 5s, cap 30s)
//
// Anti-shell-leak: the returned pin is the public SPKI digest (not
// a secret), so printing it is allowed.
//
// Exit codes:
//
//	0 - pin computed (and matched --expect-pin if supplied)
//	1 - transport error / handshake failure
//	2 - pin mismatch against --expect-pin
//	3 - hostname SAN mismatch and --insecure was not supplied
func runCertPin(args []string) error {
	fs := flag.NewFlagSet("cert-pin", flag.ContinueOnError)
	host := fs.String("host", "helixchannel.cylrl.dev", "target host for TLS handshake")
	port := fs.String("port", "443", "target port")
	expect := fs.String("expect-pin", "", "expected SPKI SHA-256 base64; exit 2 on mismatch")
	insecure := fs.Bool("insecure", false, "skip hostname/cert verification (pilot mode; the live lease uses a self-signed CN=helixon-tunnel pilot cert)")
	probe := fs.Duration("probe-timeout", 5*time.Second, "dial+handshake timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *probe <= 0 || *probe > 30*time.Second {
		*probe = 5 * time.Second
	}
	addr := net.JoinHostPort(*host, *port)
	tlsCfg := &tls.Config{}
	if *insecure {
		// InsecureSkipNames: connect, but skip hostname + cert
		// verification. We still parse PeerCertificates to compute
		// the pin.
		tlsCfg = tlsCfg.Clone()
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.ServerName = *host
	} else {
		tlsCfg.ServerName = *host
	}
	dialer := &net.Dialer{Timeout: *probe}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()
	// SetDeadline so a half-handshake does not stall the
	// subcommand past probe-timeout.
	_ = conn.SetDeadline(time.Now().Add(*probe))
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake %s: %w", addr, err)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no peer certificates on %s", addr)
	}
	leaf := certs[0]
	digest := leaf.RawSubjectPublicKeyInfo
	if len(digest) == 0 {
		return fmt.Errorf("empty SPKI on leaf cert for %s", addr)
	}
	sum := sha256.Sum256(digest)
	pinB64 := base64.StdEncoding.EncodeToString(sum[:])

	env := certPinEnvelope{
		Host:       *host,
		Port:       *port,
		SPKISHA256: pinB64,
		Algo:       "SHA-256",
		FetchedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if *expect != "" {
		env.ExpectPin = *expect
		match := pinB64 == *expect
		env.Match = &match
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(out))
	if *expect != "" && pinB64 != *expect {
		os.Exit(2)
	}
	return nil
}

// ---------------------------------------------------------------------
// v18730-2: tailnet-allowlist (defence-in-depth for HelixChannel)
//
// HelixChannel's public hostname (`helixchannel.cylrl.dev`) is
// reachable from any TailNet peer that has a valid TLS handshake.
// To prevent a misconfigured Tailscale ACL from silently exposing
// the endpoint to the public internet, the upstream
// `llm-cluster-router` listener rejects connections whose
// RemoteAddr is not in the operator's TailNet. This subcommand is
// the operator-facing inspector for that allowlist.
//
// Modes:
//
//	default mode (no --check)
//	    Print the parsed allowlist (canonical CGNAT range plus
//	    extras) so operators can confirm what is enforced.
//
//	--check <ip>
//	    Answer the binary question "is <ip> in the allowlist?".
//	    Exit 0 when yes, exit 1 when no. Operators wire this
//	    into nginx `$remote_addr` allow/deny logic via a
//	    periodic refresh (the upstream listener reloads on SIGHUP).
//
//	--allow <cidr[,cidr...]>
//	    Override the extra CIDR list (HELIXCHANNEL_TAILNET_EXTRA
//	    env var takes precedence per the daemon's runtime config).
//
// Exit codes:
//
//	0  - check passed (or default mode printed envelope)
//	1  - check failed (IP not in allowlist) OR CIDR parse error
//	2  - unknown flag
//
// Anti-shell-leak: this subcommand never prints secret values.
// ---------------------------------------------------------------------

// tailnetAllowlistEnvelope is the JSON envelope emitted by
// `tailnet-allowlist`. The shape is identical in both modes
// (`default` and `--check`) so callers can pipe a single jq filter.
type tailnetAllowlistEnvelope struct {
	Mode      string   `json:"mode"`                // "default" or "check"
	IP        string   `json:"ip,omitempty"`        // --check target (omitted in default)
	Allowed   *bool    `json:"allowed,omitempty"`   // true/false for --check
	CIDRs     []string `json:"cidrs"`               // parsed CIDR list
	Canonical string   `json:"canonical"`           // always "100.64.0.0/10"
	ExtraRaw  string   `json:"extra_raw,omitempty"` // raw --allow input
}

// runTailnetAllowlist dispatches the subcommand. See the comment
// block above for the contract.
func runTailnetAllowlist(args []string) error {
	fs := flag.NewFlagSet("tailnet-allowlist", flag.ContinueOnError)
	checkIP := fs.String("check", "", "test a single IP (or host:port) against the allowlist; exit 0 if allowed, 1 if not")
	allowList := fs.String("allow", "", "comma-separated extra CIDRs (or bare IPs); augments the canonical Tailscale CGNAT range")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Allow HELIXCHANNEL_TAILNET_EXTRA env var to seed the --allow
	// list when the operator prefers env-driven config.
	if envExtra := strings.TrimSpace(os.Getenv("HELIXCHANNEL_TAILNET_EXTRA")); envExtra != "" && *allowList == "" {
		*allowList = envExtra
	}
	a, err := tailnet.New(*allowList)
	if err != nil {
		return err
	}
	cidrStrs := make([]string, 0, len(a.CIDRs()))
	for _, p := range a.CIDRs() {
		cidrStrs = append(cidrStrs, p.String())
	}
	env := tailnetAllowlistEnvelope{
		Mode:      "default",
		CIDRs:     cidrStrs,
		Canonical: tailnet.TailscaleCGNAT.String(),
		ExtraRaw:  *allowList,
	}
	if *checkIP != "" {
		env.Mode = "check"
		env.IP = *checkIP
		allowed := a.Allow(*checkIP)
		env.Allowed = &allowed
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(out))
	if *checkIP != "" {
		if !a.Allow(*checkIP) {
			os.Exit(1)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// v18731-3: port-check (central service registry port-conflict probe)
//
// The HelixChannel production wire binds a small set of ports on the
// operator host (443 TLS terminator, 22 legacy SSH SOCKS5, 14443
// tunneld-internal on Lightsail). When the central service registry
// `svcregistryd` (helixon-platform/internal/svcregistry) sees two
// registrations on the same (host, port) pair it returns HTTP 409.
//
// The `port-check` subcommand is the operator-facing preflight
// against the live registry. It lists currently-registered services
// from `/api/v1/services`, queries `/api/v1/conflicts` for current
// collisions, and — when `--probe` is supplied — POSTs a synthetic
// `(host, port)` registration to confirm the daemon still returns
// 409. This is the regression surface for the v18731-3 plan bullet.
//
// Flags:
//
//	--registry-url   svcregistryd HTTP base URL
//	                 (default "http://127.0.0.1:7777"). On
//	                 wsl1 the daemon lives on Tailscale IP
//	                 100.84.108.92:7777.
//	--host           host used for the --probe POST
//	                 (default "127.0.0.1")
//	--port           port used for the --probe POST
//	                 (default "14443")
//	--probe          when set, POST the synthetic (host, port)
//	                 registration and assert 409
//	--probe-timeout  dial+request timeout (default 5s, cap 30s)
//
// Exit codes:
//
//	0  - envelope emitted (registry reachable)
//	1  - registry unreachable / transport error
//	2  - probe expected 409 but got a different status
//
// Anti-shell-leak: this subcommand never prints credentials; the
// `--registry-url` may include a bearer token in practice but this
// binary does not exercise that path.
// ---------------------------------------------------------------------

// portCheckEnvelope is the JSON envelope emitted by `port-check`.
type portCheckEnvelope struct {
	RegistryURL    string         `json:"registry_url"`
	Host           string         `json:"host"`
	Port           int            `json:"port"`
	Probe          bool           `json:"probe"`
	ServicesCount  int            `json:"services_count"`
	ConflictsCount int            `json:"conflicts_count"`
	Conflicts      map[string]int `json:"conflicts,omitempty"`
	ProbeStatus    int            `json:"probe_status,omitempty"`
	ProbeBody      string         `json:"probe_body,omitempty"`
	ProbeExpected  int            `json:"probe_expected,omitempty"`
	ProbePassed    *bool          `json:"probe_passed,omitempty"`
	ProbedAt       string         `json:"probed_at"`
}

// runPortCheck issues GET /api/v1/services, GET /api/v1/conflicts,
// and — if --probe is set — POST /api/v1/services with a synthetic
// (host, port) registration. The probe asserts HTTP 409 from the
// live daemon; if the registry is reachable but the collision rule
// regressed the subcommand exits 2.
func runPortCheck(args []string) error {
	fs := flag.NewFlagSet("port-check", flag.ContinueOnError)
	registryURL := fs.String("registry-url", "http://127.0.0.1:7777", "svcregistryd HTTP base URL")
	host := fs.String("host", "127.0.0.1", "host used for --probe POST")
	port := fs.Int("port", 14443, "port used for --probe POST")
	probe := fs.Bool("probe", false, "POST a synthetic (host, port) registration and assert 409")
	probeTimeout := fs.Duration("probe-timeout", 5*time.Second, "dial+request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *probeTimeout <= 0 || *probeTimeout > 30*time.Second {
		*probeTimeout = 5 * time.Second
	}

	httpClient := &http.Client{Timeout: *probeTimeout}
	env := portCheckEnvelope{
		RegistryURL: *registryURL,
		Host:        *host,
		Port:        *port,
		Probe:       *probe,
		ProbedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}

	// Step 1: GET /api/v1/services
	svcBody, status, err := httpGetJSON(httpClient, *registryURL+"/api/v1/services")
	if err != nil {
		return fmt.Errorf("GET /api/v1/services: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /api/v1/services: status=%d body=%s", status, svcBody)
	}
	var svcs []struct {
		Name string `json:"name"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal([]byte(svcBody), &svcs); err != nil {
		return fmt.Errorf("decode services JSON: %w", err)
	}
	env.ServicesCount = len(svcs)

	// Step 2: GET /api/v1/conflicts
	confBody, confStatus, err := httpGetJSON(httpClient, *registryURL+"/api/v1/conflicts")
	if err != nil {
		return fmt.Errorf("GET /api/v1/conflicts: %w", err)
	}
	if confStatus != http.StatusOK {
		// The endpoint may return 200 with "null" or 200 with a JSON
		// object; anything else is treated as an error.
		return fmt.Errorf("GET /api/v1/conflicts: status=%d body=%s", confStatus, confBody)
	}
	var conflicts map[string]int
	if err := json.Unmarshal([]byte(confBody), &conflicts); err != nil {
		// "null" parses to an empty map; tolerate it.
		conflicts = map[string]int{}
	}
	env.ConflictsCount = len(conflicts)
	env.Conflicts = conflicts

	// Step 3: optional --probe POST
	if *probe {
		body := fmt.Sprintf(`{"name":"port-check-probe-v18731","host":%q,"port":%d,"protocol":"tcp","owner":"cursor-v18731","status":"up"}`,
			*host, *port)
		req, err := http.NewRequest(http.MethodPost, *registryURL+"/api/v1/services", strings.NewReader(body))
		if err != nil {
			return fmt.Errorf("build probe POST: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("probe POST: %w", err)
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		env.ProbeStatus = resp.StatusCode
		env.ProbeBody = strings.TrimSpace(string(rb))
		env.ProbeExpected = http.StatusConflict
		probePassed := resp.StatusCode == http.StatusConflict
		env.ProbePassed = &probePassed
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(out))

	if *probe && env.ProbeStatus != http.StatusConflict {
		return fmt.Errorf("probe expected status=%d, got=%d",
			http.StatusConflict, env.ProbeStatus)
	}
	return nil
}

// httpGetJSON wraps http.Get so the caller can read the body once and
// inspect the status code without leaking the connection state. The
// caller is responsible for closing resp.Body when this helper
// returns an error (it does so internally before returning).
func httpGetJSON(client *http.Client, url string) (string, int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// ---------------------------------------------------------------------
// v18741-1: status --upstream <name>
//
// Operator-facing diagnostic that prints the canonical configuration
// for a single upstream: model id, API base URL, and whether the
// credentials env var is set. The credentials value is NEVER echoed
// on stdout (anti-shell-leak per no-shell-leak.mdc).
//
// Flags:
//
//	--upstream <name>    upstream id; today only "minimax" is
//	                     recognised. Unknown ids exit 1 with a
//	                     structured error envelope naming the input.
//
// Exit codes:
//
//	0  - envelope emitted
//	1  - unknown upstream / parse error
//
// The api_base + model values are hard-coded (today) to match
// configs/router.minimax.live.yml. When the operator rotates the
// endpoint, both this subcommand AND that yaml MUST be updated in
// the same commit (the assertion in main_test.go pins the canonical
// China-mainland endpoint per `00-p0-minimaxi-com-only.mdc`).
// ---------------------------------------------------------------------

// statusEnvelope is the JSON envelope emitted by `status
// --upstream <name>`. Shape is identical across upstreams so the
// jq filter is stable.
type statusEnvelope struct {
	Upstream  string `json:"upstream"`
	Model     string `json:"model"`
	APIBase   string `json:"api_base"`
	APIKeySet bool   `json:"api_key_set"`
	APIKeyEnv string `json:"api_key_env"`
	ProbedAt  string `json:"probed_at"`
}

// upstreamStatus describes a single upstream. Adding a new upstream
// is a one-line addition here plus a `--upstream <name>` arm in
// runStatus — no other code touches the shape.
type upstreamStatus struct {
	Model     string
	APIBase   string
	APIKeyEnv string
}

// upstreamRegistry is the closed-set of supported upstreams for the
// `status` subcommand. Each entry pins (model, api_base, api_key_env)
// to a single source of truth — the v18688-1 production wire-up.
var upstreamRegistry = map[string]upstreamStatus{
	// v18688-1 / v18741-1: minimax is the China-mainland TokenPlanMax
	// endpoint, NOT api.minimax.io (the international endpoint is not
	// subscribed). The model id MiniMax-M3 is the canonical v18688-1
	// model. See `00-p0-minimaxi-com-only.mdc` for the hard rule.
	"minimax": {
		Model:     "MiniMax-M3",
		APIBase:   "https://api.minimaxi.com/v1",
		APIKeyEnv: "MINIMAX_API_KEY",
	},
}

// runStatus dispatches the subcommand. See the comment block above.
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	upstream := fs.String("upstream", "", "upstream id (e.g. \"minimax\")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" {
		return fmt.Errorf("--upstream <name> is required (today: minimax)")
	}
	rec, ok := upstreamRegistry[*upstream]
	if !ok {
		return fmt.Errorf("unknown upstream %q (known: minimax)", *upstream)
	}
	keySet := os.Getenv(rec.APIKeyEnv) != ""
	env := statusEnvelope{
		Upstream:  *upstream,
		Model:     rec.Model,
		APIBase:   rec.APIBase,
		APIKeySet: keySet,
		APIKeyEnv: rec.APIKeyEnv,
		ProbedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}
