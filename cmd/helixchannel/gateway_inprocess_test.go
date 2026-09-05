// Copyright (c) 2026 jason. All rights reserved.
//
// gateway_inprocess_test.go (v18760) runs the gateway/proxy subcommands
// in-process. The existing suite drives the compiled binary — real, but
// invisible to `go test -coverprofile`, which is how the package sat at
// 28.8% with six test files. These tests exercise the same contracts
// through direct calls: config loading, the print seams, the token
// resolution ladder, and a full serve→request→SIGTERM lifecycle against
// a live upstream.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written. Subcommands write JSON envelopes straight to
// os.Stdout, so in-process assertions need the swap.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	runErr := fn()
	os.Stdout = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out, runErr
}

// writeGatewayConfig writes a minimal valid gateway YAML and returns its
// path. upstream is the route's backend URL; listen may be empty to test
// the --listen override.
func writeGatewayConfig(t *testing.T, listen, upstream string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/gateway.yml"
	cfg := fmt.Sprintf(`listen: %q
routes:
  - name: minimax
    prefix: /minimax/
    upstream: %q
    auth: inject
    key_env: V18760_GW_TEST_KEY # gitleaks:allow — env NAME, not a secret
    enabled: true
  - name: dark
    prefix: /dark/
    upstream: %q
    auth: inject
    key_env: V18760_GW_TEST_KEY # gitleaks:allow — env NAME, not a secret
    enabled: false
`, listen, upstream, upstream)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestRunGateway_PrintRoutesEmitsEnabledOnly(t *testing.T) {
	t.Setenv("V18760_GW_TEST_KEY", "sk-test")
	cfgPath := writeGatewayConfig(t, "127.0.0.1:0", "http://127.0.0.1:9")

	out, err := captureStdout(t, func() error {
		return runGateway([]string{"--config", cfgPath, "--print-routes"})
	})
	if err != nil {
		t.Fatalf("runGateway --print-routes = %v, want nil", err)
	}
	var env struct {
		Listen  string   `json:"listen"`
		Routes  []string `json:"routes"`
		Connect bool     `json:"connect"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("print-routes output not JSON: %v (%q)", err, out)
	}
	if len(env.Routes) != 1 || env.Routes[0] != "minimax" {
		t.Fatalf("routes = %v, want [minimax] (disabled route must be absent)", env.Routes)
	}
	if env.Connect {
		t.Fatal("connect = true, want false (not configured)")
	}
}

func TestRunGateway_ListenOverrideAppearsInEnvelope(t *testing.T) {
	t.Setenv("V18760_GW_TEST_KEY", "sk-test")
	cfgPath := writeGatewayConfig(t, "127.0.0.1:1", "http://127.0.0.1:9")

	out, err := captureStdout(t, func() error {
		return runGateway([]string{"--config", cfgPath, "--listen", "127.0.0.1:2", "--print-routes"})
	})
	if err != nil {
		t.Fatalf("runGateway = %v, want nil", err)
	}
	if !strings.Contains(out, `"listen":"127.0.0.1:2"`) {
		t.Fatalf("envelope %q missing the --listen override", out)
	}
}

func TestRunGateway_BadConfigPathFails(t *testing.T) {
	err := runGateway([]string{"--config", t.TempDir() + "/missing.yml", "--print-routes"})
	if err == nil {
		t.Fatal("runGateway with missing config = nil, want error")
	}
}

func TestRunGateway_BadFlagFails(t *testing.T) {
	if err := runGateway([]string{"--no-such-flag"}); err == nil {
		t.Fatal("runGateway with unknown flag = nil, want parse error")
	}
}

func TestRunGateway_AuditLogOpenFailureSurfaced(t *testing.T) {
	t.Setenv("V18760_GW_TEST_KEY", "sk-test")
	dir := t.TempDir()
	cfgPath := dir + "/gateway.yml"
	// audit_log points at a directory → OpenFile must fail.
	cfg := fmt.Sprintf("listen: 127.0.0.1:0\naudit_log: %q\nroutes:\n  - name: mm\n    prefix: /mm/\n    upstream: http://127.0.0.1:9\n    auth: inject\n    key_env: V18760_GW_TEST_KEY # gitleaks:allow — env NAME, not a secret\n    enabled: true\n", dir)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	err := runGateway([]string{"--config", cfgPath, "--print-routes"})
	if err == nil || !strings.Contains(err.Error(), "open audit log") {
		t.Fatalf("err = %v, want audit-log open failure", err)
	}
}

// TestRunGateway_ServesAndStopsOnSignal is the full lifecycle: the
// gateway binds a real port, proxies a request to a live upstream with
// the injected credential, and shuts down cleanly on SIGTERM.
func TestRunGateway_ServesAndStopsOnSignal(t *testing.T) {
	t.Setenv("V18760_GW_TEST_KEY", "sk-live-key")
	var gotAuth string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	lf := listenFreeTCP(t)
	port := lf.Port()
	_ = lf.Close()
	listen := fmt.Sprintf("127.0.0.1:%d", port)
	cfgPath := writeGatewayConfig(t, listen, upstream.URL)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runGateway([]string{"--config", cfgPath})
	}()

	// Wait for readiness via the gateway's own health endpoint.
	healthy := false
	for i := 0; i < 100; i++ {
		resp, err := http.Get("http://" + listen + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !healthy {
		t.Fatal("gateway never became healthy on /healthz")
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+listen+"/minimax/v1/models", nil)
	req.Header.Set("Authorization", "Bearer placeholder")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request through gateway: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("gateway response = %d %q, want 200 ok", resp.StatusCode, body)
	}
	mu.Lock()
	auth := gotAuth
	mu.Unlock()
	if auth != "Bearer sk-live-key" {
		t.Fatalf("upstream saw Authorization %q, want the injected server-side key", auth)
	}

	// Graceful stop via the signal the unit file sends.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	// 30s, not 10s, and the number is not arbitrary: it has to exceed the
	// package's shutdown grace (channel.shutdownGrace, 15s) or this test times
	// out on its OWN bound before the shutdown it is watching has finished, and
	// reports "did not stop" for a stop that was still legitimately in progress.
	//
	// The grace in turn has to exceed net/http's hard-coded 5s threshold for
	// reclaiming a connection that was accepted but has not sent a request
	// header. Before v18815 the grace WAS that same 5s, so this test failed here
	// with "context deadline exceeded" whenever the readiness loop above left a
	// connection in that state -- measured 3/3 on pristine main under load.
	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("runGateway exit = %v, want clean shutdown", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("gateway did not stop within 30s of SIGTERM")
	}
}

func TestRunProxy_PrintEnvListsProxyVariables(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return runProxy([]string{"--listen", "127.0.0.1:47821", "--print-env"})
	})
	if err != nil {
		t.Fatalf("runProxy --print-env = %v, want nil", err)
	}
	for _, want := range []string{
		"HTTPS_PROXY=http://127.0.0.1:47821",
		"NO_PROXY=127.0.0.1,localhost,::1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("print-env output %q missing %q", out, want)
		}
	}
}

func TestRunProxy_RequiresGateway(t *testing.T) {
	t.Setenv("HELIXCHANNEL_GATEWAY", "")
	t.Setenv("HELIXCHANNEL_CONNECT_TOKEN", "tok")
	err := runProxy([]string{"--listen", "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "--gateway is required") {
		t.Fatalf("err = %v, want gateway-required", err)
	}
}

func TestRunProxy_RequiresToken(t *testing.T) {
	t.Setenv("HELIXCHANNEL_CONNECT_TOKEN", "")
	err := runProxy([]string{"--listen", "127.0.0.1:0", "--gateway", "edge.example:8443"})
	if err == nil || !strings.Contains(err.Error(), "no CONNECT token") {
		t.Fatalf("err = %v, want token-required", err)
	}
}

func TestRunProxy_BadFlagFails(t *testing.T) {
	if err := runProxy([]string{"--definitely-not-a-flag"}); err == nil {
		t.Fatal("runProxy with unknown flag = nil, want parse error")
	}
}

func TestRunProxy_ServesAndStopsOnSignal(t *testing.T) {
	t.Setenv("HELIXCHANNEL_CONNECT_TOKEN", "tok-v18760")
	lf := listenFreeTCP(t)
	port := lf.Port()
	_ = lf.Close()
	listen := fmt.Sprintf("127.0.0.1:%d", port)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runProxy([]string{"--listen", listen, "--gateway", "127.0.0.1:1", "--insecure"})
	}()

	// Readiness: the local proxy port accepts TCP.
	up := false
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", listen, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			up = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		t.Fatal("client proxy never started listening")
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("runProxy exit = %v, want clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("proxy did not stop within 10s of SIGTERM")
	}
}

func TestResolveConnectToken_Ladder(t *testing.T) {
	dir := t.TempDir()
	full := dir + "/tok"
	if err := os.WriteFile(full, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	empty := dir + "/empty"
	if err := os.WriteFile(empty, []byte(" \n\t"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv("V18760_TOKEN_ENV", "env-token")
	if got, err := resolveConnectToken("V18760_TOKEN_ENV", full); err != nil || got != "env-token" {
		t.Fatalf("env wins: got (%q,%v)", got, err)
	}
	t.Setenv("V18760_TOKEN_ENV", "")
	if got, err := resolveConnectToken("V18760_TOKEN_ENV", full); err != nil || got != "file-token" {
		t.Fatalf("file fallback: got (%q,%v)", got, err)
	}
	if _, err := resolveConnectToken("V18760_TOKEN_ENV", empty); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty file: err = %v, want empty-file error", err)
	}
	if _, err := resolveConnectToken("V18760_TOKEN_ENV", dir+"/missing"); err == nil || !strings.Contains(err.Error(), "read token file") {
		t.Fatalf("missing file: err = %v, want read error", err)
	}
	if _, err := resolveConnectToken("V18760_TOKEN_ENV", ""); err == nil || !strings.Contains(err.Error(), "no CONNECT token") {
		t.Fatalf("no sources: err = %v, want no-token error", err)
	}
}

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("V18760_EOD", "set")
	if got := envOrDefault("V18760_EOD", "fb"); got != "set" {
		t.Fatalf("got %q, want set", got)
	}
	t.Setenv("V18760_EOD", "")
	if got := envOrDefault("V18760_EOD", "fb"); got != "fb" {
		t.Fatalf("got %q, want fallback", got)
	}
}

func TestTrimSpaceLocal(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"  x  ":           "x",
		"\r\n tok \t\r\n": "tok",
		"already":         "already",
		" \t\r\n":         "",
	}
	for in, want := range cases {
		if got := trimSpace(in); got != want {
			t.Fatalf("trimSpace(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFilterTestFlags(t *testing.T) {
	in := []string{"--config", "x.yml", "-test.v", "--test.run=TestX", "--print-routes"}
	got := filterTestFlags(in)
	want := []string{"--config", "x.yml", "--print-routes"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
