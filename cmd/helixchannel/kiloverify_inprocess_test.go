// Copyright (c) 2026 jason. All rights reserved.
//
// kiloverify_inprocess_test.go (v18760) exercises the kilo-verify and
// endpoint-check subcommands in-process against live httptest upstreams:
// the full verdict matrix (pass / fail / skip), config-file precedence,
// TLS-insecure handling, and the endpoint recommendation ladder.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// kiloUpstream builds an OpenAI-compatible chat completions stub.
func kiloUpstream(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const kiloOKBody = `{"id":"resp-1","model":"MiniMax-M3","choices":[{"message":{"content":"pong"}}]}`

func decodeKiloEnvelope(t *testing.T, out string) kiloVerifyEnvelope {
	t.Helper()
	var env kiloVerifyEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("kilo-verify output not JSON: %v (%q)", err, out)
	}
	return env
}

func TestRunKiloVerify_PassAgainstLiveUpstream(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk-kilo")
	srv := kiloUpstream(t, http.StatusOK, kiloOKBody)

	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/minimax/v1"})
	})
	if err != nil {
		t.Fatalf("runKiloVerify = %v, want nil (pass)", err)
	}
	env := decodeKiloEnvelope(t, out)
	if env.Verdict != "pass" || env.ResponseID != "resp-1" || env.ContentPreview != "pong" {
		t.Fatalf("envelope = %+v, want pass/resp-1/pong", env)
	}
	if strings.Contains(out, "sk-kilo") {
		t.Fatal("API key leaked into envelope")
	}
}

func TestRunKiloVerify_MissingKeySkips(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", "http://127.0.0.1:1/v1"})
	})
	if !errors.Is(err, error(kiloVerifySkipErr)) {
		t.Fatalf("err = %v, want skip sentinel", err)
	}
	env := decodeKiloEnvelope(t, out)
	if env.Verdict != "skip" || env.ErrorClass != "missing_key" {
		t.Fatalf("envelope = %+v, want skip/missing_key", env)
	}
}

func TestRunKiloVerify_OpenAIKeyFallbackAccepted(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "sk-openai")
	srv := kiloUpstream(t, http.StatusOK, kiloOKBody)
	_, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/v1"})
	})
	if err != nil {
		t.Fatalf("runKiloVerify with OPENAI_API_KEY fallback = %v, want nil", err)
	}
}

func TestRunKiloVerify_BadBaseURLSkips(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", "gopher://weird"})
	})
	if !errors.Is(err, error(kiloVerifySkipErr)) {
		t.Fatalf("err = %v, want skip sentinel", err)
	}
	env := decodeKiloEnvelope(t, out)
	if env.ErrorClass != "bad_base_url" {
		t.Fatalf("envelope = %+v, want bad_base_url", env)
	}
}

func TestRunKiloVerify_UnreachableHostFails(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	port := nothingListening(t)
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", fmt.Sprintf("http://127.0.0.1:%d/v1", port)})
	})
	if !errors.Is(err, error(kiloVerifyFailErr)) {
		t.Fatalf("err = %v, want fail sentinel", err)
	}
	env := decodeKiloEnvelope(t, out)
	if env.Verdict != "fail" || env.ErrorClass != "refused" {
		t.Fatalf("envelope = %+v, want fail/refused", env)
	}
	if !strings.Contains(env.OperatorHint, "endpoint-check") {
		t.Fatalf("hint %q should point at endpoint-check", env.OperatorHint)
	}
}

func TestRunKiloVerify_Upstream401Skips(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	srv := kiloUpstream(t, http.StatusUnauthorized, `{"error":"bad key"}`)
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/v1"})
	})
	if !errors.Is(err, error(kiloVerifySkipErr)) {
		t.Fatalf("err = %v, want skip sentinel", err)
	}
	env := decodeKiloEnvelope(t, out)
	if env.ErrorClass != "upstream_4xx" {
		t.Fatalf("envelope = %+v, want upstream_4xx", env)
	}
}

func TestRunKiloVerify_Upstream500Fails(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	srv := kiloUpstream(t, http.StatusInternalServerError, `boom`)
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/v1"})
	})
	if !errors.Is(err, error(kiloVerifyFailErr)) {
		t.Fatalf("err = %v, want fail sentinel", err)
	}
	env := decodeKiloEnvelope(t, out)
	if env.ErrorClass != "http_500" {
		t.Fatalf("envelope = %+v, want http_500", env)
	}
}

func TestRunKiloVerify_NonJSONBodyFailsParse(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	srv := kiloUpstream(t, http.StatusOK, `<html>not json</html>`)
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/v1"})
	})
	if !errors.Is(err, error(kiloVerifyFailErr)) {
		t.Fatalf("err = %v, want fail sentinel", err)
	}
	if env := decodeKiloEnvelope(t, out); env.ErrorClass != "parse" {
		t.Fatalf("envelope = %+v, want parse", env)
	}
}

func TestRunKiloVerify_EmptyChoicesFails(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	srv := kiloUpstream(t, http.StatusOK, `{"id":"x","choices":[]}`)
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/v1"})
	})
	if !errors.Is(err, error(kiloVerifyFailErr)) {
		t.Fatalf("err = %v, want fail sentinel", err)
	}
	if env := decodeKiloEnvelope(t, out); env.ErrorClass != "empty_content" {
		t.Fatalf("envelope = %+v, want empty_content", env)
	}
}

func TestRunKiloVerify_InsecureFlagAllowsSelfSignedTLS(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	t.Setenv("HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY", "")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(kiloOKBody))
	}))
	defer srv.Close()

	// Without --insecure the self-signed chain must fail → skip (net class).
	_, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/v1"})
	})
	if !errors.Is(err, error(kiloVerifySkipErr)) {
		t.Fatalf("strict TLS err = %v, want skip sentinel (tls flake class)", err)
	}
	// With --insecure the same endpoint must pass.
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", srv.URL + "/v1", "--insecure"})
	})
	if err != nil {
		t.Fatalf("insecure TLS err = %v, want nil", err)
	}
	if env := decodeKiloEnvelope(t, out); env.Verdict != "pass" {
		t.Fatalf("envelope = %+v, want pass", env)
	}
}

func TestRunKiloVerify_ConfigFileAppliesWhenFlagsUnset(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	t.Setenv("HELIXCHANNEL_TARGET", "")
	t.Setenv("HELIXCHANNEL_MODEL", "")
	srv := kiloUpstream(t, http.StatusOK, kiloOKBody)
	dir := t.TempDir()
	cfgPath := dir + "/helix.yml"
	cfg := fmt.Sprintf("target: %s/cfg/v1\nmodel: cfg-model\ntimeout_seconds: 25\n", srv.URL)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--config", cfgPath})
	})
	if err != nil {
		t.Fatalf("runKiloVerify --config = %v, want nil", err)
	}
	env := decodeKiloEnvelope(t, out)
	if env.BaseURL != srv.URL+"/cfg/v1" || env.Model != "cfg-model" {
		t.Fatalf("envelope = %+v, want config-supplied target+model", env)
	}
}

func TestRunKiloVerify_TargetAliasOverridesEverything(t *testing.T) {
	t.Setenv("KILO_CODE_API_KEY", "sk")
	srv := kiloUpstream(t, http.StatusOK, kiloOKBody)
	out, err := captureStdout(t, func() error {
		return runKiloVerify([]string{"--base-url", "http://127.0.0.1:1/v1", "--target", srv.URL + "/alias/v1"})
	})
	if err != nil {
		t.Fatalf("runKiloVerify --target = %v, want nil", err)
	}
	if env := decodeKiloEnvelope(t, out); env.BaseURL != srv.URL+"/alias/v1" {
		t.Fatalf("base_url = %q, want the --target alias", env.BaseURL)
	}
}

func TestRunKiloVerify_BrokenConfigRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/broken.yml"
	if err := os.WriteFile(cfgPath, []byte(":\n  - ["), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := runKiloVerify([]string{"--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("err = %v, want config parse failure", err)
	}
}

func TestRunKiloVerify_BadFlagRejected(t *testing.T) {
	if err := runKiloVerify([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag = nil, want parse error")
	}
}

// --- endpoint-check (in-process) ---

func decodeEndpointEnvelope(t *testing.T, out string) endpointCheckEnvelope {
	t.Helper()
	var env endpointCheckEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("endpoint-check output not JSON: %v (%q)", err, out)
	}
	return env
}

func TestRunEndpointCheck_InProcess_RecommendsTCP443(t *testing.T) {
	l22 := listenFreeTCP(t)
	defer func() { _ = l22.Close() }()
	l443 := listenFreeTCP(t)
	defer func() { _ = l443.Close() }()

	out, err := captureStdout(t, func() error {
		return runEndpointCheck([]string{
			"--host", "127.0.0.1",
			"--tcp22-port", fmt.Sprint(l22.Port()),
			"--tcp443-port", fmt.Sprint(l443.Port()),
		})
	})
	if err != nil {
		t.Fatalf("runEndpointCheck = %v, want nil", err)
	}
	env := decodeEndpointEnvelope(t, out)
	if env.Recommendation != "tcp443" || !env.TCP22Reachable || !env.TCP443Reachable {
		t.Fatalf("envelope = %+v, want tcp443 with both reachable", env)
	}
}

func TestRunEndpointCheck_InProcess_TCP22Fallback(t *testing.T) {
	l22 := listenFreeTCP(t)
	defer func() { _ = l22.Close() }()
	closed := nothingListening(t)

	out, err := captureStdout(t, func() error {
		return runEndpointCheck([]string{
			"--host", "127.0.0.1",
			"--tcp22-port", fmt.Sprint(l22.Port()),
			"--tcp443-port", fmt.Sprint(closed),
		})
	})
	if err != nil {
		t.Fatalf("runEndpointCheck = %v, want nil", err)
	}
	env := decodeEndpointEnvelope(t, out)
	if env.Recommendation != "tcp22" || env.TCP443Error == "" {
		t.Fatalf("envelope = %+v, want tcp22 with a 443 error", env)
	}
}

func TestRunEndpointCheck_InProcess_NoneReachableErrors(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return runEndpointCheck([]string{
			"--host", "127.0.0.1",
			"--tcp22-port", fmt.Sprint(nothingListening(t)),
			"--tcp443-port", fmt.Sprint(nothingListening(t)),
			"--probe-timeout", "500ms",
		})
	})
	if err == nil || !strings.Contains(err.Error(), "neither TCP/22 nor TCP/443") {
		t.Fatalf("err = %v, want neither-reachable failure", err)
	}
	if env := decodeEndpointEnvelope(t, out); env.Recommendation != "none" {
		t.Fatalf("envelope = %+v, want none", env)
	}
}

func TestRunEndpointCheck_InProcess_TimeoutClampAndConfig(t *testing.T) {
	l443 := listenFreeTCP(t)
	defer func() { _ = l443.Close() }()
	dir := t.TempDir()
	cfgPath := dir + "/ok.yml"
	if err := os.WriteFile(cfgPath, []byte("model: m\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Out-of-range probe-timeout must clamp to the 2s default, not error.
	out, err := captureStdout(t, func() error {
		return runEndpointCheck([]string{
			"--host", "127.0.0.1",
			"--tcp22-port", fmt.Sprint(nothingListening(t)),
			"--tcp443-port", fmt.Sprint(l443.Port()),
			"--probe-timeout", "45s",
			"--config", cfgPath,
		})
	})
	if err != nil {
		t.Fatalf("runEndpointCheck = %v, want nil", err)
	}
	if env := decodeEndpointEnvelope(t, out); env.Recommendation != "tcp443" {
		t.Fatalf("envelope = %+v, want tcp443", env)
	}
}

func TestRunEndpointCheck_InProcess_BrokenConfigRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/broken.yml"
	if err := os.WriteFile(cfgPath, []byte("{{{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := runEndpointCheck([]string{"--host", "127.0.0.1", "--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("err = %v, want config failure", err)
	}
}

func TestRunEndpointCheck_InProcess_BadFlagRejected(t *testing.T) {
	if err := runEndpointCheck([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag = nil, want parse error")
	}
}
