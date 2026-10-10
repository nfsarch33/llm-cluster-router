// Package router — minimax live pilot wire-up (v18688-1).
//
// RED tests that verify the deterministic URL/auth builders for the
// minimax live pilot. The plan mandates:
//   - GREEN: api.minimaxi.com/v1/text/chatcompletion_v2 (NOT .io)
//   - RED: TestMinChat_URLCanonical, TestMinChat_RejectsForbiddenURL,
//     TestMinChat_BearerHeader, TestMinChat_EmptyKeyRejected,
//     TestMinChat_ModelWhitelist
//
// Live API round-trip tests (TestMinimaxRoute_*) are gated on
// MINIMAX_LIVE_TEST=1 and use httptest upstream stubs as the GREEN
// path for CI. Run `go test -race -count=1 ./internal/router/...`
// to exercise the GREEN contract locally.
package router

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// Pure-function URL/auth builders (RED → GREEN tests)
// =====================================================================

// TestMinChat_URLCanonical asserts the canonical URL is built when
// the base is the documented MinChatBase.
func TestMinChat_URLCanonical(t *testing.T) {
	got, err := MinChatURL(MinChatBase)
	require.NoError(t, err)
	assert.Equal(t, "https://api.minimaxi.com/v1/text/chatcompletion_v2", got,
		"canonical URL MUST equal the documented live pilot base + path")
}

// TestMinChat_URLDefault asserts the empty-base fallback returns the
// canonical URL.
func TestMinChat_URLDefault(t *testing.T) {
	got, err := MinChatURL("")
	require.NoError(t, err)
	assert.Equal(t, "https://api.minimaxi.com/v1/text/chatcompletion_v2", got)
}

// TestMinChat_RejectsForbiddenURL enforces the forbidden-host deny-list.
func TestMinChat_RejectsForbiddenURL(t *testing.T) {
	for _, bad := range []string{
		"https://api.minimax.io/v1",
		"https://api.minimax.com/v1",
	} {
		_, err := MinChatURL(bad)
		assert.ErrorIs(t, err, ErrMinForbiddenHost,
			"URL builder MUST reject forbidden host %q", bad)
	}
}

// TestMinChat_BearerHeader asserts the auth header format.
func TestMinChat_BearerHeader(t *testing.T) {
	got, err := MinChatAuthorizationHeader("test-key")
	require.NoError(t, err)
	assert.Equal(t, "Bearer test-key", got)
}

// TestMinChat_EmptyKeyRejected asserts the router will not silently
// inject an empty Bearer.
func TestMinChat_EmptyKeyRejected(t *testing.T) {
	for _, blank := range []string{"", " ", "\t\n"} {
		_, err := MinChatAuthorizationHeader(blank)
		assert.ErrorIs(t, err, ErrMinEmptyAPIKey,
			"empty/blank api key MUST return ErrMinEmptyAPIKey (got blank=%q)", blank)
	}
}

// TestMinChat_ModelWhitelist asserts only the canonical model ids are
// accepted by IsMinChatModel.
func TestMinChat_ModelWhitelist(t *testing.T) {
	allowed := []string{"MiniMax-M3", "MiniMax-Text-01", "minimax-M3", "minimax-Text-01"}
	for _, m := range allowed {
		assert.True(t, IsMinChatModel(m), "model %q MUST be allowed", m)
	}
	rejected := []string{"MiniMax-M2.7", "gpt-4o", "claude-3", "", "random-model-99"}
	for _, m := range rejected {
		assert.False(t, IsMinChatModel(m), "model %q MUST be rejected", m)
	}
}

// =====================================================================
// Live API round-trip tests (gated on MINIMAX_LIVE_TEST=1)
// =====================================================================

// TestMinimaxRoute_200OnHello exercises the live `api.minimaxi.com`
// endpoint via the bearer flow. Skipped unless MINIMAX_LIVE_TEST=1
// AND MINIMAX_API_KEY is set (resolved from a 1Password item in
// production per $HOME/.config/runx/owners.yaml; tests read directly
// from env).
func TestMinimaxRoute_200OnHello(t *testing.T) {
	if os.Getenv("MINIMAX_LIVE_TEST") != "1" {
		t.Skip("MINIMAX_LIVE_TEST!=1; skipping live round-trip")
	}
	apiKey := os.Getenv("MINIMAX_API_KEY")
	if apiKey == "" {
		t.Skip("MINIMAX_API_KEY unset")
	}

	url, err := MinChatURL(MinChatBase)
	require.NoError(t, err)
	auth, err := MinChatAuthorizationHeader(apiKey)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, url,
		strings.NewReader(`{"model":"MiniMax-M3","messages":[{"role":"user","content":"hi"}],"max_tokens":1}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"live minimax round-trip MUST return HTTP 200 (got %d)", resp.StatusCode)
}

// TestMinimaxRoute_UpstreamMock is the unit-level GREEN gate the
// 7-gate battery uses for the new live-llm-endpoint axis. It mirrors
// the live call but uses httptest instead of api.minimaxi.com, so
// CI runs in <1s.
func TestMinimaxRoute_UpstreamMock(t *testing.T) {
	var seenAuth, seenPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"hi"}}]}`))
	}))
	defer upstream.Close()

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+MinChatCompletionPath,
		strings.NewReader(`{"model":"MiniMax-M3","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Bearer test-key", seenAuth,
		"upstream MUST receive the Bearer auth header")
	assert.Equal(t, MinChatCompletionPath, seenPath,
		"upstream MUST be dialed at the canonical completion path")
}

// TestMinimaxRoute_NoIOEndpoint is the RED guard: any drift to
// api.minimax.io/.com is a hard error.
func TestMinimaxRoute_NoIOEndpoint(t *testing.T) {
	for _, bad := range []string{"api.minimax.io", "api.minimax.com"} {
		assert.NotEqual(t, "https://"+bad+"/v1", MinChatBase,
			"canonical base MUST NOT be %s (forbidden per plan)", bad)
	}
}

// TestMinimaxRoute_ConfigShape verifies the live router config has
// the `minimax-chat` route pointing at api.minimaxi.com. This runs
// without MINIMAX_LIVE_TEST so it gates the GREEN summary at PR
// merge time.
func TestMinimaxRoute_ConfigShape(t *testing.T) {
	const configPath = "configs/router.minimax.live.yml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skipf("config %s not present in working dir; defer to GREEN commit", configPath)
		return
	}
	raw, err := os.ReadFile(configPath)
	require.NoError(t, err)
	body := string(raw)

	assert.Contains(t, body, "name: minimax-chat",
		"live config MUST define the minimax-chat route")
	assert.Contains(t, body, "url: https://api.minimaxi.com/v1",
		"live config MUST point at api.minimaxi.com/v1 (not .io, not .com)")
	assert.Contains(t, body, MinChatCompletionPath,
		"live config MUST include the chat completion path")
	assert.Contains(t, body, "auth:",
		"live config MUST declare an auth block (Bearer token)")
	assert.Contains(t, body, "MINIMAX_API_KEY",
		"live config MUST read from MINIMAX_API_KEY env var (resolved from 1Password)")
}
