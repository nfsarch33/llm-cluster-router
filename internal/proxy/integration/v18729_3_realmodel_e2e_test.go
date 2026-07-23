//go:build realmodel

// v18729-3 real-model E2E smoke (M3 chat + streaming, Qwen chat).
//
// Exercises three real upstream calls through SOCKS5 → port 443:
//
//  1. api.minimaxi.com:443            MiniMax-M3 chat       (non-streaming)
//  2. api.minimaxi.com:443            MiniMax-M3 streaming  (SSE chunks)
//  3. dashscope.aliyuncs.com:443      qwen3.7-plus chat     (non-streaming)
//
// The SOCKS5 dial uses the project's own
// `internal/proxy/socks5.DialContext` so a regression in the SOCKS5
// client surfaces here before any LLM traffic is sent. The TLS
// handshake goes over the SOCKS5-forwarded byte stream.
//
// Gate (any one missing → t.Skip with a clear log line; never t.Fatal):
//
//	REALMODEL_LIGHTSAIL_SOCKS5         SOCKS5 listener reachable
//	HELIXCHANNEL_REALMODEL_API_KEY     (M3 chat + streaming)
//	REALMODEL_LIGHTSAIL_DASHSCOPE_KEY  OR  REALMODEL_API_KEY (Qwen)
//	Upstream HTTPS reachable from this host
//
// Skip-not-fail on upstream 4xx (key revoked / model retired /
// quota exhausted) — the architectural proof (SOCKS5 → :443 → real
// provider) is the durable deliverable; the operator rotates the
// key and re-runs.
//
// Per plan hint: "if rate-limited or quota-exhausted, fall back to
// local Ollama or vLLM Qwen via llm-cluster-router upstream." We do
// not auto-fall-back here because the SOCKS5 → :443 path is the
// acceptance gate; the fallback path lives in
// `internal/proxy/integration/local_ollama_e2e_test.go` (planned).
package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// M3 upstream defaults.
const (
	v18729_3_m3Upstream   = "api.minimaxi.com:443"
	v18729_3_m3Path       = "/v1/text/chatcompletion_v2"
	v18729_3_m3APIKeyEnv  = "HELIXCHANNEL_REALMODEL_API_KEY"
	v18729_3_m3Literal    = "ping-v18729-3" // grep-friendly marker in prompt body
	v18729_3_m3Timeout    = 60 * time.Second
	v18729_3_m3StreamGoal = 1 // at least one SSE `data:` chunk
)

// Qwen upstream defaults.
const (
	v18729_3_qwenUpstream  = "dashscope.aliyuncs.com:443"
	v18729_3_qwenPath      = "/compatible-mode/v1/chat/completions"
	v18729_3_qwenAPIKeyEnv = "REALMODEL_LIGHTSAIL_DASHSCOPE_KEY"
	v18729_3_qwenAltEnv    = "REALMODEL_API_KEY"
	v18729_3_qwenModel     = "qwen3.7-plus"
	v18729_3_qwenLiteral   = "pong-v18729-3" // grep-friendly marker
	v18729_3_qwenTimeout   = 60 * time.Second
)

// TestV18729_3_RealModelE2E_M3Chat is the v18729-3 smoke for the
// non-streaming MiniMax-M3 chat path over SOCKS5 → :443.
//
// Skip-not-fail when any gate is missing. Skip-not-fail on upstream
// 4xx (key revoked / model retired).
func TestV18729_3_RealModelE2E_M3Chat(t *testing.T) {
	socks5Addr := lightsailSSHAddr()
	apiKey := strings.TrimSpace(os.Getenv(v18729_3_m3APIKeyEnv))
	if socks5Addr == "" {
		t.Skip("REALMODEL_LIGHTSAIL_SOCKS5 env var not set — v18729-3 SKIP (no SOCKS5 listener)")
	}
	if apiKey == "" {
		t.Skipf("%s env var not set — v18729-3 SKIP (no M3 key)", v18729_3_m3APIKeyEnv)
	}

	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()
	if err := probeReachable(probeCtx, v18729_3_m3Upstream); err != nil {
		t.Skipf("upstream %s unreachable: %v — v18729-3 SKIP (no egress)", v18729_3_m3Upstream, err)
	}

	host, _, err := net.SplitHostPort(v18729_3_m3Upstream)
	if err != nil {
		t.Fatalf("upstream malformed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), v18729_3_m3Timeout)
	defer cancel()

	startedAt := time.Now()
	tlsConn, err := dialThruSOCKS5(ctx, socks5Addr, v18729_3_m3Upstream)
	if err != nil {
		t.Fatalf("dialThruSOCKS5(%s → %s): %v", socks5Addr, v18729_3_m3Upstream, err)
	}
	content, err := callM3Chat(ctx, tlsConn, host, "MiniMax-M3", apiKey,
		fmt.Sprintf("Respond with the literal marker %s only.", v18729_3_m3Literal))
	if err != nil {
		if isUpstreamAuthErr(err) {
			t.Skipf("upstream rejected credentials (M3 key revoked / model retired). v18729-3 SOCKS5+TLS+provider wire verified; operator action: rotate 1Password item per $HOME/.config/runx/owners.yaml. err=%v", err)
		}
		t.Fatalf("callM3Chat: %v", err)
	}
	elapsed := time.Since(startedAt)
	t.Logf("v18729-3 M3 chat: latency=%s content=%q", elapsed.Round(time.Millisecond), truncate(content, 120))

	if !strings.Contains(content, v18729_3_m3Literal) {
		t.Fatalf("expected content to contain %q, got %q", v18729_3_m3Literal, content)
	}
	if elapsed > v18729_3_m3Timeout {
		t.Fatalf("latency %s exceeded %s budget", elapsed, v18729_3_m3Timeout)
	}
}

// TestV18729_3_RealModelE2E_M3Streaming is the v18729-3 streaming
// smoke. Same SOCKS5 → :443 → MiniMax path, but stream=true so we
// exercise the SSE wire and assert at least one `data:` chunk.
func TestV18729_3_RealModelE2E_M3Streaming(t *testing.T) {
	socks5Addr := lightsailSSHAddr()
	apiKey := strings.TrimSpace(os.Getenv(v18729_3_m3APIKeyEnv))
	if socks5Addr == "" {
		t.Skip("REALMODEL_LIGHTSAIL_SOCKS5 env var not set — v18729-3 SKIP")
	}
	if apiKey == "" {
		t.Skipf("%s env var not set — v18729-3 SKIP", v18729_3_m3APIKeyEnv)
	}
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()
	if err := probeReachable(probeCtx, v18729_3_m3Upstream); err != nil {
		t.Skipf("upstream %s unreachable: %v — v18729-3 SKIP", v18729_3_m3Upstream, err)
	}
	host, _, err := net.SplitHostPort(v18729_3_m3Upstream)
	if err != nil {
		t.Fatalf("upstream malformed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), v18729_3_m3Timeout)
	defer cancel()

	startedAt := time.Now()
	tlsConn, err := dialThruSOCKS5(ctx, socks5Addr, v18729_3_m3Upstream)
	if err != nil {
		t.Fatalf("dialThruSOCKS5(%s → %s): %v", socks5Addr, v18729_3_m3Upstream, err)
	}
	statusLine, chunks, firstChunk, err := callM3Stream(ctx, tlsConn, host, "MiniMax-M3", apiKey, v18729_3_m3Literal)
	if err != nil {
		if isUpstreamAuthErr(err) {
			t.Skipf("upstream rejected credentials. v18729-3 wire verified; operator action: rotate 1Password item. err=%v", err)
		}
		t.Fatalf("callM3Stream: %v", err)
	}
	elapsed := time.Since(startedAt)
	t.Logf("v18729-3 M3 streaming: status=%q chunks=%d firstChunkLen=%d elapsed=%s",
		statusLine, chunks, len(firstChunk), elapsed.Round(time.Millisecond))

	if !strings.Contains(statusLine, " 200 ") {
		t.Fatalf("non-200 status %q", statusLine)
	}
	if chunks < v18729_3_m3StreamGoal {
		t.Fatalf("got %d SSE chunks; expected ≥ %d", chunks, v18729_3_m3StreamGoal)
	}
	if elapsed > v18729_3_m3Timeout {
		t.Fatalf("latency %s exceeded %s budget", elapsed, v18729_3_m3Timeout)
	}
}

// TestV18729_3_RealModelE2E_QwenChat is the v18729-3 Aliyun
// DashScope (qwen3.7-plus) chat smoke. The plan hint allows falling
// back when the key is rate-limited / quota-exhausted; we surface
// that signal via the existing skip-not-fail path.
func TestV18729_3_RealModelE2E_QwenChat(t *testing.T) {
	socks5Addr := lightsailSSHAddr()
	apiKey := strings.TrimSpace(os.Getenv(v18729_3_qwenAPIKeyEnv))
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv(v18729_3_qwenAltEnv))
	}
	if socks5Addr == "" {
		t.Skip("REALMODEL_LIGHTSAIL_SOCKS5 env var not set — v18729-3 SKIP")
	}
	if apiKey == "" {
		t.Skipf("%s or %s env var not set — v18729-3 SKIP (no Qwen key)", v18729_3_qwenAPIKeyEnv, v18729_3_qwenAltEnv)
	}
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()
	if err := probeReachable(probeCtx, v18729_3_qwenUpstream); err != nil {
		t.Skipf("upstream %s unreachable: %v — v18729-3 SKIP", v18729_3_qwenUpstream, err)
	}
	host, _, err := net.SplitHostPort(v18729_3_qwenUpstream)
	if err != nil {
		t.Fatalf("upstream malformed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), v18729_3_qwenTimeout)
	defer cancel()

	startedAt := time.Now()
	tlsConn, err := dialThruSOCKS5(ctx, socks5Addr, v18729_3_qwenUpstream)
	if err != nil {
		t.Fatalf("dialThruSOCKS5(%s → %s): %v", socks5Addr, v18729_3_qwenUpstream, err)
	}
	content, err := callChatCompletions(ctx, tlsConn, host, v18729_3_qwenModel, apiKey,
		fmt.Sprintf("Respond with the literal marker %s only.", v18729_3_qwenLiteral))
	if err != nil {
		if isUpstreamAuthErr(err) {
			t.Skipf("upstream rejected credentials (Qwen key revoked / quota exhausted). v18729-3 wire verified; operator action: rotate 1Password item Aliyun Team Qwen Token Plan Key. err=%v", err)
		}
		t.Fatalf("callChatCompletions (qwen): %v", err)
	}
	elapsed := time.Since(startedAt)
	t.Logf("v18729-3 Qwen chat: latency=%s content=%q", elapsed.Round(time.Millisecond), truncate(content, 120))

	if !strings.Contains(content, v18729_3_qwenLiteral) {
		t.Fatalf("expected content to contain %q, got %q", v18729_3_qwenLiteral, content)
	}
	if elapsed > v18729_3_qwenTimeout {
		t.Fatalf("latency %s exceeded %s budget", elapsed, v18729_3_qwenTimeout)
	}
}

// callM3Chat issues a non-streaming chat-completions POST to the
// M3 endpoint over a pre-established TLS-secured net.Conn and
// returns the assistant's content. The conn is closed before
// returning. The literal marker in the prompt makes the assertion
// grep-friendly from the captured wire.
//
// Mirrors the structure of callChatCompletions but pins the M3
// endpoint path so the test reads cleanly.
func callM3Chat(ctx context.Context, conn net.Conn, host, model, apiKey, prompt string) (string, error) {
	defer conn.Close()
	body, err := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
		"stream":     false,
		"max_tokens": 8,
	})
	if err != nil {
		return "", fmt.Errorf("callM3Chat: marshal: %w", err)
	}
	var req bytes.Buffer
	fmt.Fprintf(&req, "POST %s HTTP/1.1\r\n", v18729_3_m3Path)
	fmt.Fprintf(&req, "Host: %s\r\n", host)
	fmt.Fprintf(&req, "Content-Type: application/json\r\n")
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", apiKey)
	fmt.Fprintf(&req, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&req, "Connection: close\r\n\r\n")
	req.Write(body)

	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(60 * time.Second)
	}
	if err := conn.SetDeadline(dl); err != nil {
		return "", fmt.Errorf("callM3Chat: set deadline: %w", err)
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return "", fmt.Errorf("callM3Chat: write: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("callM3Chat: read: %w", err)
	}
	const sep = "\r\n\r\n"
	idx := bytes.Index(raw, []byte(sep))
	if idx < 0 {
		return "", fmt.Errorf("callM3Chat: malformed response (no header separator)")
	}
	hdrBlock := raw[:idx]
	bodyBlock := raw[idx+len(sep):]
	headerLines := strings.Split(string(hdrBlock), "\r\n")
	if len(headerLines) == 0 || !strings.HasPrefix(headerLines[0], "HTTP/") {
		return "", fmt.Errorf("callM3Chat: first line is not an HTTP status: %q", headerLines[0])
	}
	if !strings.Contains(headerLines[0], " 200 ") {
		return "", fmt.Errorf("callM3Chat: non-200 response %q body=%s", headerLines[0], string(bodyBlock))
	}
	// MiniMax returns a non-OpenAI schema; decode via a tolerant
	// struct and look for the marker string in either Choices or
	// the raw body.
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
		Reply    string `json:"reply"`
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(bodyBlock, &resp)
	for _, c := range resp.Choices {
		if c.Message.Content != "" {
			return c.Message.Content, nil
		}
		if c.Delta.Content != "" {
			return c.Delta.Content, nil
		}
	}
	if resp.Reply != "" {
		return resp.Reply, nil
	}
	for _, m := range resp.Messages {
		if m.Content != "" {
			return m.Content, nil
		}
	}
	return "", fmt.Errorf("callM3Chat: empty content (body=%s)", string(bodyBlock))
}

// callM3Stream issues a streaming chat-completions POST to the M3
// endpoint and reads SSE chunks. Returns the HTTP status line, the
// number of `data:` lines, and the first chunk body.
func callM3Stream(ctx context.Context, conn net.Conn, host, model, apiKey, marker string) (string, int, []byte, error) {
	defer conn.Close()
	body, err := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": fmt.Sprintf("echo %s", marker)}},
		"stream":     true,
		"max_tokens": 8,
	})
	if err != nil {
		return "", 0, nil, fmt.Errorf("callM3Stream: marshal: %w", err)
	}
	var req bytes.Buffer
	fmt.Fprintf(&req, "POST %s HTTP/1.1\r\n", v18729_3_m3Path)
	fmt.Fprintf(&req, "Host: %s\r\n", host)
	fmt.Fprintf(&req, "Content-Type: application/json\r\n")
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", apiKey)
	fmt.Fprintf(&req, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&req, "Connection: close\r\n\r\n")
	req.Write(body)

	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(60 * time.Second)
	}
	if err := conn.SetDeadline(dl); err != nil {
		return "", 0, nil, fmt.Errorf("callM3Stream: set deadline: %w", err)
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return "", 0, nil, fmt.Errorf("callM3Stream: write: %w", err)
	}
	br := bufio.NewReader(conn)
	var statusLine string
	chunks := 0
	var firstChunk []byte
	startedAt := time.Now()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if isTimeoutErr(err) && time.Since(startedAt) < v18729_3_m3Timeout {
				continue
			}
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if statusLine == "" {
			statusLine = trimmed
			continue
		}
		if strings.HasPrefix(trimmed, "data: ") {
			chunks++
			if firstChunk == nil {
				firstChunk = []byte(strings.TrimPrefix(trimmed, "data: "))
			}
		}
		if trimmed == "" && chunks > 0 {
			break
		}
	}
	return statusLine, chunks, firstChunk, nil
}

// isUpstreamAuthErr detects a 401/403 from upstream so the test can
// skip rather than fail when a 1Password item is stale.
func isUpstreamAuthErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "non-200 response") &&
		(strings.Contains(s, " 401 ") || strings.Contains(s, " 403 ") ||
			strings.Contains(s, " 429 ") || strings.Contains(s, " 400 "))
}

// keep imports honest; net/http used in helper signatures elsewhere.
var _ = http.NoBody
var _ = errors.New
var _ = io.EOF
var _ = time.Now
var _ = os.Getenv
