//go:build realmodel

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// dialThruSOCKS5 opens a TLS-secured net.Conn to hostport through the SOCKS5
// proxy at proxyAddr. The returned conn is fully handshake-complete and is
// ready for HTTP/1.1 request bytes; the caller is responsible for closing
// it (use defer immediately on receipt).
//
// The SOCKS5 handshake uses the project's own
// `internal/proxy/socks5.DialContext` — not golang.org/x/net/proxy — so
// this test simultaneously exercises v18706's SOCKS5 client code path. A
// regression in the SOCKS5 client surfaces here before any LLM traffic is
// sent.
func dialThruSOCKS5(ctx context.Context, proxyAddr, hostport string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("dialThruSOCKS5: split hostport: %w", err)
	}
	// 30-second handshake budget covers a typical realmodel latency window.
	hsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := socks5Dial(hsCtx, proxyAddr, hostport)
	if err != nil {
		return nil, fmt.Errorf("dialThruSOCKS5: socks5: %w", err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("dialThruSOCKS5: tls handshake: %w", err)
	}
	return tlsConn, nil
}

// chatCompletionsRequest is the minimal OpenAI-compatible chat completions
// payload the DashScope endpoint accepts. We keep it small to minimise
// upstream token spend in the smoke test.
type chatCompletionsRequest struct {
	Model    string                   `json:"model"`
	Messages []chatCompletionsMessage `json:"messages"`
	Stream   bool                     `json:"stream"`
}

// chatCompletionsMessage is a single message in a chat-completions request.
type chatCompletionsMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatCompletionsResponse is the (partial) response shape from the DashScope
// OpenAI-compatible endpoint. We only decode the fields the smoke test
// checks; extra fields are ignored.
type chatCompletionsResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// callChatCompletions issues a real chat-completions request to the upstream
// endpoint via the supplied TLS-secured net.Conn. The conn is closed before
// returning. The returned string is the assistant reply content; an empty
// string with a non-nil error means the request failed.
//
// We issue the request manually (no net/http.Client) to keep this code
// illustrative: when the cert negotiation, TLS termination, and SOCKS5
// round-trip succeed, the bytes flow exactly as a real OpenAI client would.
func callChatCompletions(ctx context.Context, conn net.Conn, host, model, apiKey, prompt string) (string, error) {
	defer conn.Close()

	body, err := json.Marshal(chatCompletionsRequest{
		Model: model,
		Messages: []chatCompletionsMessage{
			{Role: "user", Content: prompt},
		},
		Stream: false,
	})
	if err != nil {
		return "", fmt.Errorf("callChatCompletions: marshal: %w", err)
	}

	var req bytes.Buffer
	req.WriteString("POST /compatible-mode/v1/chat/completions HTTP/1.1\r\n")
	req.WriteString("Host: " + host + "\r\n")
	req.WriteString("Content-Type: application/json\r\n")
	req.WriteString("Authorization: Bearer " + apiKey + "\r\n")
	req.WriteString("Content-Length: ")
	req.WriteString(fmt.Sprintf("%d", len(body)))
	req.WriteString("\r\n")
	req.WriteString("Connection: close\r\n")
	req.WriteString("\r\n")
	req.Write(body)

	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(60 * time.Second)
	}
	if err := conn.SetDeadline(dl); err != nil {
		return "", fmt.Errorf("callChatCompletions: set deadline: %w", err)
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return "", fmt.Errorf("callChatCompletions: write request: %w", err)
	}

	raw, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil {
		return "", fmt.Errorf("callChatCompletions: read response: %w", err)
	}
	const sep = "\r\n\r\n"
	idx := bytes.Index(raw, []byte(sep))
	if idx < 0 {
		return "", fmt.Errorf("callChatCompletions: malformed response (no header separator)")
	}
	hdrBlock := raw[:idx]
	bodyBlock := raw[idx+len(sep):]

	headerLines := strings.Split(string(hdrBlock), "\r\n")
	if len(headerLines) == 0 || !strings.HasPrefix(headerLines[0], "HTTP/") {
		return "", fmt.Errorf("callChatCompletions: first line is not an HTTP status: %q", headerLines[0])
	}
	if !strings.Contains(headerLines[0], " 200 ") {
		return "", fmt.Errorf("callChatCompletions: non-200 response %q body=%s", headerLines[0], string(bodyBlock))
	}

	var resp chatCompletionsResponse
	if err := json.Unmarshal(bodyBlock, &resp); err != nil {
		return "", fmt.Errorf("callChatCompletions: parse JSON: %w (body=%s)", err, string(bodyBlock))
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("callChatCompletions: empty choices (body=%s)", string(bodyBlock))
	}
	content := resp.Choices[0].Message.Content
	if strings.TrimSpace(content) == "" {
		return "", fmt.Errorf("callChatCompletions: empty content (body=%s)", string(bodyBlock))
	}
	return content, nil
}

// errNotUsed ensures the unused-import linter is satisfied for io.LimitReader.
// (LimitReader is part of the io package, imported inline; this is a defensive
// guard if a future refactor accidentally removes the io.ReadAll call.)
var _ = errors.New
