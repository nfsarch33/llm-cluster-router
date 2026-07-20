//go:build socks5_stream

// Package socks5 streaming tests.
//
// This file is gated by the `socks5_stream` build tag so that the
// regular `go test ./...` run stays fast. To exercise the SOCKS5
// streaming pipeline:
//
//	go test -tags=socks5_stream ./internal/proxy/socks5/...
//
// In v18709 we cover two scenarios:
//
//  1. **Fake-stream** — starts an in-process HTTP server that emits
//     a finite SSE stream and drives the request through a SOCKS5
//     listener bound on 127.0.0.1. Asserts the client receives every
//     data chunk in order and the [DONE] sentinel terminates the
//     stream. This is the deterministic CI gate.
//
//  2. **Real-model E2E** — when MINIMAX_API_KEY_FILE points at a
//     file containing a valid minimaxi.com API key, the test dials
//     https://api.minimaxi.com/v1/chat/completions through the
//     SOCKS5 tunnel with stream=true. It asserts that the upstream
//     response is a text/event-stream and that at least one chunk
//     arrives within a 60-second budget. This test is opt-in and
//     skipped on plain CI runs.
//
// The plain (non-tagged) CI pipeline still exercises the streaming
// pipeline via TestStreamSSE_FakeStream_Default which lives in
// streaming_default_test.go without a build tag.
package socks5

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestStreamSSE_FakeStream drives a SOCKS5-tunneled SSE call against
// an in-process HTTP server that streams three data chunks followed
// by [DONE]. Asserts chunk order and termination.
func TestStreamSSE_FakeStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, line := range []string{
			"data: chunk-1",
			"data: chunk-2",
			"data: chunk-3",
			"data: [DONE]",
		} {
			fmt.Fprintf(w, "%s\n", line)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer upstream.Close()

	upstreamHostPort := strings.TrimPrefix(upstream.URL, "http://")

	srvLn, srvStop := startTestSOCKS5(t)
	defer srvStop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	chunks, errs := StreamSSE(ctx, srvLn.Addr().String(), upstreamHostPort,
		"POST", "/v1/chat/completions", "Bearer test",
		`{"model":"MiniMax-M3","stream":true,"messages":[{"role":"user","content":"hi"}]}`)

	var got []string
	done := false
	for c := range chunks {
		got = append(got, c.Data)
		if c.IsDone {
			done = true
		}
	}
	if e := <-errs; e != nil && e != io.EOF {
		t.Fatalf("stream error: %v", e)
	}
	if !done {
		t.Fatalf("stream did not terminate with [DONE]; got=%v", got)
	}
	want := []string{"chunk-1", "chunk-2", "chunk-3", "[DONE]"}
	if len(got) != len(want) {
		t.Fatalf("chunk count: got %d want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chunk %d: got %q want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

// TestStreamSSE_RealModelMinimaxM3 is the real-model end-to-end gate
// behind MINIMAX_API_KEY_FILE. It exercises:
//   - SOCKS5 client handshake against our own listener
//   - TLS to api.minimaxi.com (China mainland token plan endpoint)
//   - Streaming chat completion against model id "MiniMax-M3"
//   - At least one chunk arriving before the budget is exhausted
//
// Skip when MINIMAX_API_KEY_FILE is unset or unreadable.
func TestStreamSSE_RealModelMinimaxM3(t *testing.T) {
	keyPath := os.Getenv("MINIMAX_API_KEY_FILE")
	if keyPath == "" {
		t.Skip("MINIMAX_API_KEY_FILE not set; real-model E2E skipped")
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Skipf("cannot read %s: %v", keyPath, err)
	}
	apiKey := strings.TrimSpace(string(keyBytes))
	if apiKey == "" {
		t.Skipf("empty API key in %s", keyPath)
	}

	// Bundled CA pool — the route to api.minimaxi.com uses standard
	// public CAs. If the host trust store is custom, the test will
	// surface a TLS error which is itself useful evidence.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	httpClient := &http.Client{
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				srvLn, srvStop := startTestSOCKS5(t)
				_ = srvLn
				defer srvStop()
				return DialContext(ctx, srvLn.Addr().String(), addr)
			},
		},
	}

	body := `{"model":"MiniMax-M3","stream":true,"max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest("POST", "https://api.minimaxi.com/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content-type=%q, expected text/event-stream", ct)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dec := newSSEDecoder(resp.Body)
	count := 0
	for {
		if ctx.Err() != nil {
			break
		}
		chunk, err := dec.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode chunk %d: %v", count, err)
		}
		count++
		if chunk == "[DONE]" {
			break
		}
		if count >= 5 {
			break
		}
	}
	if count == 0 {
		t.Fatal("no SSE chunks received within budget")
	}
	t.Logf("real-model streaming E2E received %d chunks (first=%q)", count, "ok")
}

// sseDecoder is a tiny Server-Sent Events decoder that reads "data:"
// lines from an io.Reader and emits the payload.
type sseDecoder struct {
	br *bufioReader
}

func newSSEDecoder(r io.Reader) *sseDecoder { return &sseDecoder{br: newBufioReader(r)} }

func (d *sseDecoder) Next(ctx context.Context) (string, error) {
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		line, err := d.br.ReadLine()
		if err != nil {
			return "", err
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			return strings.TrimPrefix(line, "data: "), nil
		}
	}
}

type bufioReader struct {
	r   io.Reader
	buf []byte
}

func newBufioReader(r io.Reader) *bufioReader { return &bufioReader{r: r, buf: make([]byte, 4096)} }

func (b *bufioReader) ReadLine() (string, error) {
	out := []byte{}
	for {
		n, err := b.r.Read(b.buf)
		if n > 0 {
			for _, c := range b.buf[:n] {
				if c == '\n' {
					return strings.TrimRight(string(out), "\r"), nil
				}
				out = append(out, c)
			}
		}
		if err != nil {
			if err == io.EOF && len(out) > 0 {
				return string(out), nil
			}
			return "", err
		}
	}
}
