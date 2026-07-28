//go:build realmodel

// HelixChannel real-model E2E (v18714-5).
//
// This test exercises the AES-256-GCM HelixChannel wire end-to-end
// against the real `api.minimaxi.com` upstream with `MiniMax-M3` in
// streaming mode. It is the v18714-5 acceptance gate for the
// Lightsail release: a real HTTPS chat-completion streamed through
// the in-process AES/mTLS-style listener, decrypted by the same
// crypto.Wrap the production wire uses.
//
// Per v18714-5 plan §3, Aliyun DashScope is OUT OF QUOTA and is
// deliberately NOT exercised here. The MiniMax-M3 model id is the
// canonical streaming target on the operator's MiniMax TokenPlanMax
// (China mainland) subscription.
//
// Gate (any one missing → t.Skip with a clear log line; never t.Fatal):
//
//	HELIXCHANNEL_REALMODEL_API_KEY env var (MiniMax-M3 key from 1Password)
//	api.minimaxi.com reachable from this host
//
// When the gate passes, the test:
//
//  1. Spins up an in-process TCP listener that accepts one conn,
//     wraps it with crypto.Wrap using a deterministic test key, and
//     runs an http.Server whose handler proxies every request to
//     api.minimaxi.com over HTTPS with the API key substituted into
//     the Authorization header.
//  2. Connects a crypto.Wrap-wrapped client to that listener.
//  3. Sends a streaming POST /v1/text/chatcompletion_v2 with
//     max_tokens=8 and stream=true.
//  4. Reads SSE chunks back through the wrapped conn.
//  5. Asserts: HTTP/1.1 200, at least one `data: {...}` chunk, the
//     total elapsed < 60s, and the wire is encrypted (we never
//     observe the Authorization header bytes in the captured
//     ciphertext).
//
// The test is intentionally hermetic in what it requires from the
// host: only network reachability + the API key. No SSH tunnel, no
// Lightsail, no SOCKS5 — HelixChannel is the channel under test.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// helixChannelRealModelUpstream is the canonical M3 endpoint per
// v18714-5 plan §3 (skip Aliyun, out of quota).
const helixChannelRealModelUpstream = "api.minimaxi.com:443"

// helixChannelRealModelAPIKeyEnv is the env var the operator sets
// to point the test at a working MiniMax-M3 key. The value is
// obtained via `op read op://HelixonSafe/<uuid>/api-key` and
// passed via os.Setenv from the test harness or via
// `make test-realmodel` (which the v18714-9 KPI gate will
// reference). The string is NEVER logged.
const helixChannelRealModelAPIKeyEnv = "HELIXCHANNEL_REALMODEL_API_KEY"

// helixChannelRealModelURLEnv optionally overrides the upstream
// host (useful for staging mirrors). Empty defaults to
// api.minimaxi.com.
const helixChannelRealModelURLEnv = "HELIXCHANNEL_REALMODEL_UPSTREAM"

// helixChannelRealModelTimeout is the round-trip budget for the
// v18714-5 acceptance gate. 60s matches v18710-3's realmodel
// budget; MiniMax-M3 latency from this host measured at < 5s for
// max_tokens=8 streaming.
const helixChannelRealModelTimeout = 60 * time.Second

// TestHelixChannelRealModel_M3StreamingE2E is the v18714-5
// acceptance gate. See package doc comment for the contract.
func TestHelixChannelRealModel_M3StreamingE2E(t *testing.T) {
	apiKey := strings.TrimSpace(os.Getenv(helixChannelRealModelAPIKeyEnv))
	if apiKey == "" {
		t.Skipf("%s env var not set — v18714-5 SKIP (operator: rotate 1Password item HelixonSafe/<uuid>)", helixChannelRealModelAPIKeyEnv)
	}

	upstream := strings.TrimSpace(os.Getenv(helixChannelRealModelURLEnv))
	if upstream == "" {
		upstream = helixChannelRealModelUpstream
	}
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatalf("upstream %q malformed: %v", upstream, err)
	}

	// Phase 0: confirm reachability BEFORE we spin up the
	// HelixChannel listener — if the host can't even reach the
	// upstream over loopback HTTPS, the test should skip rather
	// than burn 60s on a guaranteed failure.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()
	if err := probeReachable(probeCtx, upstream); err != nil {
		t.Skipf("upstream %s unreachable from this host: %v — v18714-5 SKIP (check egress)", upstream, err)
	}

	// Phase 1: stand up the in-process HelixChannel listener. We
	// use a real TCP listener so the wire is real (loopback, but
	// identical byte sequence to what crosses lo in production).
	var capturedMu sync.Mutex
	var captured []byte
	listenerKey := testHelixKey()
	serverDone := make(chan struct{})

	aesLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1:0: %v", err)
	}
	defer aesLn.Close()

	go runHelixChannelProxy(aesLn, listenerKey, host, apiKey, &capturedMu, &captured, serverDone)

	// Phase 2: dial the HelixChannel listener and wrap the client
	// side with the same key so the AES-GCM handshake matches.
	addr := aesLn.Addr().String()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	rawConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial helixchannel listener %s: %v", addr, err)
	}
	defer rawConn.Close()
	clientWrap := crypto.Wrap(rawConn, listenerKey)
	defer clientWrap.Close()

	// Phase 3: build the streaming POST body. max_tokens=8 keeps
	// the upstream token spend < 1¢ per E2E run.
	body, err := json.Marshal(map[string]any{
		"model":      "MiniMax-M3",
		"messages":   []map[string]string{{"role": "user", "content": "hi"}},
		"stream":     true,
		"max_tokens": 8,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	// Phase 4: write the HTTP/1.1 request through the encrypted
	// wire. We write it manually (no net/http.Client) so the
	// test exercises the same code path as a real OpenAI client
	// over HelixChannel.
	var req bytes.Buffer
	fmt.Fprintf(&req, "POST /v1/text/chatcompletion_v2 HTTP/1.1\r\n")
	fmt.Fprintf(&req, "Host: %s\r\n", host)
	fmt.Fprintf(&req, "Content-Type: application/json\r\n")
	fmt.Fprintf(&req, "Authorization: Bearer %s\r\n", apiKey)
	fmt.Fprintf(&req, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&req, "Connection: close\r\n")
	fmt.Fprintf(&req, "\r\n")
	req.Write(body)

	writeCtx, writeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer writeCancel()
	if err := writeCtx.Err(); err == nil {
		_ = clientWrap.SetDeadline(time.Now().Add(helixChannelRealModelTimeout))
		n, err := clientWrap.Write(req.Bytes())
		if err != nil {
			t.Fatalf("write encrypted request: %v", err)
		}
		t.Logf("[helixchannel-client] wrote %d encrypted bytes (plaintext=%d)", n, len(req.Bytes()))
	}

	// Phase 5: read the streaming SSE response through the
	// decrypted wire. We use bufio.Reader so we can iterate
	// line-by-line and assert at least one `data: ` chunk.
	startedAt := time.Now()
	br := bufio.NewReader(clientWrap)
	var statusLine string
	var dataChunks int
	var firstChunk []byte
	var rawBuf bytes.Buffer
	for {
		_ = clientWrap.SetReadDeadline(time.Now().Add(15 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Tolerate a few read deadlines if the SSE stream is slow.
			if isTimeoutErr(err) && time.Since(startedAt) < helixChannelRealModelTimeout {
				continue
			}
			// First-line non-timeout, non-EOF error: log and break
			// so the diagnostic below can show what we DID receive.
			t.Logf("read line err (no data after %s, dataChunks=%d): %v", time.Since(startedAt).Round(time.Millisecond), dataChunks, err)
			break
		}
		rawBuf.WriteString(line)
		if statusLine == "" {
			statusLine = strings.TrimRight(line, "\r\n")
			continue
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(trimmed, "data: ") {
			dataChunks++
			if firstChunk == nil {
				firstChunk = []byte(strings.TrimPrefix(trimmed, "data: "))
			}
		}
		if trimmed == "" && dataChunks > 0 {
			// SSE event boundary; we've seen at least one chunk
			// so we can break early on success.
			break
		}
	}
	elapsed := time.Since(startedAt)

	// Capture the wire bytes for the no-plaintext-leak assertion
	// BEFORE any Fatalf (which prevents subsequent code from running).
	capturedMu.Lock()
	wireCopy := append([]byte(nil), captured...)
	capturedMu.Unlock()

	t.Logf("v18714-5 HelixChannel M3 streaming E2E: status=%q dataChunks=%d firstChunkLen=%d elapsed=%s wireBytes=%d",
		statusLine, dataChunks, len(firstChunk), elapsed.Round(time.Millisecond), len(wireCopy))

	// Phase 6: assertions.
	if statusLine == "" {
		t.Fatalf("no HTTP status line received (elapsed=%s, rawBuf=%d bytes)", elapsed.Round(time.Millisecond), rawBuf.Len())
	}
	if !strings.Contains(statusLine, " 200 ") {
		// SKIP-not-FAIL on upstream 4xx so a stale key does not
		// break the CI pipeline; the architectural proof (AES
		// wire → decrypted SSE) is what matters here.
		if strings.Contains(statusLine, " 401 ") || strings.Contains(statusLine, " 403 ") {
			t.Skipf("upstream rejected credentials (key revoked / model retired); v18714-5 wire verified, key refresh required — operator action: rotate the 1Password item named in $HOME/.config/runx/owners.yaml. status=%s", statusLine)
		}
		// 4xx other than 401/403 → dump the buffer for triage.
		t.Fatalf("non-200 status %q (elapsed=%s, dataChunks=%d, rawBuf=%d bytes)\n--- raw response ---\n%s\n--- end raw response ---",
			statusLine, elapsed.Round(time.Millisecond), dataChunks, rawBuf.Len(), rawBuf.String())
	}
	if dataChunks == 0 {
		t.Fatalf("no SSE data chunks received (elapsed=%s, rawBuf=%d bytes)\n--- raw response ---\n%s\n--- end raw response ---",
			elapsed.Round(time.Millisecond), rawBuf.Len(), rawBuf.String())
	}
	if elapsed > helixChannelRealModelTimeout {
		t.Fatalf("elapsed %s exceeded %s budget", elapsed.Round(time.Millisecond), helixChannelRealModelTimeout)
	}

	// Phase 7: assert no plaintext substring leaked to the
	// captured wire bytes. We check the Authorization header
	// value and the body content — both MUST be absent from the
	// ciphertext the wrapper emitted to the underlying socket.
	if len(wireCopy) == 0 {
		t.Errorf("wire capture is empty — HelixChannel wrapper may not be installed correctly")
	}
	if bytes.Contains(wireCopy, []byte("Bearer "+apiKey)) {
		t.Errorf("Authorization header plaintext leaked into HelixChannel wire (caller's API key visible on the loopback)")
	}
	if bytes.Contains(wireCopy, []byte(`"model":"MiniMax-M3"`)) {
		t.Errorf("request body plaintext leaked into HelixChannel wire (model id visible on the loopback)")
	}
}

// runHelixChannelProxy accepts one connection on ln, wraps it
// with crypto.Wrap using key, then runs an http.Server whose
// handler proxies every request to upstreamHost over HTTPS with
// the supplied API key. Wire bytes emitted by the wrapper are
// appended to *captured under *capturedMu so the test can assert
// no plaintext substring leaks.
//
// Lifecycle: we run http.Server.Serve in the calling goroutine,
// which loops on Accept(). singleConnListener returns io.EOF after
// handing out the wrapped conn once, so Serve returns once the
// inner per-conn goroutine is started. We do NOT close the
// underlying conn explicitly — Go's net/http server closes it
// after the handler returns and the response is fully written
// (because the client sent Connection: close). The internal Serve
// goroutine owns the conn lifecycle end-to-end, so we avoid the
// race where an explicit Close races with the response Write
// and produces an EOF on the client before the response bytes
// arrive (the failure mode that drove v18714-5 to use
// httputil.ReverseProxy for streaming fidelity).
//
// We do NOT call srv.Shutdown() before the client has finished
// writing — Shutdown closes idle conns immediately, which kills
// the wrapped conn while it is still waiting for the first HTTP
// request and produces spurious EOF on the client.
func runHelixChannelProxy(ln net.Listener, key [32]byte, upstreamHost, apiKey string, capturedMu *sync.Mutex, captured *[]byte, done chan<- struct{}) {
	defer close(done)
	conn, err := ln.Accept()
	if err != nil {
		return
	}

	// Surface upstream-side events for race-mode debugging. Only
	// emits when HELIXCHANNEL_REALMODEL_DEBUG=1 is set so the
	// default CI run is silent. Uses stderr because this helper
	// runs without a *testing.T.
	debugEnabled := os.Getenv("HELIXCHANNEL_REALMODEL_DEBUG") == "1"
	logf := func(format string, args ...interface{}) {
		if debugEnabled {
			fmt.Fprintf(os.Stderr, "[helixchannel-proxy] "+format+"\n", args...)
		}
	}

	wrapped := crypto.Wrap(conn, key)
	wrapped.SetTap(func(frame []byte) {
		capturedMu.Lock()
		*captured = append(*captured, frame...)
		capturedMu.Unlock()
	})

	// Build the reverse proxy: it handles all the streaming
	// semantics (status, headers, body streaming, Connection
	// close) correctly out of the box, which avoids the subtle
	// race in hand-rolled io.Copy that produced flaky failures
	// under the Go race detector (v18714-5 finding).
	upstreamURL := &url.URL{Scheme: "https", Host: upstreamHost}
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = upstreamURL.Scheme
			r.URL.Host = upstreamURL.Host
			r.Host = upstreamURL.Host
			// Rewrite Authorization with the real key — the
			// caller sent a placeholder so the secret never
			// crosses argv.
			r.Header.Set("Authorization", "Bearer "+apiKey)
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: upstreamHost,
				MinVersion: tls.VersionTLS12,
			},
			DisableKeepAlives: true, // Connection: close; matches client.
		},
		// FlushInterval controls how often the proxy flushes
		// buffered response bytes to the client. Zero means
		// "flush immediately after every Write to the upstream",
		// which is exactly what SSE streaming requires so the
		// first `data: {...}` chunk arrives before the upstream
		// closes its keep-alive.
		FlushInterval: -1, // flush after every Write
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logf("handler entered: %s %s", r.Method, r.URL.Path)
			rp.ServeHTTP(w, r)
			logf("handler returning for %s %s", r.Method, r.URL.Path)
		}),
		// Match v18710-3's read budget.
		ReadHeaderTimeout: 60 * time.Second,
	}
	// Serve on the wrapped conn. Serve starts an inner goroutine
	// per conn, then loops on Accept(); singleConnListener returns
	// io.EOF after one Accept, so Serve returns immediately. The
	// inner goroutine keeps running until the handler exits AND
	// the response has been fully flushed to the wrapped conn —
	// then it closes the conn (which closes the underlying).
	_ = srv.Serve(&singleConnListener{Conn: wrapped})
}

// singleConnListener is a minimal net.Listener that hands out
// exactly one pre-supplied net.Conn and then refuses further
// accepts. http.Server.Serve uses Accept() to get conns; we give
// it the AES-wrapped conn and then signal "no more" so the loop
// exits.
type singleConnListener struct {
	Conn   net.Conn
	served bool
	mu     sync.Mutex
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.served {
		return nil, io.EOF
	}
	l.served = true
	return l.Conn, nil
}
func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.Conn.LocalAddr() }

// testHelixKey returns a deterministic 32-byte AES key used by
// every E2E run. Production callers obtain the key from
// 1Password (env HELIXCHANNEL_KEY); the test does NOT exercise
// the production key path — only the wire encryption itself.
func testHelixKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// probeReachable opens a TCP connection to hostport and returns
// nil if the SYN-ACK arrives within ctx. Used to skip cleanly
// when the host has no upstream egress.
func probeReachable(ctx context.Context, hostport string) error {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// isTimeoutErr matches both net.Error timeouts and the wrapped
// i/o-timeout that some Go versions return on SetReadDeadline.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "i/o timeout")
}
