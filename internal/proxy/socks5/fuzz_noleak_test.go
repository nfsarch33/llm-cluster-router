// Package socks5 fuzz-no-leak target for ADR-083 Lightsail release
// readiness.
//
// Scope (v18710-2): ADR-083 C2 — plaintext SOCKS5 negotiation bytes
// MUST NOT leak via stdout/stderr in production builds.
//
// The fuzz target connects to a loopback SOCKS5 listener, writes the
// fuzz input as the (possibly malformed) handshake, then asserts that
// the fuzz input bytes are not echoed verbatim on the captured
// `log` output stream.
//
// Build tag rationale: this fuzz target runs only with the
// `adversarial` tag so unit `go test ./...` stays fast. Operators run:
//   go test -tags=adversarial -run=^$ -fuzz=FuzzSOCKS5NoLeak -fuzztime=30s ./internal/proxy/socks5/...
//
// Owner: cursor-parent@win3-wsl3 (v18710-2).
// Machine-Id: win3-wsl3.
//
//go:build adversarial

package socks5

import (
	"bytes"
	"context"
	"log"
	"net"
	"testing"
	"time"
)

// FuzzSOCKS5NoLeak verifies ADR-083 C2: when the SOCKS5 listener
// receives arbitrary client bytes, the fuzz input MUST NOT appear
// verbatim on the captured log stream. We swap the default `log`
// writer with a buffer for the duration of the iteration and assert
// the input is absent from the captured text.
//
// We use `log.SetOutput` rather than swapping os.Stderr because the
// stdlib log package serializes writes via an internal mutex; swapping
// os.Stderr directly is racy with anything that holds a reference to
// the original fd (including the SOCKS5 server goroutine). SetOutput
// is the supported redirection surface.
func FuzzSOCKS5NoLeak(f *testing.F) {
	f.Add([]byte{0x05, 0x01, 0x00})
	f.Add([]byte{0x05, 0x02, 0x00, 0x02})
	f.Add([]byte{0x05, 0x01, 0xff})
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add([]byte("password=ghp_FIXTURE_NOT_REAL_TOKEN_REPLACE_BEFORE_PUSH"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Capture log output via SetOutput (mutex-protected).
		buf := &bytes.Buffer{}
		origWriter := log.Writer()
		log.SetOutput(buf)
		defer log.SetOutput(origWriter)

		// Bind a fresh loopback listener.
		factory := NewListenerFactory()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ln, serve, err := factory.Listen(ctx, "127.0.0.1:0")
		if err != nil {
			t.Skipf("factory.Listen: %v (skipping; port exhaustion)", err)
			return
		}
		defer ln.Close()

		serveDone := make(chan struct{})
		go func() {
			defer close(serveDone)
			_ = serve(ctx, ln)
		}()
		defer func() {
			cancel()
			<-serveDone
		}()

		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_, _ = conn.Write(data)
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		readBuf := make([]byte, 1500)
		_, _ = conn.Read(readBuf)

		// Give the SOCKS5 server goroutine a brief moment to flush
		// its log line (if any). 50ms is well under the fuzz timeout.
		time.Sleep(50 * time.Millisecond)

		// Assert the fuzz input does not appear verbatim in the
		// captured log stream. Skip the empty-input case (nothing
		// to assert).
		if len(data) == 0 {
			return
		}
		if bytes.Contains(buf.Bytes(), data) {
			t.Fatalf("C2 violated: fuzz input %q appeared verbatim in captured log output", string(data))
		}
	})
}
