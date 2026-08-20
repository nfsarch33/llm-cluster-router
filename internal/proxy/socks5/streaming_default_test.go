package socks5

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStreamSSE_FakeStream_Default is the deterministic, non-build-tagged
// CI gate for the SOCKS5 streaming pipeline. It runs on every
// `go test ./...` invocation so v18709-3 cannot regress without
// surfacing a test failure.
//
// Scope: a SOCKS5 listener bound on 127.0.0.1, an in-process HTTP
// upstream that emits 3 SSE chunks then [DONE], and our StreamSSE
// client driving a streaming POST through the tunnel. Asserts every
// chunk arrives in order and [DONE] terminates the stream.
//
// The real-model gate (api.minimaxi.com / MiniMax-M3) lives in
// streaming_test.go behind the `socks5_stream` build tag.
func TestStreamSSE_FakeStream_Default(t *testing.T) {
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
			_, _ = fmt.Fprintf(w, "%s\n", line)
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
