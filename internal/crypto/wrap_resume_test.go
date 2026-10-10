package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// deadlineConn injects ONE timeout partway through a Read, then behaves
// normally. It reproduces exactly what a read deadline does to a framed
// protocol: the reader is interrupted having already consumed part of a record.
type deadlineConn struct {
	net.Conn
	tripped bool
	after   int
	read    int
}

type injectedTimeout struct{}

func (injectedTimeout) Error() string   { return "i/o timeout (injected)" }
func (injectedTimeout) Timeout() bool   { return true }
func (injectedTimeout) Temporary() bool { return true }

func (d *deadlineConn) Read(p []byte) (int, error) {
	if !d.tripped && d.read >= d.after {
		d.tripped = true
		return 0, injectedTimeout{}
	}
	n, err := d.Conn.Read(p)
	d.read += n
	return n, err
}

// TestWrap_ReadResumesAfterDeadline is the regression for the defect that made
// the AES leg fail every request after the first on a keep-alive connection.
//
// net/http sets a read deadline while waiting for the next request on a reused
// connection. When that deadline fires mid-record, a framed reader that has
// already consumed the 4-byte length prefix -- and cannot resume -- is
// permanently desynchronised: the next Read interprets ciphertext as a length
// prefix, and every later request on that connection dies. Measured on the live
// edge as 502 error="canceled" latency_ms=0, five times out of six, all on one
// client port.
//
// A correct framed Read treats a timeout as "no progress yet, call me again"
// and preserves whatever it has already buffered.
func TestWrap_ReadResumesAfterDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	key := prodKey()
	payload := make([]byte, 40*1024) // several records
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		w := Wrap(c, key)
		_, _ = w.Write(payload)
		time.Sleep(300 * time.Millisecond)
		_ = c.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()

	// Trip the timeout after 2 bytes: mid length-prefix, the worst case.
	client := Wrap(&deadlineConn{Conn: raw, after: 2}, key)

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	timeouts := 0
	deadline := time.Now().Add(20 * time.Second)
	for len(got) < len(payload) {
		if time.Now().After(deadline) {
			t.Fatalf("stalled at %d/%d bytes after %d timeouts", len(got), len(payload), timeouts)
		}
		n, rerr := client.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if rerr != nil {
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() {
				timeouts++
				continue // resume: this is the whole point
			}
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("read failed at %d/%d bytes: %v", len(got), len(payload), rerr)
		}
	}
	if timeouts == 0 {
		t.Fatal("the injected timeout never fired; this test proves nothing")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted after a mid-record timeout: got %d want %d", len(got), len(payload))
	}
}

// TestWrap_HTTPKeepAliveManyRequests is the end-to-end shape of the same
// defect: many SEQUENTIAL requests over one wrapped, reused connection, with a
// server read deadline in force between them. On the live edge this failed
// 5 of 6 after the first request.
func TestWrap_HTTPKeepAliveManyRequests(t *testing.T) {
	key := prodKey()
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	aesLn := WrapListener(rawLn, key)

	body := bytes.Repeat([]byte("x"), 12*1024) // spans records
	srv := &http.Server{
		ReadHeaderTimeout: 400 * time.Millisecond, // force deadlines between requests
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write(body)
		}),
	}
	go func() { _ = srv.Serve(aesLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	// ONE transport, keep-alives ON, so every request reuses the same conn.
	tr := &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			c, derr := d.DialContext(ctx, "tcp", rawLn.Addr().String())
			if derr != nil {
				return nil, derr
			}
			return Wrap(c, key), nil
		},
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}

	for i := 1; i <= 6; i++ {
		// Pause between requests so the server's read deadline fires while it
		// waits for the next one -- the live failure mode.
		if i > 1 {
			time.Sleep(500 * time.Millisecond)
		}
		req, _ := http.NewRequest(http.MethodPost, "http://aes/echo",
			bytes.NewReader(bytes.Repeat([]byte("q"), 8*1024)))
		resp, rerr := client.Do(req)
		if rerr != nil {
			t.Fatalf("request %d failed on the reused connection: %v", i, rerr)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status %d", i, resp.StatusCode)
		}
		if len(got) != len(body) {
			t.Fatalf("request %d: body %d bytes, want %d", i, len(got), len(body))
		}
	}
}
