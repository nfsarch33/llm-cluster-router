package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// prodKey is a distinct non-zero key for the productionisation tests
// (kept separate from testKey in wrap_test.go to avoid coupling).
func prodKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(255 - i)
	}
	return k
}

// tcpPipe returns two ends of a real TCP connection, each AES-wrapped
// with the same key. A real socket (not net.Pipe) is used so writes
// buffer the way they do in production rather than blocking per-frame.
func tcpPipe(t *testing.T) (client, server *WrapConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	key := prodKey()
	type acc struct {
		c   net.Conn
		err error
	}
	accCh := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		accCh <- acc{c, err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-accCh
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	client = Wrap(raw, key)
	server = Wrap(a.c, key)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// TestWrap_LargePayloadRoundTrip pushes a payload many times larger
// than maxFrame through the wrapper and reads it back with a SMALL
// buffer, proving Write splits into records and Read reassembles
// across records without dropping or corrupting a byte. This is the
// exact shape net/http subjects the conn to (32 KiB io.Copy writes,
// 4 KiB bufio reads).
func TestWrap_LargePayloadRoundTrip(t *testing.T) {
	client, server := tcpPipe(t)

	payload := make([]byte, 1<<20) // 1 MiB, ~16 maxFrame records
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	writeErr := make(chan error, 1)
	go func() {
		// One big Write; the wrapper must split it internally.
		n, err := server.Write(payload)
		if err == nil && n != len(payload) {
			err = fmt.Errorf("short write: %d != %d", n, len(payload))
		}
		writeErr <- err
	}()

	// Read back with a buffer far smaller than one record.
	got := make([]byte, 0, len(payload))
	small := make([]byte, 512)
	for len(got) < len(payload) {
		n, err := client.Read(small)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
		got = append(got, small[:n]...)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d (equal=%v)", len(got), len(payload), bytes.Equal(got, payload))
	}
}

// TestWrap_ByteAtATimeReads reads one byte per call across a record
// boundary, the pathological case for the leftover buffer.
func TestWrap_ByteAtATimeReads(t *testing.T) {
	client, server := tcpPipe(t)

	payload := []byte("boundary-spanning payload that is comfortably longer than a single read of one byte")
	go func() { _, _ = server.Write(payload) }()

	got := make([]byte, 0, len(payload))
	one := make([]byte, 1)
	for len(got) < len(payload) {
		n, err := client.Read(one)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, one[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

// TestWrap_HTTPOverWrapListener is the load-bearing proof: a real
// http.Server served over a WrapListener, and a real http.Client
// whose transport dials an AES-wrapped conn, exchange a request and a
// response body larger than maxFrame. If Write-split or Read-leftover
// were wrong, the body would be truncated or the handler would never
// parse the request. No TLS here — TLS is an orthogonal outer layer;
// this isolates the AES transport as an HTTP carrier.
func TestWrap_HTTPOverWrapListener(t *testing.T) {
	key := prodKey()

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	aesLn := WrapListener(rawLn, key)

	body := make([]byte, 300*1024) // > 4 maxFrame records
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var gotReqBody []byte
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotReqBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
		}),
	}
	go func() { _ = srv.Serve(aesLn) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Client transport dials the raw socket then AES-wraps it, so the
	// http.Transport speaks HTTP/1.1 over the encrypted stream.
	reqBody := make([]byte, 200*1024)
	if _, err := rand.Read(reqBody); err != nil {
		t.Fatalf("rand: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				c, derr := d.DialContext(ctx, "tcp", rawLn.Addr().String())
				if derr != nil {
					return nil, derr
				}
				return Wrap(c, key), nil
			},
		},
	}

	resp, err := client.Post("http://aes-inner/echo", "application/octet-stream", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !bytes.Equal(respBody, body) {
		t.Fatalf("response body mismatch: got %d bytes want %d", len(respBody), len(body))
	}
	if !bytes.Equal(gotReqBody, reqBody) {
		t.Fatalf("request body mismatch: got %d bytes want %d", len(gotReqBody), len(reqBody))
	}
}

// TestWrap_ConcurrentDuplex exercises a full-duplex conversation with
// independent reader/writer goroutines on each end, the documented
// safe concurrency mode, under large payloads.
func TestWrap_ConcurrentDuplex(t *testing.T) {
	client, server := tcpPipe(t)

	msg := bytes.Repeat([]byte("duplex-"), 20000) // ~140 KiB
	var wg sync.WaitGroup
	wg.Add(2)

	// server echoes what it reads back to client
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		got := 0
		for got < len(msg) {
			n, err := server.Read(buf)
			if err != nil {
				t.Errorf("server read: %v", err)
				return
			}
			if _, err := server.Write(buf[:n]); err != nil {
				t.Errorf("server write: %v", err)
				return
			}
			got += n
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := client.Write(msg); err != nil {
			t.Errorf("client write: %v", err)
		}
	}()

	got := make([]byte, 0, len(msg))
	buf := make([]byte, 4096)
	for len(got) < len(msg) {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	wg.Wait()
	if !bytes.Equal(got, msg) {
		t.Fatalf("duplex echo mismatch: %d vs %d", len(got), len(msg))
	}
}
