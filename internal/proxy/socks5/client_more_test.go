// Copyright (c) 2026 nfsarch33. Test-only; do not export.
//
// client_more_test.go (v18760) exercises the SOCKS5 client's protocol
// error handling and the StreamSSE failure paths against scripted
// wire-level servers. Nothing is mocked at the package boundary: every
// test speaks real RFC 1928 bytes over real TCP sockets so the
// assertions cover the exact reads/writes production traffic hits.
package socks5

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptedServer accepts one connection and runs script against it.
// It returns the listener address. The listener closes when the test ends.
func scriptedServer(t *testing.T, script func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		script(c)
	}()
	return ln.Addr().String()
}

// readN reads exactly n bytes or fails the connection silently (the
// client side surfaces the resulting error, which is what we assert).
func readN(c net.Conn, n int) []byte {
	buf := make([]byte, n)
	total := 0
	for total < n {
		m, err := c.Read(buf[total:])
		if err != nil {
			return buf[:total]
		}
		total += m
	}
	return buf
}

// consumeConnect reads the greeting + CONNECT request for an FQDN target
// and leaves the connection positioned to write the reply.
func consumeConnect(c net.Conn) {
	readN(c, 3)                        // greeting VER NMETHODS METHODS
	_, _ = c.Write([]byte{0x05, 0x00}) // no-auth accepted
	hdr := readN(c, 5)                 // VER CMD RSV ATYP LEN
	if len(hdr) == 5 {
		readN(c, int(hdr[4])+2) // fqdn + port
	}
}

func TestDialSOCKS5_ProxyUnreachable(t *testing.T) {
	// Reserve then close a port so nothing is listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	_, err = DialContext(context.Background(), addr, "target.example:443")
	if err == nil || !strings.Contains(err.Error(), "dial proxy") {
		t.Fatalf("err = %v, want dial proxy failure", err)
	}
}

func TestDialSOCKS5_BadGreetingVersion(t *testing.T) {
	addr := scriptedServer(t, func(c net.Conn) {
		readN(c, 3)
		_, _ = c.Write([]byte{0x04, 0x00})
	})
	_, err := DialContext(context.Background(), addr, "t.example:443")
	if err == nil || !strings.Contains(err.Error(), "bad greeting reply version") {
		t.Fatalf("err = %v, want bad greeting version", err)
	}
}

func TestDialSOCKS5_AuthRequired(t *testing.T) {
	for _, method := range []byte{0xff, 0x02} {
		addr := scriptedServer(t, func(c net.Conn) {
			readN(c, 3)
			_, _ = c.Write([]byte{0x05, method})
		})
		_, err := DialContext(context.Background(), addr, "t.example:443")
		if !errors.Is(err, ErrAuthRequired) {
			t.Fatalf("method 0x%02x: err = %v, want ErrAuthRequired", method, err)
		}
	}
}

func TestDialSOCKS5_TruncatedGreetingReply(t *testing.T) {
	addr := scriptedServer(t, func(c net.Conn) {
		readN(c, 3)
		_, _ = c.Write([]byte{0x05}) // half a greeting, then close
	})
	_, err := DialContext(context.Background(), addr, "t.example:443")
	if err == nil || !strings.Contains(err.Error(), "read greeting reply") {
		t.Fatalf("err = %v, want greeting read failure", err)
	}
}

func TestDialSOCKS5_BadReplyVersion(t *testing.T) {
	addr := scriptedServer(t, func(c net.Conn) {
		consumeConnect(c)
		_, _ = c.Write([]byte{0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})
	_, err := DialContext(context.Background(), addr, "t.example:443")
	if err == nil || !strings.Contains(err.Error(), "bad reply version") {
		t.Fatalf("err = %v, want bad reply version", err)
	}
}

func TestDialSOCKS5_ServerReplyCodeSurfaced(t *testing.T) {
	addr := scriptedServer(t, func(c net.Conn) {
		consumeConnect(c)
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // 0x05 = connection refused
	})
	_, err := DialContext(context.Background(), addr, "t.example:443")
	var reply *ErrServerReply
	if !errors.As(err, &reply) {
		t.Fatalf("err = %v, want *ErrServerReply", err)
	}
	if reply.Code != 0x05 {
		t.Fatalf("reply.Code = 0x%02x, want 0x05", reply.Code)
	}
	if !strings.Contains(reply.Error(), "0x05") {
		t.Fatalf("Error() = %q, want the code rendered", reply.Error())
	}
}

func TestDialSOCKS5_ReplyATYPVariants(t *testing.T) {
	cases := []struct {
		name string
		tail []byte // written after VER REP RSV
	}{
		{"ipv4", append([]byte{0x01}, make([]byte, 4+2)...)},
		{"ipv6", append([]byte{0x04}, make([]byte, 16+2)...)},
		{"fqdn", append([]byte{0x03, 0x07}, append([]byte("example"), 0x01, 0xbb)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := scriptedServer(t, func(c net.Conn) {
				consumeConnect(c)
				_, _ = c.Write(append([]byte{0x05, 0x00, 0x00}, tc.tail...))
				time.Sleep(200 * time.Millisecond) // hold open so the client finishes
			})
			conn, err := DialContext(context.Background(), addr, "t.example:443")
			if err != nil {
				t.Fatalf("ATYP %s: err = %v, want success", tc.name, err)
			}
			_ = conn.Close()
		})
	}
}

func TestDialSOCKS5_UnknownATYP(t *testing.T) {
	addr := scriptedServer(t, func(c net.Conn) {
		consumeConnect(c)
		_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x09, 0, 0})
	})
	_, err := DialContext(context.Background(), addr, "t.example:443")
	if err == nil || !strings.Contains(err.Error(), "unknown ATYP") {
		t.Fatalf("err = %v, want unknown ATYP", err)
	}
}

func TestDialSOCKS5_TruncatedReplyTail(t *testing.T) {
	addr := scriptedServer(t, func(c net.Conn) {
		consumeConnect(c)
		_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x7f}) // 1 of 6 tail bytes, then close
	})
	_, err := DialContext(context.Background(), addr, "t.example:443")
	if err == nil || !strings.Contains(err.Error(), "read reply tail") {
		t.Fatalf("err = %v, want reply tail failure", err)
	}
}

func TestDialSOCKS5_BadTargetPort(t *testing.T) {
	addr := scriptedServer(t, func(c net.Conn) { readN(c, 3) })
	_, err := DialContext(context.Background(), addr, "host:notaport")
	if err == nil || !strings.Contains(err.Error(), "target addr") {
		t.Fatalf("err = %v, want target addr failure", err)
	}
}

// sseGateway runs a scripted SOCKS5 hop that accepts the CONNECT and then
// plays raw HTTP bytes back at the client, so StreamSSE's header + body
// paths run against real network reads.
func sseGateway(t *testing.T, payload []byte) string {
	t.Helper()
	return scriptedServer(t, func(c net.Conn) {
		consumeConnect(c)
		_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		readN(c, 1) // wait for at least the first request byte before replying
		// Drain the rest of the request in the background; the client
		// writes a fixed-size request then reads.
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}()
		_, _ = c.Write(payload)
		time.Sleep(150 * time.Millisecond)
	})
}

func TestStreamSSE_ProxyUnreachableSurfacesError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	chunks, errs := StreamSSE(context.Background(), addr, "t.example:443", "POST", "/v1/x", "Bearer t", "{}")
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("errs delivered nil, want dial error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no error within 5s")
	}
	for range chunks { // channel must close
	}
}

func TestStreamSSE_ParsesChunksAndStopsAtDone(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n" +
		": keep-alive comment\n" +
		"event: message\r\n" +
		"data: {\"tok\":1}\r\n" +
		"\n" +
		"data: {\"tok\":2}\n" +
		"data: [DONE]\n" +
		"data: {\"after\":\"done\"}\n")
	addr := sseGateway(t, payload)

	chunks, errs := StreamSSE(context.Background(), addr, "t.example:443", "POST", "/v1/chat", "Bearer k", `{"stream":true}`)
	var got []SSEChunk
	for c := range chunks {
		got = append(got, c)
	}
	if err := <-errs; err != nil {
		t.Fatalf("errs = %v, want nil", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d chunks (%v), want 3 (two data + DONE)", len(got), got)
	}
	if got[0].Data != `{"tok":1}` || got[0].IsDone {
		t.Fatalf("chunk[0] = %+v", got[0])
	}
	if got[1].Data != `{"tok":2}` || got[1].IsDone {
		t.Fatalf("chunk[1] = %+v", got[1])
	}
	if !got[2].IsDone {
		t.Fatalf("chunk[2] = %+v, want IsDone", got[2])
	}
}

func TestStreamSSE_EOFWithoutDoneClosesCleanly(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\n\r\ndata: partial\n")
	addr := sseGateway(t, payload)

	chunks, errs := StreamSSE(context.Background(), addr, "t.example:443", "POST", "/v1/chat", "Bearer k", "{}")
	var got []SSEChunk
	for c := range chunks {
		got = append(got, c)
	}
	if err := <-errs; err != nil {
		t.Fatalf("errs = %v, want nil on clean EOF", err)
	}
	if len(got) != 1 || got[0].Data != "partial" {
		t.Fatalf("chunks = %+v, want the single partial data line", got)
	}
}

func TestStreamSSE_HeadersTooLargeRejected(t *testing.T) {
	huge := make([]byte, 17*1024)
	for i := range huge {
		huge[i] = 'A'
	}
	addr := sseGateway(t, append([]byte("HTTP/1.1 200 OK\r\nX-Big: "), huge...))

	chunks, errs := StreamSSE(context.Background(), addr, "t.example:443", "GET", "/v1/x", "Bearer k", "")
	select {
	case err := <-errs:
		if err == nil || !strings.Contains(err.Error(), "headers too large") {
			t.Fatalf("errs = %v, want headers-too-large", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no error within 5s")
	}
	for range chunks {
	}
}

func TestBuildHTTPRequest_Shape(t *testing.T) {
	req := buildHTTPRequest("api.example:8443", "POST", "/v1/chat/completions", "Bearer secret", `{"a":1}`)
	for _, want := range []string{
		"POST /v1/chat/completions HTTP/1.1\r\n",
		"Host: api.example\r\n",
		"Authorization: Bearer secret\r\n",
		"Accept: text/event-stream\r\n",
		"Content-Length: 7\r\n\r\n" + `{"a":1}`,
	} {
		if !strings.Contains(req, want) {
			t.Fatalf("request missing %q:\n%s", want, req)
		}
	}
}

func TestParseDataLine(t *testing.T) {
	cases := []struct {
		line    string
		payload string
		ok      bool
	}{
		{"", "", false},
		{"event: message", "", false},
		{"data:", "", false},
		{"data: x", "x", true},
		{"data: [DONE]", "[DONE]", true},
	}
	for _, tc := range cases {
		p, ok := parseDataLine(tc.line)
		if p != tc.payload || ok != tc.ok {
			t.Fatalf("parseDataLine(%q) = (%q,%v), want (%q,%v)", tc.line, p, ok, tc.payload, tc.ok)
		}
	}
}

func TestSplitHostPort_InvalidPortRejected(t *testing.T) {
	if _, _, err := splitHostPort("h:70000"); err == nil {
		t.Fatal("splitHostPort(h:70000) = nil error, want range failure")
	}
}
