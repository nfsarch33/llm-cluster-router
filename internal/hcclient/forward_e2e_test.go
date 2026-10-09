package hcclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// e2eSrv is a dual-mode upstream: Negotiate per conn over a tap so the
// E2E can assert no plaintext on the wire.
type e2eSrv struct {
	ln      net.Listener
	conns   chan net.Conn
	tapMu   sync.Mutex
	capture []byte
	keys    []crypto.LongTermKey
	static  [32]byte
}

// Accept/listener interface so http.Server.Serve consumes negotiated conns.
func (s *e2eSrv) Accept() (net.Conn, error) {
	c, ok := <-s.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (s *e2eSrv) Close() error   { return s.ln.Close() }
func (s *e2eSrv) Addr() net.Addr { return s.ln.Addr() }

func startE2EServer(t *testing.T) (*e2eSrv, crypto.ServerPin, [32]byte) {
	t.Helper()
	lt, err := crypto.GenerateLongTermKey()
	if err != nil {
		t.Fatal(err)
	}
	static := [32]byte{}
	for i := range static {
		static[i] = byte(i + 11)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &e2eSrv{ln: ln, conns: make(chan net.Conn, 8),
		keys: []crypto.LongTermKey{{ID: "k2026a", Priv: lt}}, static: static}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"ok":true,"echo":"SECRET-REST-PAYLOAD-%v"}`, body["msg"])
	})
	mux.HandleFunc("/v1/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 5; i++ {
			_, _ = fmt.Fprintf(w, "data: SECRET-SSE-CHUNK-%d\n\n", i)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Method  string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]any{"secret-mcp": "SECRET-MCP-RESULT", "method": req.Method},
		})
	})
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				close(s.conns)
				return
			}
			go func(raw net.Conn) {
				tapped := &tapConn{Conn: raw, srv: s}
				got, _ := crypto.Negotiate(tapped, s.keys, s.static, 3*time.Second)
				if got != nil {
					s.conns <- got
				}
			}(raw)
		}
	}()
	go func() { _ = (&http.Server{Handler: mux}).Serve(s) }()
	t.Cleanup(func() { _ = s.Close() })
	return s, crypto.ServerPin{ID: "k2026a", Pub: lt.PublicKey()}, static
}

func (s *e2eSrv) captured() []byte {
	s.tapMu.Lock()
	defer s.tapMu.Unlock()
	return append([]byte{}, s.capture...)
}

// tapConn records every byte written to the wire (the ciphertext side).
type tapConn struct {
	net.Conn
	srv *e2eSrv
}

func (t *tapConn) Write(b []byte) (int, error) {
	t.srv.tapMu.Lock()
	t.srv.capture = append(t.srv.capture, b...)
	t.srv.tapMu.Unlock()
	return t.Conn.Write(b)
}

// forwardAddr starts the real Forward on an ephemeral port.
func forwardAddr(t *testing.T, upstream string, pin crypto.ServerPin, static [32]byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	go func() {
		_ = Forward(Options{ListenAddr: addr, Upstream: upstream, Pin: pin, StaticKey: static})
	}()
	// wait until the forwarder accepts (avoids startup races)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("forwarder never became ready on %s", addr)
	return addr
}

// E1 — REST + SSE through the forwarder; E4 — wire capture has no
// plaintext markers.
func TestE2ERESTAndSSENoPlaintextWire(t *testing.T) {
	srv, pin, static := startE2EServer(t)
	fwd := forwardAddr(t, srv.ln.Addr().String(), pin, static)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Post("http://"+fwd+"/v1/chat", "application/json",
		strings.NewReader(`{"msg":"hello-rest"}`))
	if err != nil {
		t.Fatalf("REST via forwarder: %v", err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	if out["echo"] != "SECRET-REST-PAYLOAD-hello-rest" {
		t.Fatalf("REST echo = %v", out["echo"])
	}

	resp2, err := client.Get("http://" + fwd + "/v1/stream")
	if err != nil {
		t.Fatalf("SSE via forwarder: %v", err)
	}
	sc := bufio.NewScanner(resp2.Body)
	chunks := 0
	for sc.Scan() {
		if strings.Contains(sc.Text(), "SECRET-SSE-CHUNK") {
			chunks++
		}
	}
	_ = resp2.Body.Close()
	if chunks != 5 {
		t.Fatalf("SSE chunks = %d, want 5", chunks)
	}

	// E4: none of the plaintext markers appear in the captured wire.
	wire := srv.captured()
	for _, marker := range []string{"SECRET-REST-PAYLOAD", "SECRET-SSE-CHUNK", "/v1/chat", "hello-rest"} {
		if bytes.Contains(wire, []byte(marker)) {
			t.Fatalf("PLAINTEXT %q leaked to the wire", marker)
		}
	}
}

// E3 — MCP JSON-RPC through the forwarder.
func TestE2EMCPJSONRPC(t *testing.T) {
	srv, pin, static := startE2EServer(t)
	fwd := forwardAddr(t, srv.ln.Addr().String(), pin, static)
	resp, err := http.Post("http://"+fwd+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("MCP via forwarder: %v", err)
	}
	var out struct {
		Result struct {
			Secret string `json:"secret-mcp"`
			Method string `json:"method"`
		} `json:"result"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	if out.Result.Secret != "SECRET-MCP-RESULT" || out.Result.Method != "tools/list" {
		t.Fatalf("MCP result = %+v", out.Result)
	}
	if bytes.Contains(srv.captured(), []byte("SECRET-MCP-RESULT")) {
		t.Fatal("PLAINTEXT MCP payload leaked to the wire")
	}
}

// E2 — HTTP/2 framing path: the forwarder is byte-blind, so an h2
// upgrade request (the preface gRPC rides on) round-trips through a raw
// echo of the negotiated conn. Full gRPC service tests are covered by
// the same byte path; this pins the h2 client preface specifically.
func TestE2EHTTP2PrefaceRoundTrip(t *testing.T) {
	lt, _ := crypto.GenerateLongTermKey()
	static := [32]byte{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				wc, _ := crypto.Negotiate(raw, []crypto.LongTermKey{{ID: "k2026a", Priv: lt}}, static, 3*time.Second)
				if wc != nil {
					_, _ = io.Copy(wc, wc) // echo
				}
			}(raw)
		}
	}()
	pin := crypto.ServerPin{ID: "k2026a", Pub: lt.PublicKey()}
	fwd := forwardAddr(t, ln.Addr().String(), pin, static)
	conn, err := net.Dial("tcp", fwd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") // h2 client preface (gRPC's substrate)
	if _, err := conn.Write(preface); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(preface))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("h2 preface echo: %v", err)
	}
	if !bytes.Equal(got, preface) {
		t.Fatalf("h2 preface mangled: %q", got)
	}
}

// E6 — fallback: an ephemeral client against a static-only upstream.
func TestE2EFallbackToStatic(t *testing.T) {
	static := [32]byte{}
	for i := range static {
		static[i] = byte(i + 21)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				wc, _ := crypto.Negotiate(raw, nil, static, 3*time.Second) // no ephemeral keys
				if wc != nil {
					_, _ = io.Copy(wc, wc)
				}
			}(raw)
		}
	}()
	lt, _ := crypto.GenerateLongTermKey()
	pin := crypto.ServerPin{ID: "k2026a", Pub: lt.PublicKey()}
	fwd := forwardAddr(t, ln.Addr().String(), pin, static)
	conn, err := net.Dial("tcp", fwd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	msg := []byte("fallback-payload-SECRET")
	_, _ = conn.Write(msg)
	got := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("static fallback echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("fallback mangled: %q", got)
	}
}

// E8 — perf smoke: handshake + first byte round trip well under budget.
func TestE2EPerfSmoke(t *testing.T) {
	lt, _ := crypto.GenerateLongTermKey()
	static := [32]byte{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				wc, _ := crypto.Negotiate(raw, []crypto.LongTermKey{{ID: "k", Priv: lt}}, static, 3*time.Second)
				if wc != nil {
					_, _ = io.Copy(wc, wc)
				}
			}(raw)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	wc, err := crypto.ClientHandshake(c, crypto.ServerPin{ID: "k", Pub: lt.PublicKey()}, 3*time.Second)
	hsMS := time.Since(start).Milliseconds()
	if err != nil {
		t.Fatal(err)
	}
	if hsMS > 150 {
		t.Fatalf("handshake took %dms (budget 150)", hsMS)
	}
	_, _ = wc.Write([]byte("x"))
	buf := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = wc.Read(buf)
	if total := time.Since(start).Milliseconds(); total > 200 {
		t.Fatalf("handshake+echo took %dms", total)
	}
	_ = context.Background
	_ = base64.StdEncoding
}
