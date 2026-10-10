// Copyright (c) 2026 nfsarch33. Test-only; v18750-Q3 B1.
//
// Cross-node LLM tunnel E2E: spins up a fake http server bound to
// 127.0.0.1:<port> on a side loopback listener, configures the tunnel
// package to forward to that loopback port via the fake ssh binary,
// and asserts that an HTTP request through the dial reaches the
// http server. This is the only way to test the full config -> dial
// -> http.Transport -> tunnel bridge roundtrip without a live fleet
// node.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/tunnel"
)

func TestCrossNode_TunnelDialReachesHTTPServer(t *testing.T) {
	// 1. Start an httptest.Server.
	hit := make(chan string, 8)
	var hitMu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hitMu.Lock()
		hits = append(hits, string(body))
		hitMu.Unlock()
		select {
		case hit <- string(body):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = fmt.Fprintf(w, `{"echo":%q,"from":"llama-server-fake"}`, string(body))
	}))
	defer srv.Close()

	// 2. Extract innerPort from srv.URL (127.0.0.1:NNNNN).
	innerAddr := srv.Listener.Addr().String()
	parts := strings.Split(innerAddr, ":")
	if len(parts) != 2 {
		t.Fatalf("bad srv URL: %s", innerAddr)
	}
	var innerPort int
	_, _ = fmt.Sscanf(parts[1], "%d", &innerPort)

	// 3. Spin up the fake ssh binary that forwards to innerPort.
	tmp := t.TempDir()
	fake := fmt.Sprintf(`#!/usr/bin/env python3
import socket, threading, sys
inner_port = %d
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(8)
print("FAKE_SSH_PORT=" + str(srv.getsockname()[1]), file=sys.stderr, flush=True)

def pipe(a, b):
    try:
        while True:
            data = a.recv(4096)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        try: a.close()
        except: pass
        try: b.close()
        except: pass

def handle(c):
    try:
        up = socket.create_connection(("127.0.0.1", inner_port), timeout=2)
        t1 = threading.Thread(target=pipe, args=(c, up), daemon=True)
        t2 = threading.Thread(target=pipe, args=(up, c), daemon=True)
        t1.start(); t2.start()
    except Exception:
        c.close()

while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
`, innerPort)
	sshPath := filepath.Join(tmp, "ssh")
	if err := os.WriteFile(sshPath, []byte(fake), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))

	// 4. Dial via tunnel. DialContext will spawn the fake ssh with
	// `-L <random>:127.0.0.1:8001` which our fake ignores (it forwards
	// straight to innerPort). The router http.Transport.DialContext
	// then connects to 127.0.0.1:<random>, the fake accepts, and pipes
	// bytes to innerPort.
	cfg := tunnel.SSHTunnelConfig{
		Host:           "jump.example",
		User:           "ubuntu",
		IdentityFile:   "/k",
		LocalPort:      innerPort, // tunnel.LocalPort == the server port
		Port:           22,
		ConnectTimeout: 5 * time.Second,
	}

	// To make the dial work, the fake ssh binds on a random port the
	// router can connect to. We need to read the port from fake ssh's
	// stderr — which DialContext captures and returns on error. The
	// cleanest path is to make the fake ssh listen on the same port
	// the tunnel expects, so we know where to dial.

	// Re-implement: have fake ssh bind to 127.0.0.1:18001 (a known
	// port), then have DialContext dial 127.0.0.1:18001 by setting
	// LocalPort=18001 on the listener it opens. But DialContext opens
	// ITS OWN listener for the -L port. To avoid the dance, we can:
	//
	// A. Skip the local listener: modify our fake to bind directly
	//    on the port the router will dial (127.0.0.1:0). Read the
	//    bound port from stderr. Pass it back to DialContext by
	//    setting `addr` to "127.0.0.1:<port>".
	//
	//    BUT DialContext ignores `addr` and uses ln.Addr() from its
	//    OWN listener. The -L arg we pass to ssh is irrelevant to the
	//    data path; it's only the parent-side port. So if our fake
	//    reads the -L flag, binds on THAT port, and forwards to
	//    innerPort, then DialContext's loopback listener (= the
	//    parent-side port from -L) must equal the port the fake ssh
	//    binds on.
	//
	// B. Cheat: bind the fake ssh on a fixed port and set
	//    LocalPort=that port in SSHTunnelConfig? No, LocalPort is the
	//    REMOTE port, not the parent-side.
	//
	// C. Easiest: pre-bind a listener ourselves on a free port,
	//    pass its address as the dial target, AND tell the fake ssh
	//    to bind on that port. But DialContext opens ITS OWN
	//    listener and uses that port for -L.
	//
	// Solution: have the fake ssh read `-L <port>` and bind on
	// <port> directly (reusing SO_REUSEADDR). It also needs to
	// parse the inner host:port from the same -L spec.

	fake2 := fmt.Sprintf(`#!/usr/bin/env python3
import socket, threading, sys, re
args = sys.argv[1:]
remote_port = None
inner_port = %d
i = 0
while i < len(args):
    if args[i] == "-L" and i + 1 < len(args):
        m = re.match(r"(\d+):[^:]+:(\d+)", args[i+1])
        if m:
            remote_port = int(m.group(1))
            inner_port = int(m.group(2))
        i += 2
    elif args[i] == "-N":
        i += 1
    elif args[i] in ("-i", "-p"):
        i += 2
    elif args[i] == "-o":
        i += 2
    elif args[i].startswith("-"):
        i += 1
    else:
        i += 1

if not remote_port:
    print("fake ssh: no -L port found", file=sys.stderr)
    sys.exit(2)

# tunnel.DialContext opens a loopback listener on remote_port and waits
# for ssh to connect to it. We are ssh, so we dial it (NOT bind).
# Then we bridge stdin/stdout with the inner test server on inner_port.
bridge = socket.create_connection(("127.0.0.1", remote_port), timeout=5)
upstream = socket.create_connection(("127.0.0.1", inner_port), timeout=5)
sys.stderr.write("FAKE_SSH_BRIDGED %%d %%d\n" %% (remote_port, inner_port))
sys.stderr.flush()

def pipe(a, b):
    try:
        while True:
            data = a.recv(4096)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        try: a.close()
        except: pass
        try: b.close()
        except: pass

t1 = threading.Thread(target=pipe, args=(bridge, upstream), daemon=True)
t2 = threading.Thread(target=pipe, args=(upstream, bridge), daemon=True)
t1.start()
t2.start()
t1.join()
t2.join()
`, innerPort)
	if err := os.WriteFile(sshPath, []byte(fake2), 0o755); err != nil {
		t.Fatalf("rewrite fake ssh: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Open a tunnel dial. The router's transport.DialContext will
	// accept on the local listener and return a bridged conn.
	conn, err := tunnel.DialContext(ctx, cfg, "tcp", "jump.example:0")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Issue a real HTTP request through that conn.
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			DisableKeepAlives: true,
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://jump.example/v1/chat/completions",
		strings.NewReader(`{"model":"qwen3.6-27b","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "llama-server-fake") {
		t.Fatalf("body did not echo from inner server: %s", string(body))
	}
	select {
	case got := <-hit:
		if !strings.Contains(got, "qwen3.6-27b") {
			t.Fatalf("inner server saw: %s; want qwen3.6-27b payload", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inner server was not hit within 2s")
	}
}
