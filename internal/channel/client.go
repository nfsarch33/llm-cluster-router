package channel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ClientProxy is the loopback forward proxy an agent points HTTPS_PROXY at.
//
// It exists because some agents cannot be pointed at a rewritten base URL
// without losing functionality: Claude Code, for example, disables Remote
// Control when ANTHROPIC_BASE_URL names a non-Anthropic host, while
// HTTPS_PROXY is the documented, supported path. The proxy accepts a plain
// CONNECT on loopback and re-issues it inside a TLS session to the gateway,
// so the agent's own TLS to the provider is nested inside the channel's TLS:
// no hop in between — including the gateway — can read or tamper with it.
//
//	agent → 127.0.0.1:port (plain CONNECT)
//	      → TLS to gateway → CONNECT (token-authorised)
//	      → gateway dials provider → end-to-end TLS inside the tunnel
type ClientProxy struct {
	// Listen is the loopback bind address for the agent to point at.
	Listen string
	// Gateway is the channel edge, "host:port" (TLS).
	Gateway string
	// Token authorises the CONNECT at the gateway.
	Token string
	// InsecureSkipVerify disables verification of the gateway certificate.
	// Needed only while the pilot edge serves a self-signed certificate;
	// it affects the outer channel hop only — the agent's inner TLS to the
	// provider is still verified end to end by the agent itself.
	InsecureSkipVerify bool
	// DialTimeout bounds the dial to the gateway.
	DialTimeout time.Duration
	// Audit receives connection events; may be nil.
	Audit Auditor

	httpSrv *http.Server
}

// ListenAndServe runs the client proxy until ctx is cancelled.
func (c *ClientProxy) ListenAndServe(ctx context.Context) error {
	if c.Gateway == "" {
		return fmt.Errorf("gateway is required")
	}
	if c.Token == "" {
		return fmt.Errorf("token is required")
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 15 * time.Second
	}
	c.httpSrv = &http.Server{
		Addr:              c.Listen,
		Handler:           http.HandlerFunc(c.handle),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := c.httpSrv.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// logEvent records an event, tolerating a nil Auditor so the handler is safe
// to drive directly (tests, embedding) and not only via ListenAndServe.
func (c *ClientProxy) logEvent(e AuditEvent) {
	if c.Audit != nil {
		c.Audit.Log(e)
	}
}

func (c *ClientProxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// Plain HTTP through the channel would travel unencrypted on the
		// inner hop; refuse rather than silently downgrade.
		http.Error(w, "only CONNECT is supported; configure the agent to use HTTPS", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}

	tunnel, err := c.dialGateway(target)
	if err != nil {
		http.Error(w, "channel unavailable", http.StatusBadGateway)
		c.logEvent(AuditEvent{
			Event: "client_connect_failed", Target: target,
			Status: http.StatusBadGateway, LatencyMS: time.Since(start).Milliseconds(),
			Error: errorClass(err),
		})
		return
	}
	defer tunnel.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	c.logEvent(AuditEvent{
		Event: "client_connect_established", Target: target,
		Status: http.StatusOK, LatencyMS: time.Since(start).Milliseconds(),
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(tunnel, client) }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, tunnel) }()
	wg.Wait()
}

// dialGateway opens the TLS hop to the gateway and completes a CONNECT for
// target, returning the established tunnel.
func (c *ClientProxy) dialGateway(target string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(c.Gateway)
	if err != nil {
		host = c.Gateway
	}
	timeout := c.DialTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", c.Gateway, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // pilot edge uses a self-signed cert; see field docs
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: http.Header{"Proxy-Authorization": {"Bearer " + c.Token}},
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("gateway refused CONNECT: %s", resp.Status)
	}
	// Any bytes the gateway already buffered belong to the tunnel and must
	// not be dropped when we hand the raw connection back.
	if br.Buffered() > 0 {
		pending := make([]byte, br.Buffered())
		if _, err := io.ReadFull(br, pending); err != nil {
			conn.Close()
			return nil, fmt.Errorf("drain buffered bytes: %w", err)
		}
		return &prefixedConn{Conn: conn, pending: pending}, nil
	}
	return conn, nil
}

// prefixedConn replays bytes that were read into a bufio.Reader before the
// caller took ownership of the connection.
type prefixedConn struct {
	net.Conn
	pending []byte
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if len(p.pending) > 0 {
		n := copy(b, p.pending)
		p.pending = p.pending[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// ProxyEnv returns the environment settings an agent needs in order to route
// through a running client proxy. Returned as data so callers (CLI, docs
// generator, tests) share one definition of the contract.
//
// NO_PROXY keeps loopback traffic off the proxy, which prevents a proxy that
// is asked to reach itself from deadlocking.
func ProxyEnv(listen string) map[string]string {
	addr := listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	endpoint := "http://" + addr
	return map[string]string{
		"HTTPS_PROXY": endpoint,
		"HTTP_PROXY":  endpoint,
		"https_proxy": endpoint,
		"http_proxy":  endpoint,
		"NO_PROXY":    "127.0.0.1,localhost,::1",
	}
}
