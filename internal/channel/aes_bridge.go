package channel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// AESBridge is the client-side forwarder for the AES leg. It listens as a plain
// HTTP server on a loopback address for an OpenAI-compatible client (Kilo Code
// being the motivating one) and forwards every request to the gateway's AES leg
// over TCP → TLS → AES-256-GCM, so the HTTP payload is AES-encrypted INSIDE the
// outer TLS. A TLS-terminating middlebox on the path — a corporate intercepting
// proxy — peels the outer TLS and still sees only AES ciphertext.
//
// The bridge holds no provider key and injects nothing. The client still sends
// the gateway token as an ordinary X-HLXN-Token header; the bridge forwards it
// verbatim to the leg, which enforces it exactly as the reverse-proxy leg does.
// The pre-shared AES key is what gates the leg cryptographically; the gateway
// token is what authorises spend.
type AESBridge struct {
	// Listen is the loopback HTTP bind the client points its base URL at,
	// e.g. "127.0.0.1:8788". It MUST be loopback: the hop from the client to
	// the bridge is un-encrypted, so it must never leave the machine.
	Listen string
	// Gateway is the AES leg's public address as host:port, e.g.
	// "helixchannel.example.com:8444".
	Gateway string
	// Key is the 32-byte pre-shared AES-256 key, identical to the gateway's.
	Key [32]byte
	// InsecureSkipVerify relaxes verification of the OUTER TLS hop to the
	// gateway only. Under a TLS-intercepting corporate proxy the outer
	// certificate the bridge sees is the proxy's, not the edge's; the inner
	// AES layer — keyed out of band — still protects the payload regardless,
	// which is the whole reason this leg exists. Leave false when the path is
	// not intercepted so the edge certificate is verified normally.
	InsecureSkipVerify bool
	// ReadHeaderTimeout bounds the loopback server's header read; defaults to
	// 10s when zero.
	ReadHeaderTimeout time.Duration
}

// gatewayHost returns the host portion of Gateway for TLS SNI/verification.
func (b *AESBridge) gatewayHost() string {
	if h, _, err := net.SplitHostPort(b.Gateway); err == nil {
		return h
	}
	return b.Gateway
}

// handler builds the reverse proxy that forwards to the AES leg. The transport
// dials the encrypted stream itself, so http.Transport speaks HTTP/1.1 over it.
func (b *AESBridge) handler() http.Handler {
	// Scheme is nominal: DialTLSContext supplies the real (TLS+AES) conn, so
	// http.Transport does not add its own TLS. Host carries SNI + vhost.
	target := &url.URL{Scheme: "https", Host: b.Gateway}
	rp := httputil.NewSingleHostReverseProxy(target)
	host := b.gatewayHost()
	rp.Transport = &http.Transport{
		ForceAttemptHTTP2: false, // HTTP/1.1 only; the wrapper frames a byte stream
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			raw, err := d.DialContext(ctx, "tcp", b.Gateway)
			if err != nil {
				return nil, fmt.Errorf("aes-bridge: dial gateway %s: %w", b.Gateway, err)
			}
			tlsConn := tls.Client(raw, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: b.InsecureSkipVerify, //nolint:gosec // outer hop only; inner AES protects the payload, see field doc
				MinVersion:         tls.VersionTLS12,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("aes-bridge: outer TLS handshake to %s: %w", b.Gateway, err)
			}
			// Inner AES: from here every byte http.Transport writes is
			// AES-sealed before it reaches the TLS record layer.
			return crypto.Wrap(tlsConn, b.Key), nil
		},
	}
	return rp
}

// ListenAndServe binds Listen and serves until ctx is cancelled. It refuses a
// non-loopback Listen: the client→bridge hop is unencrypted and must not be
// exposed off-host.
func (b *AESBridge) ListenAndServe(ctx context.Context) error {
	if err := requireLoopbackAddr(b.Listen); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", b.Listen)
	if err != nil {
		return fmt.Errorf("aes-bridge: listen %s: %w", b.Listen, err)
	}
	return b.Serve(ctx, ln)
}

// Serve runs the bridge on an already-bound listener until ctx is cancelled,
// taking ownership of ln. It refuses to serve on a non-loopback listener,
// judged from the socket ln actually bound, so the unencrypted client→bridge
// hop can never be reached from another host.
func (b *AESBridge) Serve(ctx context.Context, ln net.Listener) error {
	if err := requireLoopbackAddr(ln.Addr().String()); err != nil {
		_ = ln.Close()
		return err
	}
	rht := b.ReadHeaderTimeout
	if rht == 0 {
		rht = 10 * time.Second
	}
	srv := &http.Server{Handler: b.handler(), ReadHeaderTimeout: rht}
	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err == http.ErrServerClosed {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		return shutdownHTTPServer(srv, errCh)
	case err := <-errCh:
		return err
	}
}

// requireLoopbackAddr rejects an address that is not loopback, so the
// unencrypted client→bridge hop cannot be exposed to other hosts.
func requireLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("aes-bridge: listen %q must be host:port: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("aes-bridge: listen %q must be a loopback address (127.0.0.0/8, ::1, or localhost); the client→bridge hop is unencrypted", addr)
	}
	return nil
}
