// Package hcclient is the HelixChannel local forwarder: a plain-TCP
// listener on the personal device that relays every byte to the router
// over the ephemeral-key wrapped channel (with automatic fallback to the
// legacy static-key channel when the upstream does not negotiate it).
// The forwarder is protocol-blind by construction — REST, SSE, gRPC
// (HTTP/2) and MCP JSON-RPC traverse unchanged.
package hcclient

import (
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// Options configures one forwarder run.
type Options struct {
	ListenAddr string // local plain listener, e.g. 127.0.0.1:8081
	Upstream   string // router address, host:port
	Pin        crypto.NoisePin
	// AllowStaticFallback enables the LEGACY static channel when the
	// Noise handshake cannot be completed. OFF by default (downgrade
	// resistance); every use logs WARN and increments
	// hcclient_static_fallback_total.
	AllowStaticFallback bool
	// StaticKey is the legacy channel key (used only when the flag is
	// set; all-zero = refuse even with the flag).
	StaticKey    [32]byte
	HandshakeTTL time.Duration
}

// Forward runs until the listener fails. Each accepted local conn opens
// one upstream conn, performs the ephemeral handshake (fallback:
// static), then pumps bytes both ways.
func Forward(opts Options) error {
	if opts.HandshakeTTL <= 0 {
		opts.HandshakeTTL = 5 * time.Second
	}
	ln, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("hcclient: listen %s: %w", opts.ListenAddr, err)
	}
	defer func() { _ = ln.Close() }()
	for {
		local, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("hcclient: accept: %w", err)
		}
		go func(local net.Conn) {
			defer func() { _ = local.Close() }()
			upstream, mode, err := dialWrapped(opts)
			if err != nil {
				return
			}
			defer func() { _ = upstream.Close() }()
			_ = mode
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(upstream, local); done <- struct{}{} }()
			go func() { _, _ = io.Copy(local, upstream); done <- struct{}{} }()
			<-done
		}(local)
	}
}

// dialWrapped connects upstream and returns a secured conn: the
// Noise_IKpsk2 channel (HCX2). The legacy static channel is used ONLY
// when AllowStaticFallback is set, and every such use is loudly
// recorded (WARN log + expvar counter) so downgrade attempts are
// visible in operations.
func dialWrapped(opts Options) (net.Conn, string, error) {
	raw, err := net.DialTimeout("tcp", opts.Upstream, opts.HandshakeTTL)
	if err != nil {
		return nil, "", fmt.Errorf("hcclient: dial %s: %w", opts.Upstream, err)
	}
	ephTTL := opts.HandshakeTTL
	if ephTTL <= 0 {
		ephTTL = 5 * time.Second
	}
	wc, err := crypto.NoiseClientHandshake(raw, opts.Pin, ephTTL)
	if err == nil {
		return wc, "noise", nil
	}
	_ = raw.Close()
	if !opts.AllowStaticFallback {
		return nil, "", fmt.Errorf("hcclient: noise handshake failed (%v) and static fallback is disabled (default; pass -allow-static-fallback during migration only)", err)
	}
	log.Printf("WARN hcclient: static fallback used — noise handshake failed: %v", err)
	staticFallbacks.Add(1)
	raw2, err := net.DialTimeout("tcp", opts.Upstream, opts.HandshakeTTL)
	if err != nil {
		return nil, "", fmt.Errorf("hcclient: redial %s: %w", opts.Upstream, err)
	}
	sw := crypto.Wrap(raw2, opts.StaticKey)
	return sw, "static", nil
}

// staticFallbacks counts downgrade-resistance exceptions: every use of
// the legacy static channel. Exposed as hcclient_static_fallback_total.
var staticFallbacks expvar.Int

func init() { expvar.Publish("hcclient_static_fallback_total", &staticFallbacks) }
