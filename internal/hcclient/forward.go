// Package hcclient is the HelixChannel local forwarder: a plain-TCP
// listener on the personal device that relays every byte to the router
// over the ephemeral-key wrapped channel (with automatic fallback to the
// legacy static-key channel when the upstream does not negotiate it).
// The forwarder is protocol-blind by construction — REST, SSE, gRPC
// (HTTP/2) and MCP JSON-RPC traverse unchanged.
package hcclient

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// Options configures one forwarder run.
type Options struct {
	ListenAddr string // local plain listener, e.g. 127.0.0.1:8081
	Upstream   string // router address, host:port
	Pin        crypto.ServerPin
	// StaticKey is the fallback channel key (all-zero = no fallback).
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

// dialWrapped connects upstream and returns a wrapped conn: ephemeral
// first; on handshake failure, one retry on the static channel.
func dialWrapped(opts Options) (net.Conn, string, error) {
	raw, err := net.DialTimeout("tcp", opts.Upstream, opts.HandshakeTTL)
	if err != nil {
		return nil, "", fmt.Errorf("hcclient: dial %s: %w", opts.Upstream, err)
	}
	// A healthy upstream answers the handshake in milliseconds; bounding
	// the first attempt keeps the static fallback snappy when the peer
	// never speaks HCX1.
	ephTTL := opts.HandshakeTTL
	if ephTTL > 2*time.Second {
		ephTTL = 2 * time.Second
	}
	wc, err := crypto.ClientHandshake(raw, opts.Pin, ephTTL)
	if err == nil {
		return wc, "ephemeral", nil
	}
	_ = raw.Close()
	// Fallback: static channel (server sniff keeps the same port).
	raw2, err := net.DialTimeout("tcp", opts.Upstream, opts.HandshakeTTL)
	if err != nil {
		return nil, "", fmt.Errorf("hcclient: redial %s: %w", opts.Upstream, err)
	}
	sw := crypto.Wrap(raw2, opts.StaticKey)
	return sw, "static", nil
}
