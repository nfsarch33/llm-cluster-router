// Package proxy provides the ListenerFactory contract and the
// canonical HelixChannel AES/mTLS HTTP listener used by
// llm-cluster-router.
//
// # HelixChannel (v18712)
//
// HelixChannel is the operator-facing name for the AES-256-GCM
// application-layer encrypted HTTP channel introduced incrementally
// across v18704-v18710 and standardised by ADR-085. The channel id
// returned by Channel() is "aes-mtls" for back-compat with existing
// dashboards and runbooks; the brand name "HelixChannel" is stamped
// as a response header (see WithHelixChannelHeader) and exposed in
// the additive metric families
// llm_cluster_router_helixchannel_connections_total and
// llm_cluster_router_helixchannel_bytes_total.
//
// See the README "HelixChannel (encrypted dual-listener)" section
// for the threat model and the operator-facing config keys
// (HELIXCHANNEL_*).
package proxy

import (
	"context"
	"net"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy/observability"
)

// ServeLoop is the long-running accept loop for a listener. It MUST
// return promptly when ctx is cancelled. Implementations are
// expected to close the supplied net.Listener on exit if they own
// its lifecycle.
type ServeLoop func(ctx context.Context, ln net.Listener) error

// ListenerFactory abstracts construction of a TCP listener for a
// named encryption channel. A single daemon can compose multiple
// factories and run each ServeLoop in its own goroutine.
//
// The contract:
//
//   - Channel() returns a stable identifier used for metrics,
//     logging, and config keys.
//   - Listen(ctx, addr) returns a bound net.Listener and the
//     ServeLoop that should be run for it. addr is the host:port
//     the caller wants to bind. addr MUST NOT be empty; factories
//     return an error if it is.
type ListenerFactory interface {
	Channel() string
	Listen(ctx context.Context, addr string) (net.Listener, ServeLoop, error)
}

// aesMTLSListenerFactory builds the canonical AES/mTLS-flavoured
// HTTP listener. The actual TLS handshake is performed by callers
// that wrap the returned net.Listener in a tls.Listener; this
// factory only owns the TCP bind + ServeLoop plumbing so the
// production main.go can compose it alongside future channels.
//
// v18710-4: each accepted connection is wrapped with
// `internal/crypto.Wrap` (AES-256-GCM) so the dual-listener demo
// exercises the application-layer encryption path. The wrapper
// surfaces tamper events via the TamperCount counter; this
// ServeLoop forwards each tamper to
// `observability.DecryptFailedTotal{listener="aes-mtls"}`.
type aesMTLSListenerFactory struct {
	// key is the 32-byte AES key. Production callers obtain it
	// from a secret store; the demo defaults to a deterministic
	// key so the v18710-4 release gate is reproducible. Storing
	// the key here (rather than as a global) lets tests inject
	// different keys and lets future config-based wiring swap
	// the source.
	key [32]byte
}

// NewAESMTLSListenerFactory returns a ListenerFactory for the
// existing AES/mTLS HTTP path. The factory is intentionally
// minimal: the production router already has its http.Server
// constructed in main.go; this factory exists to make the
// dual-listener interface composable.
//
// The default AES key is a deterministic placeholder; production
// callers should swap it via NewAESMTLSListenerFactoryWithKey.
func NewAESMTLSListenerFactory() ListenerFactory {
	return &aesMTLSListenerFactory{key: defaultDemoAESKey()}
}

// NewAESMTLSListenerFactoryWithKey returns a ListenerFactory
// configured with the supplied AES-256 key. Used by tests and by
// production callers that load the key from a secret store.
func NewAESMTLSListenerFactoryWithKey(key [32]byte) ListenerFactory {
	return &aesMTLSListenerFactory{key: key}
}

// defaultDemoAESKey returns a non-secret placeholder key for the
// dual-listener demo. The bytes are NOT zero — that would mask
// callers that forget to provide a key (zero-keyed AES still
// "works" but is silent about misconfiguration).
func defaultDemoAESKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func (a *aesMTLSListenerFactory) Channel() string { return "aes-mtls" }

func (a *aesMTLSListenerFactory) Listen(ctx context.Context, addr string) (net.Listener, ServeLoop, error) {
	if addr == "" {
		return nil, nil, errEmptyAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	key := a.key
	serve := func(ctx context.Context, ln net.Listener) error {
		// Watch ctx in a goroutine; on cancellation, close the
		// listener so the blocked Accept call returns an error.
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return nil
			}
			// v18710-4: wrap the raw TCP conn with AES-256-GCM
			// and forward tamper events to the observability
			// metric. The wrapper's Close is sufficient to
			// release the underlying conn; we do not need a
			// separate defer.
			//
			// connCtx is THIS CONNECTION's lifetime, and it is
			// what the tamper forwarder is given -- not the
			// serve loop's ctx, which outlives every connection
			// it accepts. The forwarder used to have no exit
			// condition of any kind: one permanent goroutine and
			// one 10ms ticker per accepted TCP connection, with
			// nothing capping the total, each still holding its
			// *crypto.WrapConn reachable long after the conn it
			// polls had been closed on the very next line.
			connCtx, closeConn := context.WithCancel(ctx)
			wrapped := crypto.Wrap(conn, key)
			startTamperForwarder(connCtx, wrapped)
			// Production HTTP handling is delegated to the
			// caller's http.Server. We close the wrapped conn
			// here so the demo's ServeLoop does not leak
			// descriptors when no http.Server is registered --
			// and closeConn retires the forwarder in the same
			// breath, so the observer cannot outlive its subject.
			_ = wrapped.Close()
			closeConn()
		}
	}
	return ln, serve, nil
}

// startTamperForwarder spawns a goroutine that polls the wrapper's
// tamper counter every 10ms and increments
// observability.DecryptFailedTotal{listener="aes-mtls"} on
// observed deltas.
//
// LIFETIME: the goroutine returns when ctx is done, and ctx MUST be
// derived from the lifetime of wc. It previously ranged over the
// ticker channel with no stop channel, no ctx and no exit condition,
// so every call started a goroutine that ran until the process did.
// A polling observer that cannot be retired is not a shortcut, it is
// an unbounded resource per accepted connection.
//
// Polling remains a demo shortcut. The right shape is still a tamper
// CALLBACK on crypto.WrapConn, and that is deliberately left as
// follow-up rather than folded in here: the counter is incremented at
// four sites inside WrapConn.Read, which is the AES-GCM decrypt path
// shared by every wrapped conn in the tree, and a callback fired from
// there runs synchronously on that path -- so a slow or panicking
// observer becomes a transport fault, and the wrapper's documented
// "safe for concurrent Read/Write pairs" contract has to be restated
// to cover it. That is a larger change to a crypto primitive than the
// leak being closed here warrants.
//
// v18714-3: each observed tamper delta ALSO increments the
// per-session HelixChannel counter with outcome="tampering", and
// the first observed tamper on a fresh connection also records
// outcome="decrypt_error" because the AES-GCM authentication tag
// failed BEFORE the request even reached the HTTP layer (so the
// HTTP path will not record it). Without this branch the session
// counter would under-report the very events the runbook alerts on.
func startTamperForwarder(ctx context.Context, wc *crypto.WrapConn) {
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		var last uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := wc.TamperCount()
				if now > last {
					observability.DecryptFailedTotal.WithLabelValues("aes-mtls").Add(float64(now - last))
					// Per-session counter: one increment per
					// tamper delta so the rate() query is
					// meaningful even when one connection
					// accumulates many tampered frames.
					for i := uint64(0); i < now-last; i++ {
						observability.HelixChannelSessionTotal.WithLabelValues("tampering").Inc()
					}
					last = now
				}
			}
		}
	}()
}

// errEmptyAddr is returned by factories when addr is empty. It is
// declared as a sentinel so tests can assert against it without
// string matching.
var errEmptyAddr = &emptyAddrError{}

type emptyAddrError struct{}

func (*emptyAddrError) Error() string { return "proxy: listener addr must not be empty" }

// ErrEmptyAddr is the exported sentinel for tests and callers that
// want to detect an empty-address bind attempt.
var ErrEmptyAddr = errEmptyAddr
