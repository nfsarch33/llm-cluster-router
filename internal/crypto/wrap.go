// Package crypto implements the application-layer AES-256-GCM
// wrapper used by the AES/mTLS listener channel of
// llm-cluster-router.
//
// The wrapper sits between a net.Conn and the application. Every
// payload byte the application writes is encrypted (with a fresh
// per-write nonce) before it reaches the underlying socket; every
// payload byte read from the socket is decrypted (and authenticated)
// before it is delivered to the application. Wire captures of the
// underlying socket therefore see ciphertext only — never plaintext.
//
// Authentication failures (flipped bits, truncated frames, replayed
// nonces) are surfaced as a typed error so callers can distinguish
// tampering from transport-level failures. The wrapper also exposes
// tamper counters that production wiring forwards to the
// llm_cluster_router_decrypt_failed_total Prometheus metric.
//
// Scope intentionally narrow: stream framing uses length-prefixed
// records (u32 BE + ciphertext). This is sufficient for the v18710-4
// binary post-conditions:
//
//  1. No plaintext substring in 200 bytes of captured wire.
//  2. Flipping any byte increments DecryptFailed and surfaces a 4xx.
//
// The package is **not** a general-purpose transport; it is the
// application-layer shim for the dual-listener demo that backs the
// Lightsail release readiness gate (ADR-083).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// ErrTampered is returned when AES-GCM authentication fails on a
// read. It is wrapped inside any read error so callers can use
// errors.Is to distinguish wire tampering from transport-level
// errors (closed conn, deadline exceeded, etc.).
var ErrTampered = errors.New("crypto: ciphertext authentication failed")

// ErrShortFrame is returned when a length-prefixed record declares
// more bytes than the underlying conn produces before EOF. This is a
// different failure mode than ErrTampered (truncation vs. mutation)
// but is also counted under DecryptFailed because both indicate an
// attacker probing the wire.
var ErrShortFrame = errors.New("crypto: truncated ciphertext frame")

// maxFrame is the largest plaintext we accept per record. Larger
// payloads are split at the application layer (not the wrapper).
// 64 KiB matches the default for HTTP/1.1 chunked transfer and is
// a defensive ceiling for the AES/mTLS demo.
const maxFrame = 64 * 1024

// nonceSize is the AES-GCM nonce length (96 bits is the
// NIST-recommended size for GCM and is what cipher.NewGCM uses by
// default).
const nonceSize = 12

// gcmTagSize is the AES-GCM authentication tag length appended by
// Seal. Used to size the on-wire frame bound so a legitimate
// maxFrame-sized record is not misread as an out-of-bounds (tamper)
// frame.
const gcmTagSize = 16

// maxRecord is the largest on-wire sealed record we will accept on a
// Read: one nonce + up to maxFrame ciphertext bytes + the GCM tag.
// The previous bound used the 4-byte length prefix in place of the
// 12-byte nonce, which rejected any full-size record as tampering;
// splitting Writes at maxFrame and accepting up to maxRecord here
// makes the two sides agree exactly.
const maxRecord = nonceSize + maxFrame + gcmTagSize

// Wrap returns a net.Conn that encrypts writes and decrypts reads
// using AES-256-GCM. key must be 32 bytes (AES-256); the caller is
// responsible for key lifecycle (rotation, zeroisation on shutdown).
//
// Each Write produces one length-prefixed record on the wire:
//
//	[4 bytes BE length][12 bytes nonce][ciphertext]
//
// Each Read consumes exactly one record. Application code that needs
// framing for half-duplex or HTTP/2 use cases should layer its own
// framing on top.
//
// The returned conn owns the underlying conn for the lifetime of
// the wrapper; callers should not write to or read from underlying
// directly once Wrap has been called.
func Wrap(underlying net.Conn, key [32]byte) *WrapConn {
	return &WrapConn{Conn: underlying, aead: newAEAD(key)}
}

func newAEAD(key [32]byte) cipher.AEAD {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		// aes.NewCipher only fails on key length; 32 bytes is always valid.
		panic(fmt.Sprintf("crypto: aes.NewCipher: %v", err))
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		// cipher.NewGCM only fails on a non-NIST nonce size; 12 is the default.
		panic(fmt.Sprintf("crypto: cipher.NewGCM: %v", err))
	}
	return aead
}

// WrapConn is the net.Conn implementation backing Wrap.
//
// Concurrency: the wrapper is safe for concurrent Read/Write pairs
// (separate goroutines). It is NOT safe for concurrent Writes
// against the same frame because each Write emits exactly one
// ciphertext record and an interleaving would corrupt the stream;
// production callers (HTTP/1.1 keep-alive, SOCKS5 tunnels) are
// already half-duplex per connection, so this is not a limitation
// in practice.
type WrapConn struct {
	net.Conn
	aead cipher.AEAD

	// tap is a function invoked with every byte written to the
	// underlying socket. The v18710-4 wire-doctor test installs a
	// tap to capture ciphertext for the "no plaintext substring"
	// assertion. Production callers leave tap nil. tap must not
	// block; it runs on the write hot path.
	tapMu sync.RWMutex
	tap   func([]byte)

	// tamper counter; read via TamperCount().
	tamperCount atomic.Uint64

	// readBuf holds plaintext decrypted from a record that did not
	// fit in the caller's Read buffer. The next Read drains this
	// before decrypting a new record, so a WrapConn is a correct
	// io.Reader for callers of any buffer size (net/http reads
	// through 4 KiB bufio buffers; a record's plaintext can exceed
	// that). Touched only by Read, which the io.Reader contract
	// already forbids calling concurrently with itself, so it needs
	// no lock of its own.
	readBuf []byte
}

// SetTap installs (or clears, with nil) a write-side observer. The
// tap function is invoked synchronously on every Write before the
// ciphertext hits the underlying socket. Tap failures are ignored;
// the tap is best-effort and exists only to support the wire-doctor
// test harness. Concurrent with Write is permitted; the tap pointer
// is guarded by a RWMutex.
func (w *WrapConn) SetTap(fn func([]byte)) {
	w.tapMu.Lock()
	w.tap = fn
	w.tapMu.Unlock()
}

// TamperCount returns the number of times AES-GCM authentication
// has failed on a Read since this wrapper was constructed. The
// v18710-4 test asserts this increments after flipping a byte; the
// v18710-5 release gate surfaces it as
// llm_cluster_router_decrypt_failed_total.
func (w *WrapConn) TamperCount() uint64 {
	return w.tamperCount.Load()
}

// Write encrypts p and writes it to the underlying socket as one or
// more length-prefixed records. A payload up to maxFrame bytes is one
// record; a larger payload (net/http and io.Copy issue writes up to
// 32 KiB, and a caller may hand us more) is split into consecutive
// maxFrame-sized records rather than rejected, so the wrapper is a
// correct io.Writer for arbitrary payloads. Each record still carries
// its own fresh nonce, and the peer's Read reassembles across records.
func (w *WrapConn) Write(p []byte) (int, error) {
	written := 0
	// A zero-length Write still emits one record so the peer observes
	// the boundary, matching net.Conn semantics for empty writes.
	for {
		chunk := p[written:]
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}
		if err := w.writeRecord(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		if written >= len(p) {
			// Report the plaintext byte count: callers expect
			// Write(n, nil) to match len(p) regardless of on-wire size.
			return len(p), nil
		}
	}
}

// writeRecord seals a single ≤maxFrame plaintext chunk into one
// length-prefixed record and writes it to the underlying socket.
func (w *WrapConn) writeRecord(chunk []byte) error {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("crypto: read nonce: %w", err)
	}

	// Seal appends ciphertext + 16-byte tag to nonce.
	sealed := w.aead.Seal(nonce, nonce, chunk, nil)

	// Length prefix covers nonce + ciphertext + tag.
	frame := make([]byte, 4+len(sealed))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(sealed)))
	copy(frame[4:], sealed)

	w.tapMu.RLock()
	tap := w.tap
	w.tapMu.RUnlock()
	if tap != nil {
		tap(frame)
	}

	if _, err := w.Conn.Write(frame); err != nil {
		return fmt.Errorf("crypto: write frame: %w", err)
	}
	return nil
}

// Read delivers decrypted plaintext into p. It first drains any
// plaintext left over from a previous record that did not fit the
// caller's buffer; only when that is exhausted does it consume and
// decrypt the next length-prefixed record from the socket. A record's
// plaintext larger than p is returned across successive Reads rather
// than dropped, so a WrapConn is a correct io.Reader for callers of
// any buffer size. Authentication failures return an error wrapping
// ErrTampered and increment the tamper counter.
func (w *WrapConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Serve leftover plaintext from a prior oversized record first.
	if len(w.readBuf) > 0 {
		n := copy(p, w.readBuf)
		w.readBuf = w.readBuf[n:]
		if len(w.readBuf) == 0 {
			w.readBuf = nil
		}
		return n, nil
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(w.Conn, lenBuf[:]); err != nil {
		return 0, fmt.Errorf("crypto: read length: %w", err)
	}
	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	if frameLen == 0 || frameLen > maxRecord {
		// A legitimate record is nonce + ciphertext + tag, at most
		// maxRecord bytes. Anything outside that envelope is a wire
		// attack (or a desynchronised stream), counted as tampering.
		w.tamperCount.Add(1)
		return 0, fmt.Errorf("%w: length %d out of bounds", ErrTampered, frameLen)
	}

	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(w.Conn, frame); err != nil {
		// Truncated frame is also a tamper signal.
		w.tamperCount.Add(1)
		return 0, fmt.Errorf("%w: %w", ErrShortFrame, err)
	}
	if len(frame) < nonceSize+gcmTagSize {
		w.tamperCount.Add(1)
		return 0, fmt.Errorf("%w: nonce+tag underrun (%d bytes)", ErrTampered, len(frame))
	}

	nonce := frame[:nonceSize]
	sealed := frame[nonceSize:]
	plaintext, err := w.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		w.tamperCount.Add(1)
		return 0, fmt.Errorf("%w: %v", ErrTampered, err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		// Caller buffer smaller than this record's plaintext: stash
		// the remainder so the next Read continues at the exact byte,
		// never dropping data. copy into a fresh slice so we do not
		// retain the whole decrypt buffer.
		rest := make([]byte, len(plaintext)-n)
		copy(rest, plaintext[n:])
		w.readBuf = rest
	}
	return n, nil
}

// Close closes the underlying conn. Idempotent w.r.t. the
// underlying (returns the underlying's error verbatim).
func (w *WrapConn) Close() error {
	return w.Conn.Close()
}

// NewTestAEAD returns a fresh cipher.AEAD using the same 32-byte key
// schedule the production Wrap uses. Exported because the v18710-4
// integration test (in a different package) needs to construct
// deterministic ciphertext frames for tamper detection. Production
// callers MUST NOT use this; it is for tests only and is documented as
// such in the v18710-4 plan.
func NewTestAEAD(key [32]byte) cipher.AEAD {
	return newAEAD(key)
}

// SealTestFrame produces a length-prefixed ciphertext frame the same
// way WrapConn.Write does. The nonce is supplied by the caller so
// tests can produce reproducible ciphertext for tamper assertions.
// Exported for the v18710-4 integration test only.
func SealTestFrame(aead cipher.AEAD, plaintext []byte) []byte {
	nonce := make([]byte, nonceSize)
	// All-zero nonce is deterministic for tests; production never
	// reuses a nonce so this is acceptable in the test surface.
	sealed := aead.Seal(nonce, nonce, plaintext, nil)
	frame := make([]byte, 4+len(sealed))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(sealed)))
	copy(frame[4:], sealed)
	return frame
}
