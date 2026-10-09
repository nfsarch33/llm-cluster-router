// Package crypto: Noise_IKpsk2 channel (Option A per
// docs/design/helixchannel-ephemeral-keys-threat-model.md).
//
// Wire: HCX2 magic (sniffed by Negotiate) || length-prefixed Noise
// handshake messages || length-prefixed AEAD records. After the
// handshake, each direction has its OWN CipherState (k1/k2 from
// Split()) with counter nonces — replay, reorder, drop and reflection
// all fail authentication. Server auth: IK (client pins the server
// static). Client auth: psk2 (per-tenant PSK). The tamper counter and
// tap semantics of the legacy WrapConn are preserved.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
)

// NoiseMagic marks the Noise channel during negotiation.
const NoiseMagic = "HCX2"

// HandshakeError distinguishes negotiation failures from record tamper.
var HandshakeError = errors.New("crypto: channel negotiation failed")

// ErrNoiseTampered marks an AEAD authentication failure on a Noise
// record (replay/reorder/mutation all land here).
var ErrNoiseTampered = errors.New("crypto: noise record authentication failed (tamper, replay or reorder)")

// NoiseKeys is the server-side channel configuration: the long-term
// static key and the per-tenant PSKs. The static private half never
// leaves the server; clients pin only StaticPub.
type NoiseKeys struct {
	StaticID string
	Static   *ecdh.PrivateKey
	PSKs     map[string][]byte // tenant id -> PSK
}

// NoisePin is the client-side configuration: pinned server static, the
// tenant id and its PSK.
type NoisePin struct {
	StaticID  string
	StaticPub *ecdh.PublicKey
	Tenant    string
	PSK       []byte
}

const noiseMaxFrame = 64 * 1024

func newNoiseSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
}

func writeFrame(w io.Writer, b []byte) error {
	f := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(f[:4], uint32(len(b)))
	copy(f[4:], b)
	_, err := w.Write(f)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > noiseMaxFrame {
		return nil, ErrNoiseTampered
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// NoiseClientHandshake dials the Noise channel on conn (the HCX2 magic
// has NOT been written yet — the client writes it as the negotiation
// marker) and returns the secure conn.
func NoiseClientHandshake(conn net.Conn, pin NoisePin, timeout time.Duration) (*NoiseConn, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	// magic + tenant id in the clear BEFORE m1: with psk2 the PSK only
	// enters the schedule at m2, so the multi-tenant server cannot
	// select the right PSK from m1 alone. Tenant NAMES are not secret
	// (the PSK is); this keeps the server deterministic.
	hello := append([]byte(NoiseMagic), byte(len(pin.Tenant)))
	hello = append(hello, pin.Tenant...)
	if _, err := conn.Write(hello); err != nil {
		return nil, fmt.Errorf("noise: write magic: %w", err)
	}
	staticPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           newNoiseSuite(),
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         noise.DHKey{Private: staticPriv.Bytes(), Public: staticPriv.PublicKey().Bytes()},
		PeerStatic:            pin.StaticPub.Bytes(),
		PresharedKey:          pin.PSK,
		PresharedKeyPlacement: 2, // psk2 (in message 2)
		Prologue:              []byte("helixchannel-hcx2-v1"),
	})
	if err != nil {
		return nil, fmt.Errorf("noise: client state: %w", err)
	}
	// -> e, es, s, ss
	msg, _, _, err := cs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noise: write m1: %w", err)
	}
	if err := writeFrame(conn, msg); err != nil {
		return nil, err
	}
	// <- e, ee, se, psk2 (carries the client-authenticating PSK)
	in, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read m2: %w", err)
	}
	_, c1, c2, err := cs.ReadMessage(nil, in)
	if err != nil {
		return nil, fmt.Errorf("noise: server authentication failed: %w", err)
	}
	// Initiator encrypts with the FIRST returned state.
	return newNoiseConn(conn, c1, c2), nil
}

// NoiseServerHandshake answers the Noise channel. The HCX2 magic has
// already been consumed by Negotiate.
func NoiseServerHandshake(conn net.Conn, keys NoiseKeys, timeout time.Duration) (*NoiseConn, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	// tenant selector: 1-byte length + id (cleartext, see client side)
	var tlen [1]byte
	if _, err := io.ReadFull(conn, tlen[:]); err != nil {
		return nil, fmt.Errorf("%w: read tenant id: %v", HandshakeError, err)
	}
	tenant := make([]byte, int(tlen[0]))
	if int(tlen[0]) > 0 {
		if _, err := io.ReadFull(conn, tenant); err != nil {
			return nil, fmt.Errorf("%w: read tenant id: %v", HandshakeError, err)
		}
	}
	psk, okT := keys.PSKs[string(tenant)]
	if !okT {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: unknown tenant %q", HandshakeError, string(tenant))
	}

	m1, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read m1: %w", err)
	}
	cs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           newNoiseSuite(),
		Pattern:               noise.HandshakeIK,
		Initiator:             false,
		StaticKeypair:         noise.DHKey{Private: keys.Static.Bytes(), Public: keys.Static.PublicKey().Bytes()},
		PresharedKey:          psk,
		PresharedKeyPlacement: 2, // psk2 (in message 2)
		Prologue:              []byte("helixchannel-hcx2-v1"),
	})
	if err != nil {
		return nil, fmt.Errorf("noise: server state: %w", err)
	}
	if _, _, _, err := cs.ReadMessage(nil, m1); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: client hello did not authenticate: %v", HandshakeError, err)
	}
	msg, sc1, sc2, err := cs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noise: write m2: %w", err)
	}
	if err := writeFrame(conn, msg); err != nil {
		return nil, err
	}
	// Responder SENDS with the second state and RECEIVES with the first
	// (Noise Split semantics: initiator tx=c1, rx=c2).
	return newNoiseConn(conn, sc2, sc1), nil
}

// NoiseConn is the post-handshake net.Conn: per-direction cipher states
// with counter nonces; the INITIATOR encrypts with c1, the responder
// with c2 (flynn Split semantics), so client and server pass their
// states in the right order at construction.
type NoiseConn struct {
	net.Conn
	w, r    *noise.CipherState
	tamper  atomic.Uint64
	tapMu   sync.RWMutex
	tap     func([]byte)
	writeMu sync.Mutex
}

func newNoiseConn(c net.Conn, w, r *noise.CipherState) *NoiseConn {
	return &NoiseConn{Conn: c, w: w, r: r}
}

// SetTap mirrors WrapConn.SetTap (write-side ciphertext observer).
func (n *NoiseConn) SetTap(fn func([]byte)) {
	n.tapMu.Lock()
	n.tap = fn
	n.tapMu.Unlock()
}

// TamperCount mirrors WrapConn.TamperCount.
func (n *NoiseConn) TamperCount() uint64 { return n.tamper.Load() }

func (n *NoiseConn) Write(p []byte) (int, error) {
	if len(p) > noiseMaxFrame {
		return 0, fmt.Errorf("crypto: plaintext %d exceeds maxFrame", len(p))
	}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	ct, err := n.w.Encrypt(nil, nil, p)
	if err != nil {
		return 0, fmt.Errorf("noise: encrypt: %w", err)
	}
	f := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(f[:4], uint32(len(ct)))
	copy(f[4:], ct)
	n.tapMu.RLock()
	tap := n.tap
	n.tapMu.RUnlock()
	if tap != nil {
		tap(f)
	}
	if _, err := n.Conn.Write(f); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (n *NoiseConn) Read(p []byte) (int, error) {
	ct, err := readFrame(n.Conn)
	if err != nil {
		if errors.Is(err, ErrNoiseTampered) {
			n.tamper.Add(1)
			return 0, err
		}
		return 0, err
	}
	pt, err := n.r.Decrypt(nil, nil, ct)
	if err != nil {
		n.tamper.Add(1)
		return 0, fmt.Errorf("%w: %v", ErrNoiseTampered, err)
	}
	return copy(p, pt), nil
}

// ClientStaticPub exposes nothing; helper for keygen tests.
func NoiseStaticKeypair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// hashBytes is a tiny helper for key-id derivation (first 8 hex of
// sha256 of the public key) — used by keygen; kept here so cmd stays
// thin.
func SHA256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
