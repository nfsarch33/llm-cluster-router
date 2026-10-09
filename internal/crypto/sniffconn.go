package crypto

import (
	"bytes"
	"net"
	"time"
)

const hsTimeout = 5 * time.Second

// prefixConn replays already-read bytes before passing reads through to
// the underlying conn — needed because the server must peek the first
// bytes to decide between the ephemeral handshake and the legacy static
// path, without losing them.
type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if p.prefix != nil {
		n, err := p.prefix.Read(b)
		if n > 0 {
			return n, nil
		}
		if err != nil && n == 0 {
			p.prefix = nil // drained
		}
	}
	return p.Conn.Read(b)
}

// Negotiate is the server-side entry point for the dual-mode listener:
// peek the first bytes; HCX2 magic → Noise_IKpsk2 channel (ephemeral
// keys, per-direction counters, PSK client auth); anything else → legacy
// static-key wrap with the peeked bytes replayed — UNLESS
// requireEphemeral is set, in which case non-HCX2 conns are refused
// (downgrade resistance: an attacker stripping the marker cannot force
// the static mode after cutover). Handshake failure closes the conn.
func Negotiate(conn net.Conn, keys NoiseKeys, staticKey [32]byte, requireEphemeral bool, timeout time.Duration) (net.Conn, string) {
	if timeout <= 0 {
		timeout = hsTimeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, "error"
	}
	peek := make([]byte, len(NoiseMagic))
	n := 0
	for n < len(peek) {
		got, err := conn.Read(peek[n:])
		n += got
		if err != nil || (got > 0 && n >= len(peek)) {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if n < len(peek) {
		_ = conn.Close()
		return nil, "error"
	}
	if string(peek) == NoiseMagic {
		// the magic is consumed; m1 framing starts fresh — no replay
		wc, err := NoiseServerHandshake(conn, keys, timeout)
		if err != nil {
			return nil, "noise"
		}
		return wc, "noise"
	}
	if requireEphemeral {
		_ = conn.Close()
		return nil, "refused-static"
	}
	pc := &prefixConn{Conn: conn, prefix: bytes.NewReader(peek[:n])}
	return Wrap(pc, staticKey), "static"
}
