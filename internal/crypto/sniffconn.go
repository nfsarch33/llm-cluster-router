package crypto

import (
	"bytes"
	"net"
	"time"
)

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
// peek the first bytes; HCX1 magic → ephemeral handshake (server keys);
// anything else → legacy static-key wrap with the peeked bytes replayed.
// On any handshake failure the conn is closed (fail closed).
func Negotiate(conn net.Conn, keys []LongTermKey, staticKey [32]byte, timeout time.Duration) (net.Conn, string) {
	if timeout <= 0 {
		timeout = hsTimeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, "error"
	}
	peek := make([]byte, len(magic))
	n := 0
	for n < len(peek) {
		got, err := conn.Read(peek[n:])
		n += got
		if err != nil || got > 0 && n >= len(peek) {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if n < len(peek) {
		_ = conn.Close()
		return nil, "error"
	}
	if string(peek) == magic && len(keys) > 0 {
		// Handshake reads the CH AFTER the magic; hand it the peeked
		// magic back via a replay conn.
		wc, err := ServerHandshake(&prefixConn{Conn: conn, prefix: bytes.NewReader(peek)}, keys, timeout)
		if err != nil {
			return nil, "ephemeral"
		}
		return wc, "ephemeral"
	}
	// Legacy: replay every peeked byte, then the existing static wrap.
	pc := &prefixConn{Conn: conn, prefix: bytes.NewReader(peek[:n])}
	return Wrap(pc, staticKey), "static"
}
