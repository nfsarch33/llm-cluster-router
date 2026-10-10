package crypto

import "net"

// wrapListener is a net.Listener that AES-256-GCM wraps every
// connection it accepts with the pre-shared key, so an http.Server
// handed this listener speaks HTTP over the encrypted stream without
// any awareness of the wrapper. Stacked over a tls.Listener it yields
// application-layer AES *inside* the outer TLS record layer: a TLS
// terminator in the path (a corporate intercepting proxy, say) sees
// only AES-GCM ciphertext, never the plaintext HTTP request.
type wrapListener struct {
	net.Listener
	key [32]byte
}

// WrapListener returns a net.Listener that wraps each accepted
// connection with Wrap(conn, key). The key is pre-shared out of band
// and identical on the dialling peer, which wraps its own end with
// Wrap before writing. Accept errors pass through unwrapped; only a
// successfully accepted conn is wrapped.
func WrapListener(inner net.Listener, key [32]byte) net.Listener {
	return &wrapListener{Listener: inner, key: key}
}

// Accept accepts a connection from the inner listener and returns it
// wrapped. The returned conn's LocalAddr/RemoteAddr are the inner
// conn's (WrapConn embeds it), so http.Server sees the real peer
// address for logging and auth decisions.
func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Wrap(c, l.key), nil
}
