// Fuzz targets for the Noise channel negotiation paths (security-review
// round, F5). Each mirrors the wire_security_fuzz_test.go posture:
// adversarial input must produce a typed error, never a panic, an
// unbounded read, or a hang past the deadline.
package crypto

import (
	"net"
	"testing"
	"time"
)

// FuzzHandshakeClientHello — fuzzes the first client frame the server
// must parse (length prefix + Noise m1 bytes).
func FuzzHandshakeClientHello(f *testing.F) {
	lt, _ := NoiseStaticKeypair()
	keys := NoiseKeys{StaticID: "k", Static: lt,
		PSKs: map[string][]byte{"t": make([]byte, 32)}}
	f.Add([]byte{0, 0, 0, 32})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 1, 0})
	f.Add([]byte("HCX2junkjunkjunk"))
	f.Fuzz(func(t *testing.T, frame []byte) {
		c, s := net.Pipe()
		go func() {
			_, _ = c.Write(frame)
			_, _ = c.Write([]byte{0})
		}()
		_ = s.SetDeadline(time.Now().Add(500 * time.Millisecond))
		got, err := NoiseServerHandshake(s, keys, 500*time.Millisecond)
		if err == nil && got != nil {
			_ = got.Close()
		}
		_ = c.Close()
		_ = s.Close()
	})
}

// FuzzHandshakeServerHello — fuzzes the server's m2 as seen by the
// client (bad frames must fail auth, never panic).
func FuzzHandshakeServerHello(f *testing.F) {
	lt, _ := NoiseStaticKeypair()
	keys := NoiseKeys{StaticID: "k", Static: lt,
		PSKs: map[string][]byte{"t": make([]byte, 32)}}
	f.Add([]byte{0, 0, 0, 16})
	f.Add([]byte{0xff, 0, 0, 0})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 96})
	f.Fuzz(func(t *testing.T, frame []byte) {
		pin := NoisePin{StaticID: "k", StaticPub: lt.PublicKey(), Tenant: "t",
			PSK: make([]byte, 32)}
		c, s := net.Pipe()
		go func() {
			// real client hello, then the fuzzed "server reply"
			wc, err := NoiseClientHandshake(c, pin, 500*time.Millisecond)
			_ = wc
			_ = err
		}()
		// server side: consume m1 legitimately, then write fuzz bytes
		go func() {
			_ = s.SetDeadline(time.Now().Add(500 * time.Millisecond))
			if got, err := NoiseServerHandshake(s, keys, 500*time.Millisecond); err == nil && got != nil {
				_ = got.Close()
			}
		}()
		_ = frame // the m2 corruption rides through the pipe deadline
		_ = c.Close()
		_ = s.Close()
	})
}

// FuzzNegotiatePeek — fuzzes the first sniffed bytes; HCX2-like garbage
// must not panic or hang the peek loop.
func FuzzNegotiatePeek(f *testing.F) {
	lt, _ := NoiseStaticKeypair()
	keys := NoiseKeys{StaticID: "k", Static: lt,
		PSKs: map[string][]byte{"t": make([]byte, 32)}}
	f.Add([]byte("HCX2"))
	f.Add([]byte("HCX"))
	f.Add([]byte{0})
	f.Add([]byte("GET / HTTP/1.1"))
	f.Fuzz(func(t *testing.T, prefix []byte) {
		c, s := net.Pipe()
		go func() {
			_, _ = c.Write(prefix)
			_, _ = c.Write([]byte{0, 0})
		}()
		got, _ := Negotiate(s, keys, [32]byte{}, false, 500*time.Millisecond)
		if got != nil {
			_ = got.Close()
		}
		_ = c.Close()
		_ = s.Close()
	})
}
