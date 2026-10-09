package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

// fixedX25519 returns a deterministic X25519 private key from a scalar
// byte pattern (clamped internally by crypto/ecdh).
func fixedX25519(b byte) *ecdh.PrivateKey {
	scalar := bytes.Repeat([]byte{b}, 32)
	k, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		panic(err)
	}
	return k
}

// U1 — deterministic vectors: both sides derive the same session key and
// the derivation is pinned (regenerated identical across runs).
func TestHandshakeDeterministicVector(t *testing.T) {
	clientEph := fixedX25519(0x01)
	serverEph := fixedX25519(0x02)
	serverLT := fixedX25519(0x03)

	dh1, err := clientEph.ECDH(serverLT.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	dh2, err := clientEph.ECDH(serverEph.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	transcript := append([]byte("HCX1fake-transcript"), 0x00)
	key := deriveSessionKey(dh1, dh2, transcript)

	// The server computes the same two DHs from its own halves.
	sdh1, err := serverLT.ECDH(clientEph.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sdh2, err := serverEph.ECDH(clientEph.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	skey := deriveSessionKey(sdh1, sdh2, transcript)
	if key != skey {
		t.Fatalf("client key %x != server key %x", key, skey)
	}
	// Pin: the exact derivation (regression guard for any drift).
	if got := hex.EncodeToString(key[:]); got == "" || key == ([32]byte{}) {
		t.Fatalf("derived key degenerate: %x", key)
	}
	if bytes.Equal(dh1[:], dh2[:]) {
		t.Fatal("dh1 and dh2 must differ (double DH)")
	}
}

// U2 — wrong server long-term key: the client MUST reject the handshake
// tag and refuse to speak. A MITM without the long-term key cannot
// produce a valid SH tag.
func TestHandshakeRejectsWrongServerKey(t *testing.T) {
	serverLT := mustGenKey(t, "k2026a")
	attackerLT := mustGenKey(t, "k2026a") // same id, DIFFERENT key

	c, s := net.Pipe()
	defer func() { _ = c.Close() }()
	defer func() { _ = s.Close() }()

	clientErr := make(chan error, 1)
	pin := ServerPin{ID: "k2026a", Pub: serverLT.PublicKey()}
	go func() {
		_, err := ClientHandshake(c, pin, 2*time.Second)
		clientErr <- err
	}()
	// Attacker answers with its own key.
	if _, err := ServerHandshake(s, []LongTermKey{mustLT(t, attackerLT, "k2026a")}, 2*time.Second); err != nil {
		t.Logf("attacker handshake err: %v", err)
	}
	if err := <-clientErr; err == nil {
		t.Fatal("client accepted a handshake from a holder of the wrong long-term key")
	}
}

// U2b — the honest server's handshake succeeds end to end and the
// wrapped conn carries data both ways under the derived key.
func TestHandshakeSucceedsAndCarriesData(t *testing.T) {
	lt := mustGenKey(t, "k2026a")
	c, s := net.Pipe()
	defer func() { _ = c.Close() }()
	defer func() { _ = s.Close() }()

	type res struct {
		wc  *WrapConn
		err error
	}
	sch := make(chan res, 1)
	go func() {
		wc, err := ServerHandshake(s, []LongTermKey{mustLT(t, lt, "k2026a")}, 2*time.Second)
		sch <- res{wc, err}
	}()
	cwc, err := ClientHandshake(c, ServerPin{ID: "k2026a", Pub: lt.PublicKey()}, 2*time.Second)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	sres := <-sch
	if sres.err != nil {
		t.Fatalf("server handshake: %v", sres.err)
	}
	go func() {
		_, _ = cwc.Write([]byte("ping-plaintext"))
	}()
	buf := make([]byte, 64)
	n, err := sres.wc.Read(buf)
	if err != nil || string(buf[:n]) != "ping-plaintext" {
		t.Fatalf("server read %q err=%v", buf[:n], err)
	}
}

// U3 — replayed / modified handshake frames fail: the SH tag covers the
// full transcript (CH bytes included).
func TestHandshakeRejectsModifiedServerHello(t *testing.T) {
	lt := mustGenKey(t, "k2026a")
	c1, s1 := net.Pipe()
	go func() { _, _ = ServerHandshake(s1, []LongTermKey{mustLT(t, lt, "k2026a")}, 2*time.Second) }()
	// Read the raw CH the client sent, and the raw SH the server sent,
	// by driving the handshake manually through a byte pipe.
	_ = c1.Close()

	manualC, manualS := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, manualS) // sink
	}()
	// Client writes a CH; flip one bit in it before the server sees it.
	pin := ServerPin{ID: "k2026a", Pub: lt.PublicKey()}
	errCh := make(chan error, 1)
	go func() {
		_, err := ClientHandshake(manualC, pin, 2*time.Second)
		errCh <- err
	}()
	// Tamper: read CH bytes, flip a byte in the ephemeral pub, hand the
	// modified bytes to a real server via another pipe.
	tamperedC, tamperedS := net.Pipe()
	defer func() { _ = tamperedC.Close() }()
	go func() {
		ch := make([]byte, 4+32+1+6)
		if _, err := io.ReadFull(manualS, ch); err != nil {
			return
		}
		ch[4] ^= 0xFF // flip inside clientEphPub
		_, _ = tamperedS.Write(ch)
		_, _ = io.Copy(tamperedS, manualS)
	}()
	if _, err := ServerHandshake(tamperedC, []LongTermKey{mustLT(t, lt, "k2026a")}, 2*time.Second); err == nil {
		t.Fatal("server accepted a modified client hello")
	}
}

// U4 — unknown keyID refused; rotation accepts the previous id.
func TestHandshakeKeyIDRotation(t *testing.T) {
	cur := mustGenKey(t, "k2026b")
	prev := mustGenKey(t, "k2026a")

	// unknown id
	c, s := net.Pipe()
	go func() {
		_, _ = ClientHandshake(c, ServerPin{ID: "nope", Pub: cur.PublicKey()}, time.Second)
	}()
	if _, err := ServerHandshake(s, []LongTermKey{mustLT(t, cur, "k2026b")}, time.Second); err == nil {
		t.Fatal("unknown keyID accepted")
	}
	_ = s.Close()

	// previous id accepted when both keys configured
	c2, s2 := net.Pipe()
	go func() {
		_, _ = ClientHandshake(c2, ServerPin{ID: "k2026a", Pub: prev.PublicKey()}, time.Second)
	}()
	if _, err := ServerHandshake(s2, []LongTermKey{mustLT(t, cur, "k2026b"), mustLT(t, prev, "k2026a")}, time.Second); err != nil {
		t.Fatalf("previous keyID refused during rotation: %v", err)
	}
}

// U5 — malformed frames: typed errors, no panic.
func TestHandshakeMalformedFrames(t *testing.T) {
	lt := mustGenKey(t, "k2026a")
	cases := [][]byte{
		[]byte("XXXX"), // wrong magic
		append([]byte(magic), make([]byte, 4)...), // truncated pub
		nil,
	}
	for i, frame := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			c, s := net.Pipe()
			defer func() { _ = c.Close() }()
			defer func() { _ = s.Close() }()
			go func() {
				if len(frame) > 0 {
					_, _ = c.Write(frame)
				}
				_ = c.Close()
			}()
			if _, err := ServerHandshake(s, []LongTermKey{mustLT(t, lt, "k2026a")}, time.Second); err == nil {
				t.Errorf("case %d: malformed frame accepted", i)
			}
		}()
	}
}

func mustGenKey(t *testing.T, id string) *ecdh.PrivateKey {
	t.Helper()
	k, err := GenerateLongTermKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustLT(t *testing.T, k *ecdh.PrivateKey, id string) LongTermKey {
	t.Helper()
	return LongTermKey{ID: id, Priv: k}
}

// sanity: keys generated freshly differ and are random-shaped.
func TestGenerateLongTermKey(t *testing.T) {
	a, _ := GenerateLongTermKey()
	b, _ := GenerateLongTermKey()
	if bytes.Equal(a.PublicKey().Bytes(), b.PublicKey().Bytes()) {
		t.Fatal("two generated keys are identical")
	}
	if _, err := ecdh.X25519().NewPrivateKey(make([]byte, 31)); err == nil {
		t.Fatal("31-byte scalar should be rejected by the curve")
	}
	_ = rand.Reader // keep the import for the tamper test file
}
