// Ephemeral-key handshake for the HelixChannel aes-mtls channel
// (spec: cursor-global-kb/backlogs/helixchannel-ephemeral-keys-spec.md).
//
// The handshake runs on the RAW conn BEFORE the AES-256-GCM Wrap is
// layered on, so the existing record format, tap, and tamper metric are
// unchanged and fully backward compatible. Shape (Noise-IK-flavoured,
// stdlib only):
//
//	CH = magic || clientEphPub[32] || keyIDLen[1] || keyID
//	SH = magic || serverEphPub[32] || tag[16]
//
//	DH1 = X25519(clientEph, serverLongTerm)  — authenticates the server
//	DH2 = X25519(clientEph, serverEph)       — forward secrecy
//	tag = HMAC-SHA256(HKDF(DH1,"HCX1 handshake tag"), transcript)[:16]
//	key = HKDF-SHA256(DH1||DH2, salt=SHA256(transcript),
//	                  info="HCX1 session key aes-256-gcm")
//
// A MITM without the long-term key cannot forge the tag; the client
// verifies it before any payload key exists, and every failure path
// closes the connection (fail closed, same posture as cert pinning).
package crypto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"net"
	"time"
)

const magic = "HCX1"

const (
	maxKeyIDLen = 64
	hsTimeout   = 5 * time.Second
)

// HandshakeError distinguishes handshake failures (negotiation, bad tag,
// malformed frames) from in-stream AEAD failures.
var HandshakeError = errors.New("crypto: ephemeral handshake failed")

// LongTermKey is one server long-term X25519 key with its key id.
type LongTermKey struct {
	ID   string
	Priv *ecdh.PrivateKey
}

// ServerPin is the client-side pinned view of the server: the long-term
// public key and its id (from config; changes only on rotation).
type ServerPin struct {
	ID  string
	Pub *ecdh.PublicKey
}

// GenerateLongTermKey creates a fresh X25519 keypair (id assigned by the
// caller at config time).
func GenerateLongTermKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// deriveSessionKey is the payload-key derivation, split out so the
// deterministic vector test can pin it.
func deriveSessionKey(dh1, dh2, transcript []byte) [32]byte {
	ikm := make([]byte, 0, len(dh1)+len(dh2))
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	salt := sha256.Sum256(transcript)
	var key [32]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt[:], []byte("HCX1 session key aes-256-gcm")), key[:]); err != nil {
		// 32 bytes from an HKDF stream never short-reads.
		panic(fmt.Sprintf("crypto: hkdf session key: %v", err))
	}
	return key
}

func handshakeTag(dh1, transcript []byte) []byte {
	early := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, dh1, nil, []byte("HCX1 handshake tag")), early); err != nil {
		panic(fmt.Sprintf("crypto: hkdf early key: %v", err))
	}
	mac := hmac.New(sha256.New, early)
	mac.Write(transcript)
	return mac.Sum(nil)[:16]
}

// ClientHandshake performs the ephemeral negotiation on conn and returns
// the conn wrapped with the derived session key.
func ClientHandshake(conn net.Conn, pin ServerPin, timeout time.Duration) (*WrapConn, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("%w: set deadline: %v", HandshakeError, err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if pin.ID == "" || pin.IDLen() > maxKeyIDLen {
		return nil, fmt.Errorf("%w: bad pin keyID", HandshakeError)
	}
	if pin.Pub == nil {
		return nil, fmt.Errorf("%w: pin has no public key", HandshakeError)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: eph keygen: %v", HandshakeError, err)
	}
	ch := make([]byte, 0, 4+32+1+len(pin.ID))
	ch = append(ch, magic...)
	ch = append(ch, eph.PublicKey().Bytes()...)
	ch = append(ch, byte(len(pin.ID)))
	ch = append(ch, []byte(pin.ID)...)
	if _, err := conn.Write(ch); err != nil {
		return nil, fmt.Errorf("%w: write CH: %v", HandshakeError, err)
	}

	sh := make([]byte, 4+32+16)
	if _, err := io.ReadFull(conn, sh); err != nil {
		return nil, fmt.Errorf("%w: read SH: %v", HandshakeError, err)
	}
	if string(sh[:4]) != magic {
		return nil, fmt.Errorf("%w: bad SH magic", HandshakeError)
	}
	serverEphPub := sh[4:36]
	tag := sh[36:52]

	serverEph, err := ecdh.X25519().NewPublicKey(serverEphPub)
	if err != nil {
		return nil, fmt.Errorf("%w: server eph pub: %v", HandshakeError, err)
	}
	dh1, err := eph.ECDH(pin.Pub)
	if err != nil {
		return nil, fmt.Errorf("%w: dh1: %v", HandshakeError, err)
	}
	dh2, err := eph.ECDH(serverEph)
	if err != nil {
		return nil, fmt.Errorf("%w: dh2: %v", HandshakeError, err)
	}
	transcript := append(append([]byte{}, ch...), sh[:36]...)
	want := handshakeTag(dh1, transcript)
	if subtle.ConstantTimeCompare(want, tag) != 1 {
		return nil, fmt.Errorf("%w: SH tag mismatch — server does not hold the pinned key", HandshakeError)
	}
	key := deriveSessionKey(dh1, dh2, transcript)
	return Wrap(conn, key), nil
}

// ServerHandshake performs the server side, selecting the long-term key
// by the client's keyID. On any failure the conn is closed (fail
// closed).
func ServerHandshake(conn net.Conn, keys []LongTermKey, timeout time.Duration) (*WrapConn, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("%w: set deadline: %v", HandshakeError, err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	head := make([]byte, 4+32+1)
	if _, err := io.ReadFull(conn, head); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: read CH: %v", HandshakeError, err)
	}
	if string(head[:4]) != magic {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: bad CH magic", HandshakeError)
	}
	clientEphPub := head[4:36]
	idLen := int(head[36])
	if idLen == 0 || idLen > maxKeyIDLen {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: keyID length %d", HandshakeError, idLen)
	}
	idBuf := make([]byte, idLen)
	if _, err := io.ReadFull(conn, idBuf); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: read keyID: %v", HandshakeError, err)
	}
	// Rebuild the exact CH transcript bytes.
	ch := append(append([]byte{}, head...), idBuf...)
	_ = binary.BigEndian // reserved for future flags

	var lt *LongTermKey
	for i := range keys {
		if keys[i].ID == string(idBuf) {
			lt = &keys[i]
			break
		}
	}
	if lt == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: unknown keyID", HandshakeError)
	}
	clientEph, err := ecdh.X25519().NewPublicKey(clientEphPub)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: client eph pub: %v", HandshakeError, err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: eph keygen: %v", HandshakeError, err)
	}
	dh1, err := lt.Priv.ECDH(clientEph)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: dh1: %v", HandshakeError, err)
	}
	dh2, err := eph.ECDH(clientEph)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: dh2: %v", HandshakeError, err)
	}
	sh := make([]byte, 0, 4+32+16)
	sh = append(sh, magic...)
	sh = append(sh, eph.PublicKey().Bytes()...)
	transcript := append(append([]byte{}, ch...), sh...)
	tag := handshakeTag(dh1, transcript)
	sh = append(sh, tag...)
	if _, err := conn.Write(sh); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: write SH: %v", HandshakeError, err)
	}
	key := deriveSessionKey(dh1, dh2, transcript)
	return Wrap(conn, key), nil
}

// IDLen keeps the pin validation in one place.
func (p ServerPin) IDLen() int { return len(p.ID) }
