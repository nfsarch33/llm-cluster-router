package crypto

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// N1 — legacy client bytes replay byte-exact through the prefix conn:
// a static-wrap client against Negotiate gets a working channel.
func TestNegotiateLegacyReplay(t *testing.T) {
	staticKey := [32]byte{}
	for i := range staticKey {
		staticKey[i] = byte(i + 7)
	}
	keys := NoiseKeys{}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	legacy := Wrap(client, staticKey)
	go func() {
		_, _ = legacy.Write([]byte("legacy-first-bytes"))
	}()

	got, mode := Negotiate(server, keys, staticKey, false, time.Second)
	if mode != "static" {
		t.Fatalf("mode = %q, want static", mode)
	}
	buf := make([]byte, 32)
	n, err := got.Read(buf)
	if err != nil || string(buf[:n]) != "legacy-first-bytes" {
		t.Fatalf("legacy replay read %q err=%v", buf[:n], err)
	}
}

// N2 — HCX1 magic routes to the ephemeral path; garbage routes static.
func TestNegotiateRouting(t *testing.T) {
	staticKey := [32]byte{}
	keys := NoiseKeys{}

	// HCX2 magic routes to the noise path; full noise round trips are
	// covered by noisechannel_test.go
	c, s := net.Pipe()
	go func() {
		_, _ = c.Write([]byte(NoiseMagic))
	}()
	got, mode := Negotiate(s, keys, staticKey, false, time.Second)
	if mode != "noise" {
		t.Fatalf("HCX2 routed to %q, want noise", mode)
	}
	if got != nil {
		_ = got.Close()
	}
	_ = c.Close()

	// garbage first bytes → static
	c2, s2 := net.Pipe()
	go func() {
		_, _ = c2.Write([]byte("GET / HTTP/1.1\r\n"))
		_, _ = c2.Write(bytes.Repeat([]byte{0xAA}, 200))
	}()
	got, mode2 := Negotiate(s2, keys, staticKey, false, time.Second)
	if mode2 != "static" || got == nil {
		t.Fatalf("garbage routed to %q (conn nil: %v)", mode2, got == nil)
	}
	_ = c2.Close()
}

// negotiation with no ephemeral keys configured always goes static.
func TestNegotiateNoKeysAlwaysStatic(t *testing.T) {
	staticKey := [32]byte{}
	c, s := net.Pipe()
	go func() { _, _ = c.Write([]byte("HCX1")); _, _ = c.Write(bytes.Repeat([]byte{1}, 64)) }()
	got, mode := Negotiate(s, NoiseKeys{}, staticKey, false, time.Second)
	if mode != "static" || got == nil {
		t.Fatalf("no-keys mode = %q", mode)
	}
	_ = c.Close()
}
