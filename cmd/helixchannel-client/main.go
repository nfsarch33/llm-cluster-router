// helixchannel-client is the HelixChannel local forwarder (ephemeral-key
// spec v1): it listens on a plain local port and relays every byte to
// the llm-cluster-router upstream over the ephemeral-key wrapped channel,
// falling back to the legacy static-key channel automatically. Because
// the channel is a byte-stream AEAD, any protocol — REST, SSE, gRPC,
// MCP JSON-RPC — traverses unchanged.
//
// Typical:
//
//	helixchannel-client \
//	  -listen 127.0.0.1:8081 \
//	  -upstream router.internal:8443 \
//	  -server-pub <base64 X25519 long-term pub> \
//	  -key-id k2026a \
//	  -static-key <base64 32B fallback key, optional>
package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
	"github.com/nfsarch33/llm-cluster-router/internal/hcclient"
)

func main() {
	var (
		listen    = flag.String("listen", "127.0.0.1:8081", "local plain listener")
		upstream  = flag.String("upstream", "", "router host:port")
		serverPub = flag.String("server-pub", "", "base64 X25519 long-term public key (or HELIXCHANNEL_SERVER_PUB)")
		keyID     = flag.String("key-id", "", "server key id (or HELIXCHANNEL_KEY_ID)")
		staticKey = flag.String("static-key", "", "base64 32-byte fallback key (or HELIXCHANNEL_KEY)")
	)
	flag.Parse()
	env := func(name, v string) string {
		if v != "" {
			return v
		}
		return os.Getenv(name)
	}
	*serverPub = env("HELIXCHANNEL_SERVER_PUB", *serverPub)
	*keyID = env("HELIXCHANNEL_KEY_ID", *keyID)
	*staticKey = env("HELIXCHANNEL_KEY", *staticKey)

	if *upstream == "" || *serverPub == "" || *keyID == "" {
		fmt.Fprintln(os.Stderr, "helixchannel-client: -upstream, -server-pub and -key-id are required")
		flag.Usage()
		os.Exit(2)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(*serverPub)
	if err != nil {
		log.Fatalf("helixchannel-client: -server-pub base64: %v", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		log.Fatalf("helixchannel-client: server pub: %v", err)
	}
	var fallback [32]byte
	if *staticKey != "" {
		fb, err := base64.StdEncoding.DecodeString(*staticKey)
		if err != nil || len(fb) != 32 {
			log.Fatalf("helixchannel-client: -static-key must be base64 of 32 bytes")
		}
		copy(fallback[:], fb)
	}
	err = hcclient.Forward(hcclient.Options{
		ListenAddr:   *listen,
		Upstream:     *upstream,
		Pin:          crypto.ServerPin{ID: *keyID, Pub: pub},
		StaticKey:    fallback,
		HandshakeTTL: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("helixchannel-client: %v", err)
	}
}
