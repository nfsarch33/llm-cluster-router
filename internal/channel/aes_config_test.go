package channel

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// baseAESConfig is a minimal, valid gateway config with one loopback-bound
// inject route, so validateAES can be exercised without tripping the other
// validators. Callers set c.AES and call c.Validate().
func baseAESConfig() *Config {
	return &Config{
		Listen: "127.0.0.1:14445",
		Routes: []Route{{
			Name: "mm", Prefix: "/mm/", Upstream: "https://api.example.com",
			Auth: AuthInject, KeyEnv: "MM_KEY", Enabled: true,
		}},
	}
}

func fullAES() AESConfig {
	return AESConfig{
		Enabled: true,
		Listen:  ":8444",
		KeyFile: "/run/secrets/aes.key",
		TLS:     TLSConfig{CertFile: "/etc/hc/tls.crt", KeyFile: "/etc/hc/tls.key"},
	}
}

func TestValidateAES(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(a *AESConfig)
		wantErr string // substring; "" means expect success
	}{
		{"disabled ignores everything", func(a *AESConfig) { *a = AESConfig{Enabled: false} }, ""},
		{"fully specified", func(a *AESConfig) {}, ""},
		{"no listen", func(a *AESConfig) { a.Listen = "" }, "listen is required"},
		{"listen equals proxy listen", func(a *AESConfig) { a.Listen = "127.0.0.1:14445" }, "must differ"},
		{"no tls", func(a *AESConfig) { a.TLS = TLSConfig{} }, "tls.cert_file and tls.key_file are required"},
		{"tls cert without key", func(a *AESConfig) { a.TLS.KeyFile = "" }, "must be set together"},
		{"tls key without cert", func(a *AESConfig) { a.TLS.CertFile = "" }, "must be set together"},
		{"no key source", func(a *AESConfig) { a.KeyFile = "" }, "one of key_env, key_file, key_ref"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseAESConfig()
			c.AES = fullAES()
			tt.mutate(&c.AES)
			err := c.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseAESKey(t *testing.T) {
	raw := "0123456789abcdef0123456789abcdef" // 32 bytes
	hexed := hex.EncodeToString([]byte(raw))  // 64 chars
	b64 := base64.StdEncoding.EncodeToString([]byte(raw))

	t.Run("raw 32 bytes", func(t *testing.T) {
		k, err := parseAESKey(raw)
		if err != nil || string(k[:]) != raw {
			t.Fatalf("raw: k=%q err=%v", k[:], err)
		}
	})
	t.Run("64-char hex", func(t *testing.T) {
		k, err := parseAESKey(hexed)
		if err != nil {
			t.Fatalf("hex: %v", err)
		}
		want, _ := hex.DecodeString(hexed)
		if string(k[:]) != string(want) {
			t.Fatalf("hex decoded mismatch")
		}
	})
	t.Run("base64 of 32 bytes", func(t *testing.T) {
		k, err := parseAESKey(b64)
		if err != nil || string(k[:]) != raw {
			t.Fatalf("b64: k=%q err=%v", k[:], err)
		}
	})
	t.Run("surrounding whitespace tolerated", func(t *testing.T) {
		if _, err := parseAESKey("  " + hexed + "\n"); err != nil {
			t.Fatalf("whitespace: %v", err)
		}
	})
	t.Run("wrong length rejected", func(t *testing.T) {
		if _, err := parseAESKey("too-short"); err == nil {
			t.Fatal("expected error for short key")
		}
	})
	t.Run("64 chars but not hex rejected", func(t *testing.T) {
		if _, err := parseAESKey(strings.Repeat("z", 64)); err == nil {
			t.Fatal("expected error for non-hex 64-char value")
		}
	})
}
