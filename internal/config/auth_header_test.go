// Package config -- v18774 auth_header admission tests.
//
// auth_header lets a node send its api_key in a named request header
// instead of "Authorization: Bearer <key>". The motivating upstream is
// an egress gateway that authenticates callers with a dedicated token
// header, where putting the token in Authorization is unsafe because
// passthrough routes forward Authorization verbatim to the provider.
//
// These tests pin the admission rules:
//   - a well-formed header name with a configured key is accepted;
//   - "Authorization" (any case) is refused -- Bearer is the default
//     path, and a config that spells it via auth_header is a footgun;
//   - header names are restricted to RFC 7230 token characters we
//     actually want (ALPHA / DIGIT / "-");
//   - auth_header without any usable key is refused, because the
//     header would silently never be sent and the operator would
//     believe gateway auth is on.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAuthHeaderConfig(t *testing.T, node string) string {
	t.Helper()
	yml := `
listen: ":0"
nodes:
` + node
	dir := t.TempDir()
	p := filepath.Join(dir, "router.yml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestLoadConfig_AuthHeaderAccepted(t *testing.T) {
	t.Setenv("TEST_GW_TOKEN", "gw-secret")
	p := writeAuthHeaderConfig(t, `
  - name: edge
    url: http://127.0.0.1:1/v1
    models: ["m"]
    api_key: "${TEST_GW_TOKEN}"
    auth_header: X-HLXN-Token
`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.Nodes[0].AuthHeader; got != "X-HLXN-Token" {
		t.Fatalf("AuthHeader = %q, want X-HLXN-Token", got)
	}
	if got := cfg.Nodes[0].APIKey; got != "gw-secret" {
		t.Fatalf("APIKey not env-expanded: %q", got)
	}
}

func TestLoadConfig_AuthHeaderRefusesAuthorization(t *testing.T) {
	for _, spelling := range []string{"Authorization", "authorization", "AUTHORIZATION"} {
		p := writeAuthHeaderConfig(t, `
  - name: edge
    url: http://127.0.0.1:1/v1
    models: ["m"]
    api_key: k
    auth_header: `+spelling+`
`)
		_, err := LoadConfig(p)
		if err == nil {
			t.Fatalf("auth_header: %s accepted; want refusal", spelling)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "authorization") {
			t.Fatalf("error should name Authorization, got: %v", err)
		}
	}
}

func TestLoadConfig_AuthHeaderRefusesNonTokenChars(t *testing.T) {
	for _, bad := range []string{"X HLXN", "X-HLXN:Token", "X-HLXN\tToken", "«header»"} {
		p := writeAuthHeaderConfig(t, `
  - name: edge
    url: http://127.0.0.1:1/v1
    models: ["m"]
    api_key: k
    auth_header: "`+bad+`"
`)
		if _, err := LoadConfig(p); err == nil {
			t.Fatalf("auth_header %q accepted; want refusal", bad)
		}
	}
}

func TestLoadConfig_AuthHeaderWithoutAnyKeyIsRefused(t *testing.T) {
	p := writeAuthHeaderConfig(t, `
  - name: edge
    url: http://127.0.0.1:1/v1
    models: ["m"]
    auth_header: X-HLXN-Token
`)
	_, err := LoadConfig(p)
	if err == nil {
		t.Fatal("auth_header with no api_key/api_keys accepted; want refusal")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Fatalf("error should explain the missing key, got: %v", err)
	}
}

func TestLoadConfig_AuthHeaderWithEmptyExpandedKeyIsRefused(t *testing.T) {
	// ${UNSET} expands to "" -- the header would never be sent. The
	// operator meant to enable gateway auth; tell them it is off.
	p := writeAuthHeaderConfig(t, `
  - name: edge
    url: http://127.0.0.1:1/v1
    models: ["m"]
    api_key: "${DEFINITELY_UNSET_VAR_v18774}"
    auth_header: X-HLXN-Token
`)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("auth_header with empty expanded key accepted; want refusal")
	}
}
