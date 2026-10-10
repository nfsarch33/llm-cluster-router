// Copyright (c) 2026 jason. All rights reserved.
//
// check_keys_inprocess_test.go (v18760) covers the 1Password probe
// classification matrix using a scripted `op` stand-in on PATH, so the
// real exec + tmpfile + classification code runs without a live vault.
// Secret values must never appear in the envelope — asserted on every
// path.
package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// writeFakeOp installs a scripted `op` in its own dir and prepends that
// dir to PATH. Behaviour keys off the vault segment of the op:// ref.
func writeFakeOp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
# $1=read $2=op://vault/item/field $3=-o $4=outfile
case "$2" in
  op://okvault/*) printf 'secret-value' > "$4"; exit 0 ;;
  op://emptyvault/*) : > "$4"; exit 0 ;;
  op://missingvault/*) echo "\"x\" isn't an item" >&2; exit 1 ;;
  op://authvault/*) echo "not signed in, run op signin" >&2; exit 1 ;;
  *) echo "boom exploded" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(dir+"/op", []byte(script), 0o755); err != nil {
		t.Fatalf("write fake op: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestProbeOnePasswordKey_ClassificationMatrix(t *testing.T) {
	writeFakeOp(t)
	cases := []struct {
		name       string
		vault      string
		wantStatus string
		wantClass  string
		wantBytes  int
	}{
		{"pass", "okvault", "pass", "", len("secret-value")},
		{"empty secret", "emptyvault", "fail", "empty", 0},
		{"item missing", "missingvault", "fail", "not_found", 0},
		{"not signed in", "authvault", "fail", "op_unauth", 0},
		{"generic op failure", "othervault", "fail", "op_nonzero", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := probeOnePasswordKey(ConfigKeyRef{
				Name: tc.name, Vault: tc.vault, Item: "item-uuid", Field: "field-uuid",
			})
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (res=%+v)", res.Status, tc.wantStatus, res)
			}
			if res.ErrorClass != tc.wantClass {
				t.Fatalf("error_class = %q, want %q", res.ErrorClass, tc.wantClass)
			}
			if res.ByteLength != tc.wantBytes {
				t.Fatalf("byte_length = %d, want %d", res.ByteLength, tc.wantBytes)
			}
			raw, _ := json.Marshal(res)
			if strings.Contains(string(raw), "secret-value") {
				t.Fatal("secret bytes leaked into the result envelope")
			}
		})
	}
}

func TestRunCheckKeys_ConfigKeysPassVerdict(t *testing.T) {
	writeFakeOp(t)
	dir := t.TempDir()
	cfgPath := dir + "/keys.yml"
	cfg := `keys:
  - name: good
    vault: okvault
    item: item-a
    field: field-a
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := captureStdout(t, func() error {
		return runCheckKeys([]string{"--config", cfgPath, "--keys", "good"})
	})
	if err != nil {
		t.Fatalf("runCheckKeys = %v, want nil (pass verdict)", err)
	}
	var env checkKeysEnvelope
	if jErr := json.Unmarshal([]byte(out), &env); jErr != nil {
		t.Fatalf("output not JSON: %v (%q)", jErr, out)
	}
	if env.Verdict != "pass" || len(env.Keys) != 1 || env.Keys[0].Status != "pass" {
		t.Fatalf("envelope = %+v, want single passing key", env)
	}
}

func TestRunCheckKeys_FailingKeyYieldsFailVerdict(t *testing.T) {
	writeFakeOp(t)
	dir := t.TempDir()
	cfgPath := dir + "/keys.yml"
	cfg := `keys:
  - name: bad
    vault: othervault
    item: item-b
    field: field-b
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := captureStdout(t, func() error {
		return runCheckKeys([]string{"--config", cfgPath, "--keys", "bad"})
	})
	if !errors.Is(err, error(verdictFailErr)) {
		t.Fatalf("err = %v, want fail sentinel", err)
	}
	var env checkKeysEnvelope
	if jErr := json.Unmarshal([]byte(out), &env); jErr != nil {
		t.Fatalf("output not JSON: %v", jErr)
	}
	if env.Verdict != "fail" {
		t.Fatalf("verdict = %q, want fail", env.Verdict)
	}
}

func TestRunCheckKeys_BrokenConfigRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/broken.yml"
	if err := os.WriteFile(cfgPath, []byte("keys: ["), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := runCheckKeys([]string{"--config", cfgPath}); err == nil {
		t.Fatal("broken config = nil, want error")
	}
}

func TestRunCheckKeys_BadFlagRejected(t *testing.T) {
	if err := runCheckKeys([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag = nil, want parse error")
	}
}
