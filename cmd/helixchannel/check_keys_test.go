package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestDedupeKeys_PreservesFirstOccurrence asserts that the
// dedupe helper keeps the first row when multiple names point
// at the same secret.
func TestDedupeKeys_PreservesFirstOccurrence(t *testing.T) {
	in := []ConfigKeyRef{
		{Name: "minimax", Vault: "HelixonSafe", Item: "rip1", Field: "tag1"},
		{Name: "minimax-aliased", Vault: "HelixonSafe", Item: "rip1", Field: "tag1"},
		{Name: "grafana", Vault: "HelixonSafe", Item: "rip2", Field: "tag2"},
	}
	out := dedupeKeys(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 unique, got %d: %+v", len(out), out)
	}
	if out[0].Name != "minimax" {
		t.Errorf("expected first occurrence kept; got %q", out[0].Name)
	}
	if out[1].Name != "grafana" {
		t.Errorf("expected grafana; got %q", out[1].Name)
	}
}

// TestFilterKeysByName_Subset returns the named subset only.
func TestFilterKeysByName_Subset(t *testing.T) {
	in := []ConfigKeyRef{
		{Name: "minimax"},
		{Name: "grafana"},
		{Name: "aws_lightsail"},
	}
	out := filterKeysByName(in, "minimax,grafana")
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].Name != "minimax" || out[1].Name != "grafana" {
		t.Errorf("ordering or names wrong: %+v", out)
	}
}

// TestFilterKeysByName_EmptyReturnsInput is the identity case.
func TestFilterKeysByName_EmptyReturnsInput(t *testing.T) {
	in := []ConfigKeyRef{{Name: "a"}, {Name: "b"}}
	out := filterKeysByName(in, "")
	if len(out) != 2 {
		t.Errorf("empty subset should pass through; got %d", len(out))
	}
}

// TestFilterKeysByName_UnknownNamesAreSilentlySkipped —
// unknown names produce a shorter envelope, not a fail.
func TestFilterKeysByName_UnknownNamesAreSilentlySkipped(t *testing.T) {
	in := []ConfigKeyRef{{Name: "a"}, {Name: "b"}}
	out := filterKeysByName(in, "nope")
	if len(out) != 0 {
		t.Errorf("unknown names should produce empty output; got %+v", out)
	}
}

// TestProbeOnePasswordKey_IncompleteRefFails — a config row with
// missing vault/item/field returns fail with a clear class.
func TestProbeOnePasswordKey_IncompleteRefFails(t *testing.T) {
	res := probeOnePasswordKey(ConfigKeyRef{Name: "broken"})
	if res.Status != "fail" {
		t.Errorf("expected fail; got %q", res.Status)
	}
	if res.ErrorClass != "incomplete_ref" {
		t.Errorf("expected incomplete_ref; got %q", res.ErrorClass)
	}
}

// TestProbeOnePasswordKey_OpMissingSkips — when `op` is not on
// PATH (the CI default), the probe returns skip with op_missing
// rather than fail. Operators install op and re-run.
func TestProbeOnePasswordKey_OpMissingSkips(t *testing.T) {
	// We force PATH to be empty so `op` cannot be found regardless
	// of host env. The skip path is reached when exec.LookPath
	// returns ENOENT.
	t.Setenv("PATH", "")
	res := probeOnePasswordKey(ConfigKeyRef{
		Name: "minimax", Vault: "HelixonSafe", Item: "x", Field: "y",
	})
	if res.Status != "skip" {
		t.Errorf("expected skip when op missing; got %q (err=%q)", res.Status, res.ErrorClass)
	}
	if res.ErrorClass != "op_missing" {
		t.Errorf("expected op_missing; got %q", res.ErrorClass)
	}
	if res.ByteLength != 0 {
		t.Errorf("skip path must NOT report a byte length; got %d", res.ByteLength)
	}
}

// TestRunCheckKeys_NoArgsEmitsSkipWhenOpMissing — the no-flag
// path with no op installed returns exit 2 (skip). This is
// the most important contract for CI: the subcommand is
// idempotent and friendly to environments without 1Password.
func TestRunCheckKeys_NoArgsEmitsSkipWhenOpMissing(t *testing.T) {
	t.Setenv("PATH", "")
	// Capture stdout to parse the JSON envelope.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := runCheckKeys([]string{})
	w.Close()
	os.Stdout = old
	if err == nil {
		t.Fatalf("expected non-nil error from runCheckKeys with no op")
	}
	if !strings.Contains(err.Error(), "verdict=skip") {
		t.Errorf("expected verdict=skip error; got %q", err.Error())
	}
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	env := checkKeysEnvelope{}
	if err := json.Unmarshal(buf[:n], &env); err != nil {
		t.Fatalf("parse envelope: %v (raw=%q)", err, string(buf[:n]))
	}
	if env.Verdict != "skip" {
		t.Errorf("expected envelope verdict=skip; got %q", env.Verdict)
	}
	if len(env.Keys) == 0 {
		t.Errorf("expected defaultCheckKeys to be probed; got 0")
	}
}

// TestRunCheckKeys_SubsetFilter wires the --keys subset and
// asserts the envelope only contains the named key. Path is
// forced empty so the run returns skip (op_missing) without
// touching 1Password.
func TestRunCheckKeys_SubsetFilter(t *testing.T) {
	t.Setenv("PATH", "")
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := runCheckKeys([]string{"--keys", "minimax"})
	w.Close()
	os.Stdout = old
	if err == nil {
		t.Fatalf("expected skip error")
	}
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	env := checkKeysEnvelope{}
	if err := json.Unmarshal(buf[:n], &env); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if len(env.Keys) != 1 {
		t.Fatalf("expected 1 key (minimax only); got %d", len(env.Keys))
	}
	if env.Keys[0].Name != "minimax" {
		t.Errorf("expected minimax; got %q", env.Keys[0].Name)
	}
}

// TestRunCheckKeys_UnknownSubsetReturnsSkipEmpty asserts that
// --keys=nope (no matches) returns a SKIP envelope with zero
// rows. This is the documented "operator-friendly" behaviour:
// unknown names produce a SHORTER envelope, not a fail.
func TestRunCheckKeys_UnknownSubsetReturnsSkipEmpty(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := runCheckKeys([]string{"--keys", "nope,also-not-here"})
	w.Close()
	os.Stdout = old
	if err == nil {
		t.Fatalf("expected skip error (no rows)")
	}
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	env := checkKeysEnvelope{}
	if err := json.Unmarshal(buf[:n], &env); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if env.Verdict != "skip" {
		t.Errorf("expected verdict=skip for empty subset; got %q", env.Verdict)
	}
	if len(env.Keys) != 0 {
		t.Errorf("expected 0 rows; got %d", len(env.Keys))
	}
}
