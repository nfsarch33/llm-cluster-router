package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestCheckCDPReachable_PassWhen200 verifies the doctor CDP check
// reports "pass" when the /json/version endpoint returns 200.
func TestCheckCDPReachable_PassWhen200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"Browser":"Chrome/Test"}`)
	}))
	defer srv.Close()
	t.Setenv("HELIXCHANNEL_CDP_URL", srv.URL+"/json/version")
	t.Setenv("HELIXCHANNEL_CDP_SKIP", "")
	if got := checkCDPReachable(); got != "pass" {
		t.Errorf("expected pass; got %q", got)
	}
}

// TestCheckCDPReachable_FailWhen404 — a CDP endpoint that returns
// non-200 (Chrome not running with --remote-debugging-port) is
// "fail", not "error", so the doctor's `fail` count goes up.
func TestCheckCDPReachable_FailWhen404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("HELIXCHANNEL_CDP_URL", srv.URL+"/json/version")
	if got := checkCDPReachable(); got != "fail" {
		t.Errorf("expected fail on 404; got %q", got)
	}
}

// TestCheckCDPReachable_ErrorOnUnreachable asserts connection-refused
// returns "error" (not "fail") so doctor distinguishes "Chrome
// hung" from "wrong port".
func TestCheckCDPReachable_ErrorOnUnreachable(t *testing.T) {
	t.Setenv("HELIXCHANNEL_CDP_URL", "http://127.0.0.1:1/json/version")
	if got := checkCDPReachable(); got != "error" {
		t.Errorf("expected error on connection refused; got %q", got)
	}
}

// TestCheckCDPReachable_SkipWhenOptOut — HELIXCHANNEL_CDP_SKIP=1
// must short-circuit to skipped (offline / CI runs).
func TestCheckCDPReachable_SkipWhenOptOut(t *testing.T) {
	t.Setenv("HELIXCHANNEL_CDP_SKIP", "1")
	if got := checkCDPReachable(); got != "skipped" {
		t.Errorf("expected skipped when opt-out set; got %q", got)
	}
}

// TestRunVersion_DefaultJSON verifies the default output remains
// a JSON envelope so existing pipelines that pipe to jq keep
// working.
func TestRunVersion_DefaultJSON(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := runVersion([]string{})
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("runVersion: %v", err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	var env versionEnvelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("parse JSON: %v (raw=%q)", err, buf.String())
	}
	if env.HelixChannelVersion != proxyHelixChannelVersion {
		t.Errorf("helixchannel_version mismatch: got %q", env.HelixChannelVersion)
	}
	if env.GoVersion == "" {
		t.Errorf("go_version should be populated")
	}
}

// TestRunVersion_TextFlag — the v18716.3 plain-text path uses
// space-separated key=value pairs.
func TestRunVersion_TextFlag(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := runVersion([]string{"--text"})
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("runVersion --text: %v", err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	got := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(got, "helixchannel_version=") {
		t.Errorf("expected helixchannel_version= prefix; got %q", got)
	}
	if !strings.Contains(got, "go_version=") {
		t.Errorf("expected go_version= token; got %q", got)
	}
	if !strings.Contains(got, proxyHelixChannelVersion) {
		t.Errorf("expected canonical version in line; got %q", got)
	}
}

// TestVersionLine_FormatStable locks the plain-text format so
// downstream scripts (gstack / shell-leak) can rely on it.
func TestVersionLine_FormatStable(t *testing.T) {
	line := versionLine()
	if !strings.HasPrefix(line, "helixchannel_version=") {
		t.Errorf("format drift: %q", line)
	}
	// exactly one space between tokens (for grep-friendly parsing)
	if strings.Contains(line, "  ") {
		t.Errorf("double-space in version line: %q", line)
	}
}

// TestCheckCDPReachable_RespectsCustomURL — operator can override
// the canonical 127.0.0.1:9222 via HELIXCHANNEL_CDP_URL.
func TestCheckCDPReachable_RespectsCustomURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	t.Setenv("HELIXCHANNEL_CDP_URL", srv.URL)
	if got := checkCDPReachable(); got != "pass" {
		t.Errorf("expected pass on custom URL; got %q", got)
	}
}

// TestCheckCDPReachable_BoundedLatency guards against a hung
// CDP endpoint blocking the doctor run indefinitely.
func TestCheckCDPReachable_BoundedLatency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("HELIXCHANNEL_CDP_URL", srv.URL+"/json/version")
	start := time.Now()
	got := checkCDPReachable()
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Errorf("doctor CDP probe took %v; expected <3s", elapsed)
	}
	if got != "error" {
		t.Errorf("expected error on hung endpoint; got %q", got)
	}
}
