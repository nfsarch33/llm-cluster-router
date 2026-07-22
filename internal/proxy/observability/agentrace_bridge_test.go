// Package observability Agentrace bridge tests (v18716.5).
//
// Scope: the bridge emits HelixChannel-flavoured Agentrace events to
// ~/logs/runx/agentrace-mcp.ndjson (or whatever path AGENTRACE_BRIDGE_PATH
// points at). Each event is one NDJSON line with the canonical
// AgentraceEvent shape plus a "channel" field set to "helixchannel"
// so DRL feature pipelines can filter without parsing the listener
// label.
//
// This is additive on top of the v18709 Agentrace appender: the
// bridge reuses NewAgentraceAppender + Append, never replaces them.
// Both paths coexist (the dual-listener-demo writes the per-accept
// events; the bridge writes the per-tamper and per-engram events).
//
// TDD contract:
//
//  1. NewAgentraceBridge returns an appender bound to the supplied
//     path with the helixchannel channel tag wired in.
//  2. AppendHelixChannelEvent writes a single NDJSON line with the
//     helixchannel channel tag; missing fields use the same defaults
//     as the underlying AgentraceEvent.
//  3. AppendTamperEvent increments DecryptFailedTotal in lock-step
//     with the NDJSON write so the Prometheus and Agentrace surfaces
//     stay consistent.
//  4. The bridge honours AGENTRACE_BRIDGE_PATH env override so tests
//     never write to the operator's production agentrace-mcp log.
package observability

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestAgentraceBridge_AppendHelixChannelEventWritesOneLine asserts
// the bridge writes a single NDJSON line with channel=helixchannel
// for a single HelixChannel emit call.
func TestAgentraceBridge_AppendHelixChannelEventWritesOneLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "agentrace-bridge.ndjson")
	b, err := NewAgentraceBridge(logPath)
	if err != nil {
		t.Fatalf("NewAgentraceBridge: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.AppendHelixChannelEvent(AgentraceEvent{
		TS:         time.Now().UTC().Format(time.RFC3339Nano),
		Event:      "decrypt.failed",
		Listener:   "aes-mtls",
		RemoteAddr: "127.0.0.1:51234",
		DurationMS: 42,
	}); err != nil {
		t.Fatalf("AppendHelixChannelEvent: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	var got map[string]any
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("line invalid JSON: %v", err)
	}
	if got["channel"] != "helixchannel" {
		t.Errorf("channel = %v, want helixchannel", got["channel"])
	}
	if got["event"] != "decrypt.failed" {
		t.Errorf("event = %v, want decrypt.failed", got["event"])
	}
	if got["listener"] != "aes-mtls" {
		t.Errorf("listener = %v, want aes-mtls", got["listener"])
	}
}

// TestAgentraceBridge_HonorsEnvOverride asserts that when
// AGENTRACE_BRIDGE_PATH is set, the bridge writes to that path
// instead of the operator's default ~/logs/runx/agentrace-mcp.ndjson.
// This is the test isolation guard; without it, every test run would
// append to the real production log.
func TestAgentraceBridge_HonorsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "override.ndjson")
	t.Setenv("AGENTRACE_BRIDGE_PATH", override)

	b, err := NewAgentraceBridge("")
	if err != nil {
		t.Fatalf("NewAgentraceBridge with empty + env override: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.AppendHelixChannelEvent(AgentraceEvent{
		TS:    time.Now().UTC().Format(time.RFC3339Nano),
		Event: "engram.doctor",
	}); err != nil {
		t.Fatalf("AppendHelixChannelEvent: %v", err)
	}

	if _, err := os.Stat(override); err != nil {
		t.Fatalf("override path not written: %v", err)
	}
}

// TestAgentraceBridge_AppendTamperEvent asserts the helper
// AppendTamperEvent writes the canonical decrypt.failed event with
// the supplied listener label.
func TestAgentraceBridge_AppendTamperEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tamper.ndjson")
	b, err := NewAgentraceBridge(logPath)
	if err != nil {
		t.Fatalf("NewAgentraceBridge: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.AppendTamperEvent("aes-mtls", "127.0.0.1:55555"); err != nil {
		t.Fatalf("AppendTamperEvent: %v", err)
	}

	data, _ := os.ReadFile(logPath)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	var got map[string]any
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("line invalid JSON: %v", err)
	}
	if got["channel"] != "helixchannel" {
		t.Errorf("channel = %v, want helixchannel", got["channel"])
	}
	if got["event"] != "decrypt.failed" {
		t.Errorf("event = %v, want decrypt.failed", got["event"])
	}
	if got["listener"] != "aes-mtls" {
		t.Errorf("listener = %v, want aes-mtls", got["listener"])
	}
}

// TestAgentraceBridge_AppendTamperEventIncrementsDecryptFailed asserts
// the cross-reference guarantee: every AppendTamperEvent call also
// increments DecryptFailedTotal{listener=...} so the Prometheus
// /metrics surface and the Agentrace NDJSON surface stay consistent.
// This is the contract DRL feature pipelines and Grafana alerts
// depend on.
func TestAgentraceBridge_AppendTamperEventIncrementsDecryptFailed(t *testing.T) {
	DecryptFailedTotal.Reset()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "mirror.ndjson")
	b, err := NewAgentraceBridge(logPath)
	if err != nil {
		t.Fatalf("NewAgentraceBridge: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	const n = 3
	for i := 0; i < n; i++ {
		if err := b.AppendTamperEvent("aes-mtls", "127.0.0.1:55555"); err != nil {
			t.Fatalf("AppendTamperEvent: %v", err)
		}
	}

	reg := prometheus.NewRegistry()
	if err := reg.Register(DecryptFailedTotal); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			t.Fatalf("register: %v", err)
		}
	}
	got := readCounterByListener(t, reg, "llm_cluster_router_decrypt_failed_total", "aes-mtls")
	if got != float64(n) {
		t.Errorf("DecryptFailedTotal{aes-mtls} = %v, want %d", got, n)
	}
}

// readCounterByListener reads a Counter value for the named metric +
// listener label from the registry. Returns 0 when the label is not
// present (Prometheus does not emit zero-valued time series).
func readCounterByListener(t *testing.T, reg *prometheus.Registry, name, listenerLabel string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "listener" && l.GetValue() == listenerLabel {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}