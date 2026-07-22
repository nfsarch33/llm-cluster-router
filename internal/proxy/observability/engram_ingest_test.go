// Package observability Engram ingest tests (v18716.5).
//
// Scope: the Engram ingest path emits a single Agentrace event
// every 30s with the canonical shape:
//
//	{ts, channel:"helixchannel", event:"engram.doctor",
//	 listener:"engram", status, embedder_queue_depth}
//
// The probe is what the v18709 Engram observation layer would have
// surfaced; the v18716.5 path routes the same signal through the
// HelixChannel Agentrace bridge so the brand-flavoured NDJSON
// carries the engram_doctor metric alongside tamper events. The
// underlying engram_doctor HTTP probe is out of scope for this
// file; we accept a status string + queue depth from the caller
// (typically the dual-listener-demo init path).
//
// TDD contract:
//
//  1. EngramIngester keeps an AgentraceBridge and a sample
//     function (or static values) plus a 30s tick interval.
//  2. NewEngramIngester returns a non-nil ingester on success.
//  3. RunOnce executes a single probe synchronously, writes one
//     engram.doctor event to the bridge, and returns nil. We do
//     NOT start the 30s ticker in tests (Ticker.Start would block
//     for 30s per tick).
//  4. The emitted NDJSON line carries status + queue_depth under
//     the canonical AgentraceEvent fields. The bridge composes a
//     typed payload struct; status lands in remote_addr and
//     queue_depth in bytes_in. We document that mapping inline.
package observability

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestEngramIngester_RunOnceEmitsEngramDoctorEvent asserts that a
// single RunOnce call writes one engram.doctor event to the bridge
// with status + embedder_queue_depth fields populated.
func TestEngramIngester_RunOnceEmitsEngramDoctorEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "engram.ndjson")
	b, err := NewAgentraceBridge(logPath)
	if err != nil {
		t.Fatalf("NewAgentraceBridge: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	ing := NewEngramIngester(b, EngramProbe{
		Status:             "ok",
		EmbedderQueueDepth: 7,
	})
	if err := ing.RunOnce(); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	var got map[string]any
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("line invalid JSON: %v", err)
	}
	if got["event"] != "engram.doctor" {
		t.Errorf("event = %v, want engram.doctor", got["event"])
	}
	if got["listener"] != "engram" {
		t.Errorf("listener = %v, want engram", got["listener"])
	}
	if got["channel"] != "helixchannel" {
		t.Errorf("channel = %v, want helixchannel", got["channel"])
	}
	// status is encoded under "remote_addr" because the bridge's
	// typed payload struct uses the v18709 AgentraceEvent field
	// set. The mapping is documented at AppendEngramDoctorEvent.
	if got["remote_addr"] != "ok" {
		t.Errorf("status (remote_addr) = %v, want ok", got["remote_addr"])
	}
	if got["bytes_in"] != float64(7) {
		t.Errorf("embedder_queue_depth (bytes_in) = %v, want 7", got["bytes_in"])
	}
}

// TestEngramIngester_RunOnceHandlesNilBridge asserts the ingester
// degrades gracefully when no bridge is supplied (typical for tests
// or during early init before the bridge is wired).
func TestEngramIngester_RunOnceHandlesNilBridge(t *testing.T) {
	ing := NewEngramIngester(nil, EngramProbe{Status: "ok"})
	if err := ing.RunOnce(); err != nil {
		t.Errorf("RunOnce with nil bridge: %v", err)
	}
}

// TestEngramIngester_StartStopDoesNotLeakGoroutines asserts that
// Start + Stop is a clean cycle and the goroutine count returns to
// baseline. We measure goroutines via runtime.NumGoroutine, which
// is a coarse signal but matches the v18704 / v18706 race-tested
// pattern.
func TestEngramIngester_StartStopDoesNotLeakGoroutines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "engram-startstop.ndjson")
	b, err := NewAgentraceBridge(logPath)
	if err != nil {
		t.Fatalf("NewAgentraceBridge: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	runtime.GC()
	before := runtime.NumGoroutine()

	ing := NewEngramIngester(b, EngramProbe{Status: "ok"})
	// Long interval so the ticker never fires inside the test
	// (which would race with the goroutine-count assertion).
	stop := ing.Start(1 << 20) // effectively never
	stop()

	// Allow the ticker goroutine to exit cleanly. 200ms is the
	// empirical minimum observed during race-test development.
	for i := 0; i < 100; i++ {
		if runtime.NumGoroutine() <= before {
			break
		}
		runtime.Gosched()
	}
	after := runtime.NumGoroutine()
	if after > before {
		t.Errorf("goroutine leak: before=%d after=%d", before, after)
	}
}
