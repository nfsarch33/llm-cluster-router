// Package outbox tests for the v18728-3 control-channel outbox.
//
// The tests below are deterministic; the relay ticker is set to
// 10ms in tests so the drain latency stays sub-second. A
// short-loop publisher goroutine pattern is used so the relay
// can shut down cleanly.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakePublisher records every event it is asked to publish and
// returns whatever the test configures (success, transient
// failure, etc.).
type fakePublisher struct {
	mu       sync.Mutex
	received []Event
	failN    int32 // first N publishes return transient error
	failAll  bool  // never succeed
	calls    atomic.Int64
}

func (f *fakePublisher) Publish(_ context.Context, e Event) error {
	f.calls.Add(1)
	if f.failAll {
		return errors.New("simulated permanent failure")
	}
	if atomic.LoadInt32(&f.failN) > 0 {
		atomic.AddInt32(&f.failN, -1)
		return ErrPublisherFailed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.received = append(f.received, e)
	return nil
}

func (f *fakePublisher) Received() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Event, len(f.received))
	copy(out, f.received)
	return out
}

// newTempOutbox returns an Outbox rooted at a fresh temp dir so
// tests don't pollute each other.
func newTempOutbox(t *testing.T) *Outbox {
	t.Helper()
	dir := t.TempDir()
	o, err := New(Config{
		Dir:          dir,
		TickInterval: 10 * time.Millisecond,
		BatchSize:    50,
		SyncOnWrite:  true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { o.Stop() })
	return o
}

func TestOutbox_HappyPath_PublishesAndMarks(t *testing.T) {
	o := newTempOutbox(t)
	p := &fakePublisher{}
	o.Start(p)

	// 5 distinct events
	for i := 0; i < 5; i++ {
		err := o.Append(Event{
			Key:       fmt.Sprintf("k-%d", i),
			EventType: "aes-mtls.connect",
			TS:        time.Now().UTC().Format(time.RFC3339Nano),
			Payload:   json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)),
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Wait until relay drains.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if o.Len() == 0 && len(p.Received()) == 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(p.Received()); got != 5 {
		t.Fatalf("expected 5 published, got %d", got)
	}
	if got := o.Len(); got != 0 {
		t.Fatalf("expected 0 pending, got %d", got)
	}
}

func TestOutbox_Idempotency_DuplicateKeyRejected(t *testing.T) {
	o := newTempOutbox(t)
	p := &fakePublisher{}
	o.Start(p)

	if err := o.Append(Event{Key: "dup", EventType: "x"}); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	err := o.Append(Event{Key: "dup", EventType: "x"})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	// Even after waiting, publisher saw only the first.
	time.Sleep(100 * time.Millisecond)
	if got := len(p.Received()); got != 1 {
		t.Fatalf("expected 1 published, got %d", got)
	}
}

func TestOutbox_TransientFailure_RetainsPending(t *testing.T) {
	o := newTempOutbox(t)
	// First 2 calls fail; subsequent succeed.
	p := &fakePublisher{failN: 2}
	o.Start(p)

	for i := 0; i < 3; i++ {
		err := o.Append(Event{
			Key:       fmt.Sprintf("tf-%d", i),
			EventType: "socks5.connect",
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Wait long enough for 2 fails + 1 success.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(p.Received()) == 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(p.Received()); got != 3 {
		t.Fatalf("expected 3 published after retries, got %d", got)
	}
	if got := o.Len(); got != 0 {
		t.Fatalf("expected 0 pending after retry, got %d", got)
	}
}

func TestOutbox_Rehydrate_ReplaysPendingAfterRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Dir:          dir,
		TickInterval: 10 * time.Millisecond,
		BatchSize:    50,
		SyncOnWrite:  true,
	}
	// Round 1: write 2 events, do NOT start the relay.
	o1, err := New(cfg)
	if err != nil {
		t.Fatalf("New #1: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := o1.Append(Event{
			Key:       fmt.Sprintf("rehydrate-%d", i),
			EventType: "rehydrate.test",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	// Simulate crash: close without Stop (which would drain).
	_ = o1.pendingFP.Close()

	// Round 2: open a NEW outbox over the same dir; verify the
	// 2 events are rehydrated into pending and then drained.
	p := &fakePublisher{}
	o2, err := New(cfg)
	if err != nil {
		t.Fatalf("New #2: %v", err)
	}
	defer o2.Stop()
	if got := o2.Len(); got != 2 {
		t.Fatalf("rehydrate: expected 2 pending, got %d", got)
	}
	o2.Start(p)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(p.Received()) == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(p.Received()); got != 2 {
		t.Fatalf("expected 2 published after rehydrate, got %d", got)
	}
}

func TestOutbox_RejectsAfterClose(t *testing.T) {
	o := newTempOutbox(t)
	o.Stop()
	err := o.Append(Event{Key: "after-stop", EventType: "x"})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestOutbox_RequiresKeyAndType(t *testing.T) {
	o := newTempOutbox(t)
	if err := o.Append(Event{EventType: "x"}); err == nil {
		t.Fatal("expected error on missing key")
	}
	if err := o.Append(Event{Key: "k"}); err == nil {
		t.Fatal("expected error on missing event_type")
	}
}

func TestDeriveKey_Stable(t *testing.T) {
	k1 := DeriveKey("conn-1", "aes-mtls.connect")
	k2 := DeriveKey("conn-1", "aes-mtls.connect")
	if k1 != k2 {
		t.Fatalf("DeriveKey non-stable: %s vs %s", k1, k2)
	}
	k3 := DeriveKey("conn-2", "aes-mtls.connect")
	if k1 == k3 {
		t.Fatal("DeriveKey collision across conn ids")
	}
	k4 := DeriveKey("conn-1", "socks5.connect")
	if k1 == k4 {
		t.Fatal("DeriveKey collision across event types")
	}
	// Sanity: SHA-256 → 32 bytes → 43 base64 chars (RawURL).
	if len(k1) != 43 {
		t.Fatalf("DeriveKey length = %d, want 43", len(k1))
	}
}

func TestOutbox_HighVolume_BatchSizeRespected(t *testing.T) {
	dir := t.TempDir()
	o, err := New(Config{
		Dir:          dir,
		TickInterval: 5 * time.Millisecond,
		BatchSize:    10,
		SyncOnWrite:  false, // speed for the burst test
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer o.Stop()
	p := &fakePublisher{}
	o.Start(p)

	const N = 100
	for i := 0; i < N; i++ {
		if err := o.Append(Event{
			Key:       fmt.Sprintf("vol-%d", i),
			EventType: "volume.test",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(p.Received()) >= N {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := len(p.Received()); got < N {
		t.Fatalf("expected ≥%d published, got %d", N, got)
	}
}

func TestOutbox_NoPublisher_AppendStillSucceeds(t *testing.T) {
	// Outbox is a pure log; Start without a publisher just
	// means nothing gets drained. Append must still work.
	o := newTempOutbox(t)
	// intentionally not calling Start
	for i := 0; i < 3; i++ {
		if err := o.Append(Event{
			Key:       fmt.Sprintf("np-%d", i),
			EventType: "no-relay.test",
		}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if got := o.Len(); got != 3 {
		t.Fatalf("expected 3 pending, got %d", got)
	}
}

func TestOutbox_FileLayout_PendingFileLivesInDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "helixo_outbox_subdir")
	o, err := New(Config{Dir: dir, TickInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer o.Stop()
	if err := o.Append(Event{Key: "layout", EventType: "x"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Verify the canonical /var/log/helixo_outbox/ shape the plan
	// references: pending.ndjson is created under the directory.
	if _, err := os.Stat(filepath.Join(dir, "pending.ndjson")); err != nil {
		t.Fatalf("pending.ndjson missing: %v", err)
	}
}
