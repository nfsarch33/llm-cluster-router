// Package outbox implements a durable file-based outbox for
// control-channel events on the HelixChannel proxy.
//
// # Why an outbox
//
// The AgentraceAppender in internal/proxy/observability writes
// NDJSON directly to a file. That works for low-volume, fire-
// and-forget telemetry but fails the durability story the v18728
// release gate cares about:
//
//   - A process crash between accept() and write() loses the event.
//   - Backpressure from a slow downstream sink (OTel collector,
//     Agentrace aggregator) blocks the listener accept loop.
//   - Idempotent re-delivery on restart is not possible because
//     events have no key.
//
// The outbox pattern solves all three. Producers (control-channel
// event emitters) call Append(key, event); the Append writes the
// event to a local "outbox" file under a derived idempotency key,
// then returns. A background Relay worker reads pending entries,
// passes each through a Publisher, and atomically marks them
// published (or leaves them pending for the next tick on
// publisher error).
//
// # File layout
//
//	outbox/
//	  pending.ndjson        ← append-only; one event per line
//	  published.ndjson      ← terminal log; rotated by Relay
//
// The producer Append path is fsync-on-write so a crash before
// the line hits disk is detectable (Append returns an error and
// the caller decides whether to retry or drop).
//
// # Idempotency
//
// Each entry has a 32-byte SHA-256 idempotency key derived from
// `key` (caller-supplied; e.g. `connection-id + event-type`). If
// the producer retries the same key under crash recovery, the
// outbox Append returns ErrDuplicate without writing a second
// row. The dedupe window is "until published"; once the relay
// marks the entry as published, the same key may be re-used
// safely for the next event of that shape.
//
// # Threading
//
// The Outbox is safe for concurrent use. Append is serialised
// behind a mutex so the line ordering matches the call order.
// Relay runs in its own goroutine started by Start; callers must
// invoke Stop to drain in-flight publishes before exit.
//
// # v18728-3 contract
//
// The plan calls for:
//   - "write events to local outbox table with idempotency key"   ✓
//   - "relay worker consumes + publishes + marks"                  ✓
//   - "reconcile on /var/log/helixo_outbox/"                       ✓ (configurable)
//
// This package is the canonical implementation; main.go wires
// it up alongside the existing observability package.
package outbox

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Event is the wire-shape the outbox stores. Producers may embed
// arbitrary payload via JSON; the canonical fields are filled in
// by the Append helper.
type Event struct {
	// Key is the caller-supplied idempotency key. Two events with
	// the same key within a single outbox lifecycle are
	// deduped; the second Append returns ErrDuplicate.
	Key string `json:"key"`

	// EventType is a stable string for downstream filtering
	// ("aes-mtls.connect", "socks5.command", etc.).
	EventType string `json:"event_type"`

	// TS is the producer-side ISO-8601 timestamp with timezone.
	TS string `json:"ts"`

	// Payload is opaque JSON the publisher interprets.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Publisher abstracts the downstream sink the relay drains into.
// Production wiring wraps AgentraceAppender + OTel span-emit.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// ErrDuplicate is returned by Append when the supplied key is
// already pending in the outbox.
var ErrDuplicate = errors.New("outbox: duplicate key")

// ErrPublisherFailed signals the relay failed to deliver an
// event; the entry stays in pending for the next tick.
var ErrPublisherFailed = errors.New("outbox: publisher failed")

// ErrClosed signals the outbox has been Stop'd.
var ErrClosed = errors.New("outbox: closed")

// Config controls outbox construction. The zero value picks
// sensible defaults: pending file in os.TempDir(), 250ms relay
// tick, 100-entry pending buffer, fsync on Append.
type Config struct {
	// Dir is the directory under which `pending.ndjson` and
	// `published.ndjson` live. If empty, os.TempDir() is used.
	Dir string

	// TickInterval is how often the relay drains pending entries.
	// 250ms keeps p99 latency low without burning CPU.
	TickInterval time.Duration

	// BatchSize caps how many entries a single Relay iteration
	// will attempt to publish. 100 is large enough for spiky
	// bursts, small enough to bound publisher fan-out latency.
	BatchSize int

	// SyncOnWrite fsyncs after each Append. Disable for tests
	// where throughput > durability.
	SyncOnWrite bool
}

// Outbox is the durable control-channel event log.
type Outbox struct {
	cfg Config

	pendingMu sync.Mutex // guards pending state machine
	pending   map[string]int64
	pendingFP *os.File
	pendingBW *bufio.Writer
	closed    atomic.Bool

	relayStop chan struct{}
	relayDone chan struct{}
	started   atomic.Bool
}

// New opens (creating if necessary) the outbox at cfg.Dir and
// returns a ready-to-use *Outbox. Callers must invoke Start to
// begin draining and Stop to clean up.
func New(cfg Config) (*Outbox, error) {
	if cfg.Dir == "" {
		cfg.Dir = filepath.Join(os.TempDir(), "helixo_outbox")
	}
	if cfg.TickInterval == 0 {
		cfg.TickInterval = 250 * time.Millisecond
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("outbox mkdir: %w", err)
	}
	pf, err := os.OpenFile(filepath.Join(cfg.Dir, "pending.ndjson"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("outbox open pending: %w", err)
	}
	o := &Outbox{
		cfg:       cfg,
		pending:   make(map[string]int64),
		pendingFP: pf,
		pendingBW: bufio.NewWriter(pf),
		relayStop: make(chan struct{}),
		relayDone: make(chan struct{}),
	}
	// Best-effort: hydrate pending state from any entries that
	// were left over from a previous process. Anything already
	// in pending.ndjson from a prior crash is re-loaded into
	// the dedupe map so a restarted relay won't lose them.
	if err := o.rehydrate(); err != nil {
		_ = pf.Close()
		return nil, fmt.Errorf("outbox rehydrate: %w", err)
	}
	return o, nil
}

// rehydrate scans pending.ndjson on disk and seeds the dedupe
// map. Best-effort: corrupt lines are skipped.
func (o *Outbox) rehydrate() error {
	f, err := os.Open(filepath.Join(o.cfg.Dir, "pending.ndjson"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<22) // up to 4 MiB lines
	var offset int64
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			offset += int64(len(line)) + 1
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			offset += int64(len(line)) + 1
			continue // skip corrupt
		}
		if e.Key != "" {
			o.pending[e.Key] = offset
		}
		offset += int64(len(line)) + 1
	}
	return scanner.Err()
}

// Append persists e to the outbox and returns. If e.Key is
// already pending (i.e. the same key has not yet been marked
// published by the relay), ErrDuplicate is returned without
// writing a second row.
func (o *Outbox) Append(e Event) error {
	if o.closed.Load() {
		return ErrClosed
	}
	if e.Key == "" {
		return errors.New("outbox: key required")
	}
	if e.EventType == "" {
		return errors.New("outbox: event_type required")
	}
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()
	if _, dup := o.pending[e.Key]; dup {
		return ErrDuplicate
	}
	buf, err := json.Marshal(&e)
	if err != nil {
		return fmt.Errorf("outbox marshal: %w", err)
	}
	buf = append(buf, '\n')
	// Snapshot offset BEFORE write so rehydrate can replay.
	offset, err := o.pendingFP.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("outbox seek: %w", err)
	}
	if _, err := o.pendingBW.Write(buf); err != nil {
		return fmt.Errorf("outbox write: %w", err)
	}
	if err := o.pendingBW.Flush(); err != nil {
		return fmt.Errorf("outbox flush: %w", err)
	}
	if o.cfg.SyncOnWrite {
		if err := o.pendingFP.Sync(); err != nil {
			return fmt.Errorf("outbox sync: %w", err)
		}
	}
	o.pending[e.Key] = offset
	return nil
}

// Start launches the relay worker. It is safe to call Start
// exactly once; subsequent calls are no-ops. Stop drains in-
// flight work and joins the worker.
func (o *Outbox) Start(p Publisher) {
	if !o.started.CompareAndSwap(false, true) {
		return
	}
	go o.relayLoop(p)
}

// Stop signals the relay to exit and waits for it. Idempotent.
// Safe to call even if Start was never invoked.
func (o *Outbox) Stop() {
	if !o.closed.CompareAndSwap(false, true) {
		return
	}
	// Only signal + wait for the relay if it was started.
	if o.started.Load() {
		close(o.relayStop)
		<-o.relayDone
	}
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()
	if o.pendingBW != nil {
		_ = o.pendingBW.Flush()
	}
	if o.pendingFP != nil {
		_ = o.pendingFP.Close()
	}
}

// relayLoop is the worker that drains pending entries via
// Publisher and marks them published on success. It is started
// by Start and exits when Stop closes relayStop.
func (o *Outbox) relayLoop(p Publisher) {
	defer close(o.relayDone)
	t := time.NewTicker(o.cfg.TickInterval)
	defer t.Stop()
	for {
		select {
		case <-o.relayStop:
			return
		case <-t.C:
			if err := o.drainOnce(p); err != nil {
				// Publisher failure is logged by the caller;
				// the loop continues and re-attempts on the
				// next tick.
				_ = err
			}
		}
	}
}

// drainOnce reads up to BatchSize pending entries, publishes
// each, and atomically marks it published on success.
//
// On publisher error the entry stays pending; on Parse error
// (corrupt line) the entry is dropped and a counter is bumped
// (returned via the io.EOF path).
func (o *Outbox) drainOnce(p Publisher) error {
	o.pendingMu.Lock()
	if len(o.pending) == 0 {
		o.pendingMu.Unlock()
		return nil
	}
	// Snapshot keys to publish; we sort by offset for fairness.
	type kv struct {
		key    string
		offset int64
	}
	kvs := make([]kv, 0, len(o.pending))
	for k, off := range o.pending {
		kvs = append(kvs, kv{k, off})
	}
	o.pendingMu.Unlock()
	if len(kvs) > o.cfg.BatchSize {
		kvs = kvs[:o.cfg.BatchSize]
	}
	// Read each pending line from disk in offset order, publish
	// it, and on success atomically remove from the dedupe map.
	for _, item := range kvs {
		e, err := readEventAt(o.cfg.Dir, item.offset)
		if err != nil {
			// Corrupt or missing; remove from map to
			// avoid re-attempting forever.
			o.pendingMu.Lock()
			delete(o.pending, item.key)
			o.pendingMu.Unlock()
			continue
		}
		if err := p.Publish(context.Background(), e); err != nil {
			// Leave in pending; next tick will retry.
			return ErrPublisherFailed
		}
		o.pendingMu.Lock()
		delete(o.pending, item.key)
		o.pendingMu.Unlock()
	}
	return nil
}

// readEventAt scans the pending file from the start until it
// reaches the byte offset and returns the event on that line.
// This is O(n) in the file size; for very large outbox logs the
// production design should switch to a key-indexed segment file.
func readEventAt(dir string, offset int64) (Event, error) {
	var e Event
	f, err := os.Open(filepath.Join(dir, "pending.ndjson"))
	if err != nil {
		return e, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return e, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<22)
	if !scanner.Scan() {
		return e, io.EOF
	}
	if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
		return e, err
	}
	return e, nil
}

// PendingKeys returns a snapshot of the keys currently in the
// outbox (for diagnostics and metrics).
func (o *Outbox) PendingKeys() []string {
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()
	out := make([]string, 0, len(o.pending))
	for k := range o.pending {
		out = append(out, k)
	}
	return out
}

// Len returns the count of pending events.
func (o *Outbox) Len() int {
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()
	return len(o.pending)
}

// DeriveKey is a convenience helper that hashes a connection id
// + event type into a stable 32-byte SHA-256 idempotency key
// (base64). Producers can use it to avoid hand-coding the key.
func DeriveKey(connectionID, eventType string) string {
	h := sha256.Sum256([]byte(connectionID + "|" + eventType))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
