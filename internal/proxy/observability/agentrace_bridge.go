// Package observability Agentrace bridge (v18716.5).
//
// Scope: emit HelixChannel-flavoured Agentrace events to the
// operator's persistent NDJSON log at
// ~/logs/runx/agentrace-mcp.ndjson. The bridge is additive on top of
// the v18709 AgentraceAppender: the dual-listener-demo keeps writing
// per-accept events via the existing NewAgentraceAppender path; the
// bridge writes a parallel stream of HelixChannel-flavoured events
// (tamper, engram doctor, sentrux gate) so DRL feature pipelines
// have a single search target for channel-specific signal.
//
// Why a second appender rather than extending the existing one?
// Existing consumers of agentrace-router.ndjson expect the v18709
// shape; the helixchannel channel tag is a new field that would
// fail unmarshal in older AgentraceEvent consumers. Splitting the
// stream keeps the v18709 contract intact and lets new consumers
// (DRL pipelines added in v18716+) opt into the channel tag.
//
// Default path: AGENTRACE_BRIDGE_PATH env, falling back to
// ~/.logs/runx/agentrace-mcp.ndjson (operator's persistent log).
// Tests override via the path argument or AGENTRACE_BRIDGE_PATH.
package observability

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// defaultAgentraceBridgePath is the operator-facing default. It is
// computed at process start to honour $HOME overrides (e.g. when the
// binary runs under `runx env personal-shell` with HOME remapped).
var defaultAgentraceBridgePath = func() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/agentrace-mcp.ndjson"
	}
	return filepath.Join(home, "logs", "runx", "agentrace-mcp.ndjson")
}()

// channelHelixchannel is the constant channel tag stamped on every
// Agentrace event this bridge emits. The literal value matches the
// brand name "HelixChannel" (lowercased for tag consistency with
// existing "socks5" / "aes-mtls" listener labels).
const channelHelixchannel = "helixchannel"

// AgentraceBridge is a thin wrapper over AgentraceAppender that
// stamps the helixchannel channel tag on every event and provides
// high-level helpers (AppendTamperEvent, AppendEngramDoctorEvent)
// that double-write to the Prometheus DecryptFailedTotal counter
// when the event represents a tamper on the wire.
type AgentraceBridge struct {
	app *AgentraceAppender
}

// NewAgentraceBridge opens the bridge for append. If path is empty,
// the bridge honours the AGENTRACE_BRIDGE_PATH env override, falling
// back to the operator's default ~/logs/runx/agentrace-mcp.ndjson.
//
// Callers must Close() in defer.
func NewAgentraceBridge(path string) (*AgentraceBridge, error) {
	if path == "" {
		path = os.Getenv("AGENTRACE_BRIDGE_PATH")
	}
	if path == "" {
		path = defaultAgentraceBridgePath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("agentrace-bridge: mkdir: %w", err)
	}
	app, err := NewAgentraceAppender(path)
	if err != nil {
		return nil, err
	}
	return &AgentraceBridge{app: app}, nil
}

// AppendHelixChannelEvent writes one NDJSON line containing the
// supplied AgentraceEvent plus a top-level "channel":"helixchannel"
// tag. The bridge does not mutate the caller-supplied event; it
// composes a parallel JSON object so older AgentraceEvent consumers
// continue to parse the line successfully (they simply ignore the
// extra "channel" field).
func (b *AgentraceBridge) AppendHelixChannelEvent(ev AgentraceEvent) error {
	if b == nil || b.app == nil {
		return fmt.Errorf("agentrace-bridge: appender closed")
	}
	if ev.TS == "" {
		ev.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// Compose a parallel struct so older consumers see the
	// v18709 AgentraceEvent shape AND new consumers see the
	// channel tag. JSON encoding is identical to a hand-rolled
	// map[string]any; the struct approach keeps the field set
	// documented at compile time.
	type enriched struct {
		Channel    string `json:"channel"`
		TS         string `json:"ts"`
		Event      string `json:"event"`
		Listener   string `json:"listener"`
		RemoteAddr string `json:"remote_addr,omitempty"`
		BytesIn    int64  `json:"bytes_in,omitempty"`
		BytesOut   int64  `json:"bytes_out,omitempty"`
		DurationMS int64  `json:"duration_ms,omitempty"`
	}
	payload := enriched{
		Channel:    channelHelixchannel,
		TS:         ev.TS,
		Event:      ev.Event,
		Listener:   ev.Listener,
		RemoteAddr: ev.RemoteAddr,
		BytesIn:    ev.BytesIn,
		BytesOut:   ev.BytesOut,
		DurationMS: ev.DurationMS,
	}
	// Serialise via the underlying appender's mu by re-using
	// Append with a custom key. We cannot pass a typed payload
	// through Append (it takes AgentraceEvent), so we marshal +
	// write through a small shim: serialize ourselves to bytes,
	// then write the line directly under the appender's mutex
	// via a small escape hatch (encodedWrite below).
	line, err := json.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("agentrace-bridge: marshal: %w", err)
	}
	return b.app.appendRaw(line)
}

// AppendTamperEvent writes the canonical "decrypt.failed" event
// for a tampering observation on the supplied listener and bumps
// the Prometheus DecryptFailedTotal counter in lock-step. The two
// surfaces stay consistent so Grafana queries and DRL pipelines
// observing the same tamper see the same count.
func (b *AgentraceBridge) AppendTamperEvent(listener, remoteAddr string) error {
	if err := b.AppendHelixChannelEvent(AgentraceEvent{
		Event:      "decrypt.failed",
		Listener:   listener,
		RemoteAddr: remoteAddr,
	}); err != nil {
		return err
	}
	// Cross-reference to Prometheus so the operator-facing
	// dashboard and the NDJSON consumer never disagree.
	DecryptFailedTotal.WithLabelValues(listener).Inc()
	return nil
}

// AppendEngramDoctorEvent writes a periodic engram_doctor metric
// snapshot so the bridge's NDJSON carries the embedder health
// signal even when engram_doctor's own log path is rotated out.
// The status string is encoded under "remote_addr" because the
// bridge's typed payload struct reuses the v18709 AgentraceEvent
// field set; the mapping is documented at the call site
// (see EngramIngester.RunOnce).
func (b *AgentraceBridge) AppendEngramDoctorEvent(status string, embedderQueueDepth int) error {
	return b.AppendHelixChannelEvent(AgentraceEvent{
		Event:      "engram.doctor",
		Listener:   "engram",
		RemoteAddr: status,
		BytesIn:    int64(embedderQueueDepth),
	})
}

// Close flushes and closes the underlying file. Idempotent.
func (b *AgentraceBridge) Close() error {
	if b == nil || b.app == nil {
		return nil
	}
	return b.app.Close()
}
