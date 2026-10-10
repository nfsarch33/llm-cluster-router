package proxy

import (
	"net/http"
	"strings"
	"time"
)

// Attribution is the v18846-5 metadata-only per-agent attribution recorder.
//
// It reads exactly one thing from the request: the X-Helixon-Agent identity
// header that helixon agents stamp on every model call (PR #139's
// IdentityDoer). Bodies, other headers, API keys, and the per-request
// X-HLXN-Run-Id are deliberately NOT recorded — the run id would be a
// cardinality bomb on a Prometheus label, and the published audit contract
// (README "no bodies, no headers, no keys" for audit records) stays true
// verbatim: these are aggregate counters, not audit records.
//
// The hot path NEVER blocks and never holds the relay semaphore: Record
// offers the event to a buffered channel and drops it if the buffer is full.
// A single drainer goroutine owns the sink, so even a stalled sink cannot
// back up the relay — that property is pinned by
// TestAttribution_NeverBlocksRelay.
type Attribution struct {
	events chan attributionEvent
	done   chan struct{}
	sink   AttributionSink
}

// AttributionSink receives drained attribution events. main.go wires the
// Prometheus implementation; tests wire fakes.
type AttributionSink interface {
	Inc(agent string)
	Observe(agent string, d time.Duration)
}

type attributionEvent struct {
	agent string
	dur   time.Duration
}

// AgentHeader is the identity header helixon's IdentityDoer stamps.
const AgentHeader = "X-Helixon-Agent"

// maxAgentLabel bounds the label value: agent ids are short, and a bound is
// the difference between a label and a log line someone posts into a metric.
const maxAgentLabel = 64

// NewAttribution starts the drainer goroutine. buffer is the event channel
// capacity; on overflow the event is dropped (counted nowhere — a drop is
// preferable to a relay stall, and the unattributed majority is already
// visible by absence in the by-agent family).
func NewAttribution(sink AttributionSink, buffer int) *Attribution {
	if buffer <= 0 {
		buffer = 1024
	}
	a := &Attribution{
		events: make(chan attributionEvent, buffer),
		done:   make(chan struct{}),
		sink:   sink,
	}
	go a.drain()
	return a
}

// Close stops the drainer. Safe to call once; events already in the buffer
// are drained first.
func (a *Attribution) Close() {
	close(a.events)
	<-a.done
}

func (a *Attribution) drain() {
	defer close(a.done)
	for ev := range a.events {
		a.sink.Inc(ev.agent)
		a.sink.Observe(ev.agent, ev.dur)
	}
}

// AgentFromHeader sanitises the identity header into a label value. An
// absent or empty header returns "" (the caller records nothing — the
// control pinned by TestAttribution_NoHeader_NoLabel). Values outside
// [A-Za-z0-9_.-] or past the length bound are clamped to "unknown" rather
// than mangled: a half-sanitised agent id is worse than none.
func AgentFromHeader(h http.Header) string {
	agent := strings.TrimSpace(h.Get(AgentHeader))
	if agent == "" {
		return ""
	}
	if len(agent) > maxAgentLabel {
		return "unknown"
	}
	for i := 0; i < len(agent); i++ {
		c := agent[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.':
		default:
			return "unknown"
		}
	}
	return agent
}

// Record offers one attribution event. It returns without blocking if the
// buffer is full. A nil Attribution (router assembled without newRouter) and
// a zero/empty agent are ignored.
func (a *Attribution) Record(agent string, start time.Time) {
	if a == nil || agent == "" {
		return
	}
	select {
	case a.events <- attributionEvent{agent: agent, dur: time.Since(start)}:
	default:
	}
}
