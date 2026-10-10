package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingSink captures everything drained, for the metadata-only tests.
type recordingSink struct {
	mu       sync.Mutex
	agents   []string
	durations []time.Duration
}

func (s *recordingSink) Inc(agent string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents = append(s.agents, agent)
}

func (s *recordingSink) Observe(agent string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durations = append(s.durations, d)
}

func (s *recordingSink) snapshot() ([]string, []time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.agents...), append([]time.Duration(nil), s.durations...)
}

// blockingSink never returns: the stalled-sink worst case.
type blockingSink struct{}

func (blockingSink) Inc(string)          { select {} }
func (blockingSink) Observe(string, time.Duration) { select {} }

// TestAttribution_NoHeader_NoLabel: the CONTROL. No identity header means no
// by-agent event at all — absence in the family is how the unattributed
// majority stays visible, so an "unknown" series would destroy that signal.
func TestAttribution_NoHeader_NoLabel(t *testing.T) {
	sink := &recordingSink{}
	a := NewAttribution(sink, 16)
	defer a.Close()

	h := http.Header{}
	h.Set("Authorization", "Bearer should-never-appear")
	h.Set("X-HLXN-Run-Id", "run-abc-123")
	if got := AgentFromHeader(h); got != "" {
		t.Fatalf("AgentFromHeader with no agent header = %q, want empty", got)
	}
	a.Record(AgentFromHeader(h), time.Now())
	agents, _ := sink.snapshot()
	if len(agents) != 0 {
		t.Fatalf("no-header request produced %d events, want 0", len(agents))
	}
}

// TestAttribution_NeverBlocksRelay: a stalled sink must not stall the relay.
// Record is called far past the buffer capacity against a sink whose Inc
// never returns; every Record call must still complete immediately.
func TestAttribution_NeverBlocksRelay(t *testing.T) {
	a := NewAttribution(blockingSink{}, 4)
	// Give the drainer time to wedge on the first event.
	a.Record("wedged-agent", time.Now())
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10000; i++ {
			a.Record("relay-agent", time.Now()) // must drop, never block
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked with a stalled sink: the relay path must never wait on attribution")
	}
	// Close drains what remains; with a wedged sink that would hang, so this
	// test intentionally leaks the drainer rather than calling Close.
}

// TestAttribution_RecordsNoBodyBytes: a canary planted in the body (and in
// every header other than the identity header) must never surface in any
// recorded value. The attribution API takes only the header set and a clock,
// so this pins that nothing richer can sneak in later.
func TestAttribution_RecordsNoBodyBytes(t *testing.T) {
	const canary = "CANARY-body-payload-must-never-be-recorded"
	sink := &recordingSink{}
	a := NewAttribution(sink, 16)
	defer a.Close()

	h := http.Header{}
	h.Set(AgentHeader, "helixon-fleet-node-a")
	h.Set("X-HLXN-Run-Id", canary)
	h.Set("X-Api-Key", canary)
	a.Record(AgentFromHeader(h), time.Now())

	deadline := time.Now().Add(2 * time.Second)
	for {
		agents, durs := sink.snapshot()
		if len(agents) >= 1 && len(durs) >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("attribution event never drained")
		}
		time.Sleep(time.Millisecond)
	}
	agents, _ := sink.snapshot()
	if agents[0] != "helixon-fleet-node-a" {
		t.Fatalf("agent label = %q, want the identity header value", agents[0])
	}
	for _, v := range agents {
		if strings.Contains(v, canary) {
			t.Fatalf("canary leaked into a recorded value: %q", v)
		}
	}
}

func TestAgentFromHeaderSanitises(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain id", "helixon-fleet-node-a", "helixon-fleet-node-a"},
		{"dots and underscores", "evospined.host_2", "evospined.host_2"},
		{"whitespace trimmed", "  agent-a  ", "agent-a"},
		{"too long", strings.Repeat("a", maxAgentLabel+1), "unknown"},
		{"weird charset", "agent\nwith\nnewlines", "unknown"},
		{"empty after trim", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(AgentHeader, tc.in)
			if got := AgentFromHeader(h); got != tc.want {
				t.Fatalf("AgentFromHeader(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestAttribution_CloseDrainsBuffer: Close is the ordered shutdown — events
// offered before Close are all delivered.
func TestAttribution_CloseDrainsBuffer(t *testing.T) {
	sink := &recordingSink{}
	a := NewAttribution(sink, 256)
	const n = 100
	for i := 0; i < n; i++ {
		a.Record(fmt.Sprintf("agent-%d", i), time.Now())
	}
	a.Close()
	agents, _ := sink.snapshot()
	if len(agents) != n {
		t.Fatalf("drained %d events, want %d", len(agents), n)
	}
}
