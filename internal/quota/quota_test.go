package quota

import (
	"regexp"
	"strings"
	"testing"
)

func TestDetector_NilOnEmptyPattern(t *testing.T) {
	d := New("", "https://hooks.slack.test/x", "#alerts", nil)
	if d != nil {
		t.Fatalf("New with empty pattern should return nil, got %v", d)
	}
}

func TestDetector_NilOnInvalidRegex(t *testing.T) {
	d := New("[unclosed", "https://hooks.slack.test/x", "#alerts", nil)
	if d != nil {
		t.Fatalf("New with invalid regex should return nil, got %v", d)
	}
}

func TestDetector_Matches(t *testing.T) {
	d := New("quota_exceeded", "", "", nil)
	if d == nil {
		t.Fatalf("New returned nil")
	}
	if !d.Matches([]byte("status: quota_exceeded")) {
		t.Fatalf("expected match")
	}
	if d.Matches([]byte("OK")) {
		t.Fatalf("expected no match")
	}
}

func TestDetector_NilSafeMatches(t *testing.T) {
	var d *Detector
	if d.Matches([]byte("anything")) {
		t.Fatalf("nil detector should never match")
	}
}

func TestDetector_NilSafeNotify(t *testing.T) {
	var d *Detector
	// Should not panic.
	d.Notify("m", "n", "v", []byte("body"))
}

func TestDetector_PostSlack_BuildText(t *testing.T) {
	d := &Detector{channel: "#alerts"}
	body := []byte(`{"error":{"code":"quota_exceeded","message":"limit hit"}}`)
	text := d.buildSlackText("gpt-x", "c1", "openai", body)
	if !strings.Contains(text, "gpt-x") {
		t.Fatalf("text missing model: %s", text)
	}
	if !strings.Contains(text, "c1") {
		t.Fatalf("text missing node: %s", text)
	}
	if !strings.Contains(text, "openai") {
		t.Fatalf("text missing vendor: %s", text)
	}
	if !strings.Contains(text, "quota_exceeded") {
		t.Fatalf("text missing body preview: %s", text)
	}
}

func TestDetector_BuildText_Truncates(t *testing.T) {
	d := &Detector{}
	body := make([]byte, 500)
	for i := range body {
		body[i] = 'A'
	}
	text := d.buildSlackText("m", "n", "v", body)
	// 200 chars of body + the framing overhead
	if len(text) > 400 {
		t.Fatalf("text too long: %d", len(text))
	}
}

func TestDetector_ChannelOverride(t *testing.T) {
	d := &Detector{channel: "#custom"}
	if d.channel != "#custom" {
		t.Fatalf("channel not stored")
	}
}

// Sanity-pattern compile (avoid unused import errors when pattern reuse is
// expected).
var _ = regexp.MustCompile
