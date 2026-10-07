package router

import (
	"encoding/json"
	"testing"
)

func TestNodeEnabled_TruthyValues(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true}, // empty = enabled by default
		{"1", true},
		{"true", true},
		{"yes", true},
		{"on", true},
		{"TRUE", true},
		{"Yes", true},
		{"  on  ", true},
	}
	for _, c := range cases {
		got := NodeEnabled(c.in)
		if got != c.want {
			t.Errorf("NodeEnabled(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNodeEnabled_FalsyValues(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"false", false},
		{"0", false},
		{"off", false},
		{"no", false},
		{"disabled", false},
		{"nope", false},
	}
	for _, c := range cases {
		got := NodeEnabled(c.in)
		if got != c.want {
			t.Errorf("NodeEnabled(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSupportsModel_Found(t *testing.T) {
	models := []string{"gpt-4o-mini", "claude-haiku", "qwen-turbo"}
	if !SupportsModel(models, "claude-haiku") {
		t.Error("expected SupportsModel=true for 'claude-haiku'")
	}
}

func TestSupportsModel_NotFound(t *testing.T) {
	models := []string{"gpt-4o-mini", "claude-haiku"}
	if SupportsModel(models, "gpt-4") {
		t.Error("expected SupportsModel=false for 'gpt-4'")
	}
}

func TestSupportsModel_Empty(t *testing.T) {
	if SupportsModel(nil, "any-model") {
		t.Error("expected SupportsModel=false for nil/empty list")
	}
	if SupportsModel([]string{}, "any-model") {
		t.Error("expected SupportsModel=false for empty slice")
	}
}

func TestSupportsModel_CaseSensitive(t *testing.T) {
	models := []string{"GPT-4o-mini"}
	if SupportsModel(models, "gpt-4o-mini") {
		t.Error("SupportsModel should be case-sensitive (got true for lowercase match against 'GPT-4o-mini')")
	}
}

func TestExtractModel_HappyPath(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"temperature":0.7}`)
	got := ExtractModel(body)
	if got != "gpt-4o-mini" {
		t.Errorf("ExtractModel = %q, want gpt-4o-mini", got)
	}
}

func TestExtractModel_OnlyModelField(t *testing.T) {
	body := []byte(`{"model":"claude-haiku"}`)
	got := ExtractModel(body)
	if got != "claude-haiku" {
		t.Errorf("ExtractModel = %q, want claude-haiku", got)
	}
}

func TestExtractModel_MissingModel(t *testing.T) {
	body := []byte(`{"messages":[]}`)
	got := ExtractModel(body)
	if got != "" {
		t.Errorf("ExtractModel = %q, want empty string", got)
	}
}

func TestExtractModel_InvalidJSON(t *testing.T) {
	body := []byte(`{"model": invalid`)
	got := ExtractModel(body)
	if got != "" {
		t.Errorf("ExtractModel = %q, want empty string for invalid JSON", got)
	}
}

func TestExtractModel_EmptyBody(t *testing.T) {
	got := ExtractModel(nil)
	if got != "" {
		t.Errorf("ExtractModel(nil) = %q, want empty string", got)
	}
	got = ExtractModel([]byte{})
	if got != "" {
		t.Errorf("ExtractModel([]) = %q, want empty string", got)
	}
}

func TestMetricLabel_Trimmed(t *testing.T) {
	if got := MetricLabel("  qwen-turbo  ", "fallback"); got != "qwen-turbo" {
		t.Errorf("MetricLabel = %q, want qwen-turbo", got)
	}
}

func TestMetricLabel_EmptyUsesFallback(t *testing.T) {
	if got := MetricLabel("", "fallback"); got != "fallback" {
		t.Errorf("MetricLabel = %q, want fallback", got)
	}
}

func TestMetricLabel_WhitespaceOnlyUsesFallback(t *testing.T) {
	if got := MetricLabel("   ", "fallback"); got != "fallback" {
		t.Errorf("MetricLabel = %q, want fallback", got)
	}
}

func TestMetricLabel_TabAndNewlineTrimmed(t *testing.T) {
	if got := MetricLabel("\tlabel\n", "fallback"); got != "label" {
		t.Errorf("MetricLabel = %q, want label", got)
	}
}

func TestApplyModelRewrite(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"alias","temperature":0.3,"messages":[{"role":"user","content":"hi"}]}`)

	out := ApplyModelRewrite(body, map[string]string{"alias": "served"})
	if out == nil {
		t.Fatal("a matching rewrite must return a rewritten body")
	}
	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v", err)
	}
	if payload["model"] != "served" {
		t.Fatalf("model must be swapped to the served name, got %v", payload["model"])
	}
	if payload["temperature"] != 0.3 {
		t.Fatalf("every other field must survive the rewrite, temperature=%v", payload["temperature"])
	}

	if got := ApplyModelRewrite(body, map[string]string{"other": "x"}); got != nil {
		t.Fatalf("a model with no rewrite key must forward verbatim, got %s", got)
	}
	if got := ApplyModelRewrite(body, map[string]string{"alias": "alias"}); got != nil {
		t.Fatalf("a rewrite to the same name is a no-op, got %s", got)
	}
	if got := ApplyModelRewrite(body, nil); got != nil {
		t.Fatalf("an empty rewrite map must forward verbatim, got %s", got)
	}
	if got := ApplyModelRewrite([]byte(`not json`), map[string]string{"alias": "served"}); got != nil {
		t.Fatalf("an unparseable body must forward verbatim rather than be mangled, got %s", got)
	}

	// A number above 2^53 must survive the rewrite EXACTLY: a map[string]any
	// decode would re-encode it as a float64 and corrupt it.
	big := []byte(`{"model":"alias","seed":9007199254740993}`)
	outBig := ApplyModelRewrite(big, map[string]string{"alias": "served"})
	if outBig == nil {
		t.Fatal("big-int row must rewrite")
	}
	var bigPayload map[string]json.RawMessage
	if err := json.Unmarshal(outBig, &bigPayload); err != nil {
		t.Fatalf("rewritten big-int body invalid: %v", err)
	}
	if string(bigPayload["seed"]) != "9007199254740993" {
		t.Fatalf("seed must round-trip exactly, got %s", bigPayload["seed"])
	}
	if got := ExtractModel(outBig); got != "served" {
		t.Fatalf("model must be rewritten, got %q", got)
	}
}

// per-node request defaults — added when absent, caller's value
// kept when set, nil (original bytes) when nothing applies.
func TestMergeRequestDefaults(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"seed":9007199254740993}`)
	tr := json.RawMessage(`true`)

	out := MergeRequestDefaults(body, map[string]json.RawMessage{"reasoning_split": tr})
	if out == nil {
		t.Fatal("absent key must be merged")
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["reasoning_split"]) != "true" {
		t.Fatalf("reasoning_split = %s", got["reasoning_split"])
	}
	if string(got["seed"]) != "9007199254740993" {
		t.Fatalf("big seed corrupted: %s", got["seed"]) // float64 round-trip guard
	}
	if string(got["model"]) != `"m"` {
		t.Fatalf("model disturbed: %s", got["model"])
	}

	callerSet := []byte(`{"model":"m","reasoning_split":false}`)
	out = MergeRequestDefaults(callerSet, map[string]json.RawMessage{"reasoning_split": tr})
	if out != nil {
		t.Fatalf("caller-set key must be kept verbatim, got %s", out)
	}

	if out := MergeRequestDefaults(body, nil); out != nil {
		t.Fatal("no defaults: original bytes")
	}
	if out := MergeRequestDefaults([]byte(`not json`), map[string]json.RawMessage{"k": tr}); out != nil {
		t.Fatal("unparseable body: original bytes, never a guess")
	}
}
