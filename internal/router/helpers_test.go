package router

import "testing"

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
