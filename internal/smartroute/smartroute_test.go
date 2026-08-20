package smartroute

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "smartroute.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

var samplePolicy = strings.ReplaceAll(samplePolicyTmpl, "FENCE", codeFence)

const codeFence = "```"

const samplePolicyTmpl = `
enabled: true
default_class: chat
classes:
  - name: code
    description: coding assistance
    match:
      any_of_markers: ["FENCE", "func ", "def ", "class "]
    route:
      model: qwen3.8-27b-local
      tier: large
      params:
        temperature: 0.2
        top_p: 0.9
  - name: long_context
    description: very large prompts
    match:
      min_prompt_chars: 100000
    route:
      model: qwen3.8-27b-local
      tier: large
      params:
        temperature: 0.3
  - name: chat
    description: default conversational
    route:
      model: qwen3.8-27b-local
      tier: small
      params:
        temperature: 0.7
  - name: cheap
    description: disabled example provider
    enabled: false
    route:
      model: some-cheap-model
      tier: small
`

func TestLoadPolicy_ParsesClassesAndDefaults(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, samplePolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if !p.Enabled {
		t.Error("policy should be enabled")
	}
	if got, want := len(p.EnabledClasses()), 3; got != want {
		t.Errorf("enabled classes = %d, want %d (the disabled one must be excluded)", got, want)
	}
	if p.DefaultClass != "chat" {
		t.Errorf("default_class = %q, want chat", p.DefaultClass)
	}
}

func TestPolicyValidate_RejectsBrokenConfig(t *testing.T) {
	cases := map[string]struct{ policy, want string }{
		"unknown default class": {
			policy: "enabled: true\ndefault_class: nope\nclasses:\n  - name: chat\n    route:\n      model: m\n",
			want:   "default_class",
		},
		"duplicate class name": {
			policy: "enabled: true\ndefault_class: chat\nclasses:\n  - name: chat\n    route:\n      model: m\n  - name: chat\n    route:\n      model: n\n",
			want:   "duplicate",
		},
		"class without model": {
			policy: "enabled: true\ndefault_class: chat\nclasses:\n  - name: chat\n    route:\n      tier: small\n",
			want:   "model is required",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadPolicy(writePolicy(t, tc.policy))
			if err == nil {
				t.Fatalf("LoadPolicy() = nil error, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestHeaderClassifier_WinsOverHeuristics is the escape hatch: an explicit
// caller header must always beat inference, so an operator can force a route
// when the heuristic guesses wrong.
func TestHeaderClassifier_WinsOverHeuristics(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, samplePolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	r := NewRouter(p)

	body := []byte(`{"model":"auto","messages":[{"role":"user","content":"` + "```go\\nfunc main(){}\\n```" + `"}]}`)
	req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(HeaderTaskClass, "chat") // contradicts the code markers in the body

	d, err := r.Decide(req, body)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Class != "chat" {
		t.Errorf("class = %q, want chat (explicit header must override heuristics)", d.Class)
	}
	if d.Source != SourceHeader {
		t.Errorf("source = %q, want %q", d.Source, SourceHeader)
	}
}

func TestHeuristicClassifier_DetectsCodeAndLongContext(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, samplePolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	r := NewRouter(p)

	t.Run("code markers", func(t *testing.T) {
		body := []byte(`{"messages":[{"role":"user","content":"write ` + "```" + ` a function"}]}`)
		d, err := r.Decide(mustReq(t), body)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if d.Class != "code" {
			t.Errorf("class = %q, want code", d.Class)
		}
		if d.Model != "qwen3.8-27b-local" || d.Tier != "large" {
			t.Errorf("route = %s/%s, want qwen3.8-27b-local/large", d.Model, d.Tier)
		}
	})

	t.Run("long context by size", func(t *testing.T) {
		long := strings.Repeat("x", 120000)
		payload, _ := json.Marshal(map[string]any{
			"messages": []map[string]string{{"role": "user", "content": long}},
		})
		d, err := r.Decide(mustReq(t), payload)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if d.Class != "long_context" {
			t.Errorf("class = %q, want long_context for a %d-char prompt", d.Class, len(long))
		}
	})

	t.Run("falls back to default", func(t *testing.T) {
		body := []byte(`{"messages":[{"role":"user","content":"hello there"}]}`)
		d, err := r.Decide(mustReq(t), body)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if d.Class != "chat" {
			t.Errorf("class = %q, want the default class chat", d.Class)
		}
		if d.Source != SourceDefault {
			t.Errorf("source = %q, want %q", d.Source, SourceDefault)
		}
	})
}

// TestRewrite_InjectsModelAndParams covers the core promise: the router
// rewrites the outbound body so a client can send model:"auto" and still land
// on a concrete model with the right sampling parameters.
func TestRewrite_InjectsModelAndParams(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, samplePolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	r := NewRouter(p)

	body := []byte(`{"model":"auto","messages":[{"role":"user","content":"` + "```" + ` code"}],"stream":true}`)
	d, err := r.Decide(mustReq(t), body)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	out, err := r.Rewrite(body, d)
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("rewritten body is not valid JSON: %v", err)
	}
	if got["model"] != "qwen3.8-27b-local" {
		t.Errorf("model = %v, want the policy's model injected", got["model"])
	}
	if got["temperature"] != 0.2 {
		t.Errorf("temperature = %v, want 0.2 injected from policy", got["temperature"])
	}
	if got["stream"] != true {
		t.Error("stream flag was dropped — rewrite must preserve caller fields it does not own")
	}
	if _, ok := got["messages"]; !ok {
		t.Error("messages were dropped by rewrite")
	}
}

// TestRewrite_CallerParamsWin protects against the router silently overriding
// an explicit choice: if the caller set temperature, policy must not clobber it.
func TestRewrite_CallerParamsWin(t *testing.T) {
	p, _ := LoadPolicy(writePolicy(t, samplePolicy))
	r := NewRouter(p)

	body := []byte(`{"model":"auto","temperature":0.95,"messages":[{"role":"user","content":"` + "```" + ` x"}]}`)
	d, _ := r.Decide(mustReq(t), body)
	out, err := r.Rewrite(body, d)
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if got["temperature"] != 0.95 {
		t.Errorf("temperature = %v, want the caller's explicit 0.95 preserved", got["temperature"])
	}
}

// TestExplicitModel_BypassesClassification: a caller naming a concrete model
// means it, and the router must not second-guess it.
func TestExplicitModel_BypassesClassification(t *testing.T) {
	p, _ := LoadPolicy(writePolicy(t, samplePolicy))
	r := NewRouter(p)

	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"` + "```" + ` code"}]}`)
	d, err := r.Decide(mustReq(t), body)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Source != SourceExplicitModel {
		t.Errorf("source = %q, want %q for an explicitly named model", d.Source, SourceExplicitModel)
	}
	if d.Model != "gpt-4o-mini" {
		t.Errorf("model = %q, want the caller's model untouched", d.Model)
	}
	out, _ := r.Rewrite(body, d)
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if got["model"] != "gpt-4o-mini" {
		t.Errorf("rewritten model = %v, want unchanged", got["model"])
	}
}

func TestDisabledPolicy_IsInert(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, "enabled: false\ndefault_class: chat\nclasses:\n  - name: chat\n    route:\n      model: m\n"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	r := NewRouter(p)
	body := []byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}]}`)
	d, err := r.Decide(mustReq(t), body)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Source != SourceDisabled {
		t.Errorf("source = %q, want %q when the feature flag is off", d.Source, SourceDisabled)
	}
	out, _ := r.Rewrite(body, d)
	if string(out) != string(body) {
		t.Error("a disabled policy must pass the body through byte-identical")
	}
}

func TestDecide_MalformedBodyFallsBackSafely(t *testing.T) {
	p, _ := LoadPolicy(writePolicy(t, samplePolicy))
	r := NewRouter(p)
	d, err := r.Decide(mustReq(t), []byte("{not json"))
	if err != nil {
		t.Fatalf("Decide must not fail on a malformed body, got %v", err)
	}
	if d.Class != "chat" {
		t.Errorf("class = %q, want the default class when the body cannot be parsed", d.Class)
	}
}

func mustReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
