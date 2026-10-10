package smartroute

import (
	"net/http"
	"testing"
)

const forcePolicy = `
enabled: true
default_class: chat
agents:
  codex: false
  kilo-code: true
  cursor:
    enabled: true
    force_class: code
classes:
  - name: code
    route:
      model: qwen3.8-27b-local
      tier: "0"
      params:
        temperature: 0.2
  - name: chat
    route:
      model: qwen3.8-27b-local
      tier: "1"
`

// TestAgentPolicy_BoolAndObjectFormsCoexist: the extended form must not break
// the one-line boolean UX the operator already uses.
func TestAgentPolicy_BoolAndObjectFormsCoexist(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, forcePolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.AgentAllowed("codex") {
		t.Error("bool false form must still block")
	}
	if !p.AgentAllowed("kilo-code") || !p.AgentAllowed("cursor") {
		t.Error("bool true and object-enabled forms must both allow")
	}
	if got := p.ForceClass("cursor"); got != "code" {
		t.Errorf("ForceClass(cursor) = %q, want code", got)
	}
	if got := p.ForceClass("kilo-code"); got != "" {
		t.Errorf("ForceClass(kilo-code) = %q, want empty", got)
	}
}

// TestForceClass_OverridesExplicitModel is the feature's whole purpose: a
// client that insists on sending its own model id (Cursor sends gpt-*) still
// lands on the policy's route.
func TestForceClass_OverridesExplicitModel(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, forcePolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	r := NewRouter(p)

	req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(HeaderAgent, "cursor")
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`)

	d, err := r.Decide(req, body)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Source != SourceAgentForce {
		t.Fatalf("source = %q, want %q", d.Source, SourceAgentForce)
	}
	if d.Model != "qwen3.8-27b-local" || d.Class != "code" {
		t.Errorf("decision = %s/%s, want qwen3.8-27b-local via code", d.Model, d.Class)
	}
	out, err := r.Rewrite(body, d)
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	if string(out) == string(body) {
		t.Error("Rewrite must replace the caller's model for a forced agent")
	}
}

// TestForceClass_OtherAgentsKeepExplicitModelBypass: forcing cursor must not
// leak onto kilo-code or unidentified callers.
func TestForceClass_OtherAgentsKeepExplicitModelBypass(t *testing.T) {
	p, _ := LoadPolicy(writePolicy(t, forcePolicy))
	r := NewRouter(p)

	for _, agent := range []string{"kilo-code", ""} {
		req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		if agent != "" {
			req.Header.Set(HeaderAgent, agent)
		}
		d, err := r.Decide(req, []byte(`{"model":"gpt-4o","messages":[]}`))
		if err != nil {
			t.Fatalf("Decide(%q): %v", agent, err)
		}
		if d.Source != SourceExplicitModel || d.Model != "gpt-4o" {
			t.Errorf("agent %q: decision = %+v, want untouched explicit model", agent, d)
		}
	}
}

func TestValidate_RejectsUnknownForceClass(t *testing.T) {
	bad := "enabled: true\ndefault_class: chat\nagents:\n  cursor:\n    force_class: nope\nclasses:\n  - name: chat\n    route:\n      model: m\n"
	if _, err := LoadPolicy(writePolicy(t, bad)); err == nil {
		t.Fatal("LoadPolicy must reject a force_class that names no class")
	}
}
