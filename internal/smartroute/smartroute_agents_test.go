package smartroute

import (
	"net/http"
	"testing"
)

const agentPolicy = `
enabled: true
default_class: chat
agents:
  cursor: true
  claude-code: true
  kilo-code: true
  codex: false
classes:
  - name: chat
    route:
      model: qwen3.8-27b-local
      tier: small
`

func loadAgentPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := LoadPolicy(writePolicy(t, agentPolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p
}

// TestAgentAllowed_ExplicitFlags is the core contract: one boolean per agent,
// false blocks, true allows.
func TestAgentAllowed_ExplicitFlags(t *testing.T) {
	p := loadAgentPolicy(t)
	for agent, want := range map[string]bool{
		"cursor":      true,
		"claude-code": true,
		"kilo-code":   true,
		"codex":       false,
	} {
		if got := p.AgentAllowed(agent); got != want {
			t.Errorf("AgentAllowed(%q) = %v, want %v", agent, got, want)
		}
	}
}

// TestAgentAllowed_UnknownAndAbsentAreAllowed: the gate is a denylist of
// explicit false values. An agent not in the map, an empty identity, or a
// policy without an agents section must all pass — otherwise adding the
// feature would break every existing caller.
func TestAgentAllowed_UnknownAndAbsentAreAllowed(t *testing.T) {
	p := loadAgentPolicy(t)
	if !p.AgentAllowed("some-new-tool") {
		t.Error("an agent absent from the map must be allowed")
	}
	if !p.AgentAllowed("") {
		t.Error("an unidentified caller must be allowed")
	}

	noAgents, err := LoadPolicy(writePolicy(t, "enabled: true\ndefault_class: chat\nclasses:\n  - name: chat\n    route:\n      model: m\n"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if !noAgents.AgentAllowed("codex") {
		t.Error("a policy without an agents section must allow everyone")
	}
}

func TestDetectAgent_HeaderWinsOverUserAgent(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("User-Agent", "Cursor/1.7.2")
	req.Header.Set(HeaderAgent, "Kilo-Code")
	if got := DetectAgent(req); got != "kilo-code" {
		t.Errorf("DetectAgent = %q, want kilo-code (explicit header, normalized)", got)
	}
}

func TestDetectAgent_UserAgentSniffing(t *testing.T) {
	cases := map[string]string{
		"Cursor/1.7.2 (darwin)":         "cursor",
		"KiloCode/4.1 VSCode-extension": "kilo-code",
		"claude-cli/2.1.235 (external)": "claude-code",
		"OpenAI-Codex/0.9":              "codex",
		"curl/8.5.0":                    "",
		"":                              "",
	}
	for ua, want := range cases {
		req, _ := http.NewRequest(http.MethodPost, "/", nil)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		if got := DetectAgent(req); got != want {
			t.Errorf("DetectAgent(UA=%q) = %q, want %q", ua, got, want)
		}
	}
}

// TestRouterAgentAllowed_NilSafe: the wiring in main calls this on whatever
// router it has; nil policy or disabled feature must behave as allow-all.
func TestRouterAgentAllowed_NilSafe(t *testing.T) {
	var r *Router
	if !r.AgentAllowed("codex") {
		t.Error("nil Router must allow everyone")
	}
	r = NewRouter(nil)
	if !r.AgentAllowed("codex") {
		t.Error("Router with nil policy must allow everyone")
	}
	off, err := LoadPolicy(writePolicy(t, "enabled: false\ndefault_class: chat\nagents:\n  codex: false\nclasses:\n  - name: chat\n    route:\n      model: m\n"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if !NewRouter(off).AgentAllowed("codex") {
		t.Error("a disabled policy must not enforce agent gates")
	}
}

// TestRouterAgentAllowed_Enforced: with the feature on, the Router surface
// (what main.go actually calls) must enforce the boolean.
func TestRouterAgentAllowed_Enforced(t *testing.T) {
	r := NewRouter(loadAgentPolicy(t))
	if r.AgentAllowed("codex") {
		t.Error("codex is flagged false and must be blocked")
	}
	if !r.AgentAllowed("kilo-code") {
		t.Error("kilo-code is flagged true and must pass")
	}
}
