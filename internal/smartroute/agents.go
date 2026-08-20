package smartroute

import (
	"net/http"
	"strings"
)

// HeaderAgent lets a caller declare which agent it is (cursor, claude-code,
// kilo-code, codex, ...). An explicit header always beats User-Agent
// sniffing, so a client that identifies itself can never be misclassified.
const HeaderAgent = "X-Helixon-Agent"

// Canonical agent identities. These are the map keys operators put under
// `agents:` in the policy, and what DetectAgent returns.
const (
	AgentCursor     = "cursor"
	AgentClaudeCode = "claude-code"
	AgentKiloCode   = "kilo-code"
	AgentCodex      = "codex"
)

// uaHints maps a lowercase User-Agent substring to a canonical agent
// identity. Order matters only for overlapping hints, so more specific
// substrings come first ("kilo" before "code").
var uaHints = []struct{ needle, agent string }{
	{"kilo", AgentKiloCode},
	{"cursor", AgentCursor},
	{"claude", AgentClaudeCode},
	{"codex", AgentCodex},
	{"openai", AgentCodex},
}

// DetectAgent identifies the calling agent from the request. The explicit
// X-Helixon-Agent header wins; otherwise the User-Agent is sniffed for known
// tools. Unknown callers return "" — which AgentAllowed treats as allowed,
// because the gate is a denylist of explicit false flags, not an allowlist.
func DetectAgent(req *http.Request) string {
	if req == nil {
		return ""
	}
	if h := strings.ToLower(strings.TrimSpace(req.Header.Get(HeaderAgent))); h != "" {
		return h
	}
	ua := strings.ToLower(req.Header.Get("User-Agent"))
	if ua == "" {
		return ""
	}
	for _, hint := range uaHints {
		if strings.Contains(ua, hint.needle) {
			return hint.agent
		}
	}
	return ""
}

// AgentPolicy is one agent's entry in the policy's agents map. YAML accepts
// two shapes, so the simple case stays a one-liner:
//
//	agents:
//	  codex: false                      # plain boolean gate
//	  cursor:                           # extended form
//	    enabled: true
//	    force_class: code               # ALL cursor traffic routed as "code",
//	                                    # even when it names a concrete model
//
// force_class exists for callers whose UIs insist on sending their own model
// ids (Cursor sends gpt-* names): it overrides both the explicit-model bypass
// and heuristic classification for that agent only.
type AgentPolicy struct {
	Enabled    *bool  `yaml:"enabled"`
	ForceClass string `yaml:"force_class"`
}

// UnmarshalYAML accepts either a bare boolean or the extended mapping form.
func (ap *AgentPolicy) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var b bool
	if err := unmarshal(&b); err == nil {
		ap.Enabled = &b
		return nil
	}
	type raw AgentPolicy // shed the method set to avoid recursion
	var r raw
	if err := unmarshal(&r); err != nil {
		return err
	}
	*ap = AgentPolicy(r)
	return nil
}

// AgentAllowed reports whether the named agent may route through this
// policy. Only an explicit `enabled: false` blocks; a missing entry, an
// empty identity, or a policy with no agents section all allow. That default
// keeps the feature purely additive: existing policies and unidentified
// callers behave exactly as before it existed.
func (p *Policy) AgentAllowed(agent string) bool {
	if p == nil || len(p.Agents) == 0 || agent == "" {
		return true
	}
	ap, present := p.Agents[strings.ToLower(agent)]
	if !present || ap.Enabled == nil {
		return true
	}
	return *ap.Enabled
}

// ForceClass returns the class name all of this agent's traffic must take,
// or "" when the agent routes normally.
func (p *Policy) ForceClass(agent string) string {
	if p == nil || agent == "" {
		return ""
	}
	return p.Agents[strings.ToLower(agent)].ForceClass
}

// AgentAllowed on the Router is the surface the serving layer calls. It is
// nil-safe and inert when the policy feature flag is off, so wiring it into
// a request path can never turn into an accidental outage.
func (r *Router) AgentAllowed(agent string) bool {
	if r == nil || r.policy == nil || !r.policy.Enabled {
		return true
	}
	return r.policy.AgentAllowed(agent)
}
