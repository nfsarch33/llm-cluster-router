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

// AgentAllowed reports whether the named agent may route through this
// policy. Only an explicit `false` in the agents map blocks; a missing
// entry, an empty identity, or a policy with no agents section all allow.
// That default keeps the feature purely additive: existing policies and
// unidentified callers behave exactly as before it existed.
func (p *Policy) AgentAllowed(agent string) bool {
	if p == nil || len(p.Agents) == 0 || agent == "" {
		return true
	}
	v, present := p.Agents[strings.ToLower(agent)]
	if !present || v == nil {
		return true
	}
	return *v
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
