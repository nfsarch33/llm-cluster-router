// Package smartroute decides which model and tier an OpenAI-compatible
// request should be served by, and rewrites the request body accordingly.
//
// It sits in front of the existing node selector: it converts
// (headers, body) into (model, tier, params), which are exactly the inputs
// the selector already consumes. Nothing downstream changes, so the feature
// is additive and can be switched off with a single flag.
//
// Why this exists: agents (Kilo Code, Cursor, Claude Code, Codex) each send a
// model name their UI knows about, but the right upstream for a request
// depends on the task — a 200k-token refactor and a one-line question should
// not land on the same node with the same sampling parameters. Callers can
// send model:"auto" and let policy decide, or name a concrete model and be
// left alone.
//
// Design (SOLID):
//
//   - Policy      — pure configuration data (SRP). Adding a task class or a
//     provider is a YAML edit, not a code change (OCP).
//   - Classifier  — strategy for deciding a request's task class. Header,
//     heuristic and default implementations are interchangeable (LSP) and the
//     Router depends only on the interface (DIP).
//   - Rewriter    — applies the chosen model and parameters to the body.
//
// All classification is deterministic and rule-based. That is deliberate: it
// adds a step to the request path without adding a model-inference step, so
// it does not multiply the end-to-end failure probability of the chain.
package smartroute

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// HeaderTaskClass lets a caller name the task class explicitly and bypass
// inference entirely.
const HeaderTaskClass = "X-Helixon-Task"

// AutoModel is the sentinel a caller sends to ask the router to choose.
const AutoModel = "auto"

// Decision sources, recorded on every decision so routing is explainable in
// logs and metrics rather than a black box.
const (
	SourceHeader        = "header"         // caller named the class
	SourceExplicitModel = "explicit_model" // caller named a concrete model
	SourceHeuristic     = "heuristic"      // inferred from the request shape
	SourceDefault       = "default"        // nothing matched; default class
	SourceDisabled      = "disabled"       // feature flag off; pass through
)

// Match holds the (deterministic) conditions for a class to apply.
type Match struct {
	// AnyOfMarkers matches when any listed substring appears in the prompt.
	AnyOfMarkers []string `yaml:"any_of_markers"`
	// MinPromptChars matches when the prompt is at least this long.
	MinPromptChars int `yaml:"min_prompt_chars"`
}

// Route is what a matched class resolves to.
type Route struct {
	// Model is the upstream model id injected into the request.
	Model string `yaml:"model"`
	// Tier maps to the router's existing X-Tier selection.
	Tier string `yaml:"tier"`
	// Params are sampling parameters applied ONLY when the caller did not
	// set them, so an explicit caller choice is never silently overridden.
	Params map[string]any `yaml:"params"`
}

// Class is one task class in the policy.
type Class struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Enabled is the per-class feature flag. Absent means enabled, so an
	// existing policy does not change meaning when this field is added.
	Enabled *bool `yaml:"enabled"`
	Match   Match `yaml:"match"`
	Route   Route `yaml:"route"`
}

// IsEnabled reports the class's flag, defaulting to true when unset.
func (c Class) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// Policy is the on-disk smart-routing configuration.
type Policy struct {
	// Enabled is the master switch. When false the router is inert and
	// bodies pass through untouched.
	Enabled bool `yaml:"enabled"`
	// Agents is the per-agent route gate: one boolean per calling agent
	// (cursor, claude-code, kilo-code, codex, ...). Only an explicit false
	// blocks; a missing entry allows, so the section is purely additive.
	Agents map[string]*bool `yaml:"agents"`
	// DefaultClass is used when no class matches.
	DefaultClass string  `yaml:"default_class"`
	Classes      []Class `yaml:"classes"`
}

// LoadPolicy reads and validates a policy file.
func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read smartroute policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse smartroute policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate reports configuration errors at load time rather than letting them
// surface as mis-routed traffic. Disabled classes are validated too: a typo in
// a class that is switched off today must not become an incident the day it is
// switched on.
func (p *Policy) Validate() error {
	if len(p.Classes) == 0 {
		return fmt.Errorf("classes: at least one class is required")
	}
	seen := map[string]bool{}
	for i, c := range p.Classes {
		switch {
		case c.Name == "":
			return fmt.Errorf("classes[%d]: name is required", i)
		case seen[c.Name]:
			return fmt.Errorf("classes[%d]: duplicate class name %q", i, c.Name)
		case c.Route.Model == "":
			return fmt.Errorf("class %q: route.model is required", c.Name)
		}
		seen[c.Name] = true
	}
	if p.DefaultClass == "" {
		return fmt.Errorf("default_class is required")
	}
	if !seen[p.DefaultClass] {
		return fmt.Errorf("default_class %q does not name a defined class", p.DefaultClass)
	}
	return nil
}

// EnabledClasses returns only the classes whose flag is on.
func (p *Policy) EnabledClasses() []Class {
	out := make([]Class, 0, len(p.Classes))
	for _, c := range p.Classes {
		if c.IsEnabled() {
			out = append(out, c)
		}
	}
	return out
}

// lookup finds a class by name regardless of its flag.
func (p *Policy) lookup(name string) (Class, bool) {
	for _, c := range p.Classes {
		if c.Name == name {
			return c, true
		}
	}
	return Class{}, false
}

// Decision is the routing outcome, including why it was reached.
type Decision struct {
	Class  string
	Model  string
	Tier   string
	Params map[string]any
	Source string
}

// Classifier decides a request's task class.
//
// Implementations return ok=false to defer to the next classifier, which lets
// the Router compose them in priority order without any of them knowing about
// the others.
type Classifier interface {
	Classify(req *http.Request, body []byte, p *Policy) (class string, ok bool)
	Name() string
}

// headerClassifier honours an explicit X-Helixon-Task header.
type headerClassifier struct{}

func (headerClassifier) Name() string { return SourceHeader }

func (headerClassifier) Classify(req *http.Request, _ []byte, p *Policy) (string, bool) {
	if req == nil {
		return "", false
	}
	name := strings.TrimSpace(req.Header.Get(HeaderTaskClass))
	if name == "" {
		return "", false
	}
	// An unknown class name is ignored rather than honoured, so a typo in a
	// client falls back to inference instead of routing nowhere.
	if _, found := p.lookup(name); !found {
		return "", false
	}
	return name, true
}

// heuristicClassifier infers a class from the request shape.
type heuristicClassifier struct{}

func (heuristicClassifier) Name() string { return SourceHeuristic }

func (heuristicClassifier) Classify(_ *http.Request, body []byte, p *Policy) (string, bool) {
	prompt := extractPrompt(body)
	if prompt == "" {
		return "", false
	}
	// Size-based classes are checked first: a very large prompt is a
	// stronger signal than an incidental code fence inside it.
	best, bestMin := "", 0
	for _, c := range p.EnabledClasses() {
		if c.Match.MinPromptChars > 0 && len(prompt) >= c.Match.MinPromptChars && c.Match.MinPromptChars > bestMin {
			best, bestMin = c.Name, c.Match.MinPromptChars
		}
	}
	if best != "" {
		return best, true
	}
	for _, c := range p.EnabledClasses() {
		for _, marker := range c.Match.AnyOfMarkers {
			if marker != "" && strings.Contains(prompt, marker) {
				return c.Name, true
			}
		}
	}
	return "", false
}

// Router composes classifiers and applies the resulting route.
type Router struct {
	policy      *Policy
	classifiers []Classifier
}

// NewRouter builds a Router with the default classifier chain: an explicit
// header first, then heuristics. The default class closes the chain.
func NewRouter(p *Policy) *Router {
	return &Router{
		policy:      p,
		classifiers: []Classifier{headerClassifier{}, heuristicClassifier{}},
	}
}

// WithClassifiers replaces the classifier chain, for tests or for a node that
// wants a different inference strategy.
func (r *Router) WithClassifiers(cs ...Classifier) *Router {
	r.classifiers = cs
	return r
}

// Decide resolves a request to a routing decision.
//
// It never returns an error for request-shaped problems: a malformed body
// falls back to the default class, because refusing to route a request the
// upstream might still understand would be a worse failure than routing it
// conservatively.
func (r *Router) Decide(req *http.Request, body []byte) (Decision, error) {
	if r.policy == nil || !r.policy.Enabled {
		return Decision{Source: SourceDisabled, Model: extractModel(body)}, nil
	}

	// A caller naming a concrete model means it; do not second-guess.
	if m := extractModel(body); m != "" && !strings.EqualFold(m, AutoModel) {
		return Decision{Model: m, Source: SourceExplicitModel}, nil
	}

	for _, c := range r.classifiers {
		if name, ok := c.Classify(req, body, r.policy); ok {
			cl, found := r.policy.lookup(name)
			if !found || !cl.IsEnabled() {
				continue
			}
			return decisionFor(cl, c.Name()), nil
		}
	}

	def, found := r.policy.lookup(r.policy.DefaultClass)
	if !found {
		// Validate() guarantees this cannot happen for a loaded policy; a
		// hand-built one gets a clear error rather than a silent misroute.
		return Decision{}, fmt.Errorf("default class %q not found", r.policy.DefaultClass)
	}
	return decisionFor(def, SourceDefault), nil
}

func decisionFor(c Class, source string) Decision {
	return Decision{
		Class:  c.Name,
		Model:  c.Route.Model,
		Tier:   c.Route.Tier,
		Params: c.Route.Params,
		Source: source,
	}
}

// Rewrite applies a decision to the request body.
//
// Caller-supplied fields always win: policy parameters fill gaps, they do not
// overwrite an explicit choice. Unknown fields are preserved verbatim so the
// router never silently drops something an upstream understands.
func (r *Router) Rewrite(body []byte, d Decision) ([]byte, error) {
	if d.Source == SourceDisabled || d.Source == SourceExplicitModel {
		return body, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		// Nothing to rewrite into; pass through rather than reject.
		return body, nil
	}
	if d.Model != "" {
		payload["model"] = d.Model
	}
	for k, v := range d.Params {
		if _, present := payload[k]; !present {
			payload[k] = v
		}
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("re-encode rewritten body: %w", err)
	}
	return out, nil
}

// extractModel reads just the model field.
func extractModel(body []byte) string {
	var p struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return ""
	}
	return p.Model
}

// extractPrompt concatenates message contents so heuristics have one string
// to inspect. Multimodal content arrays contribute their text parts only.
func extractPrompt(body []byte) string {
	var p struct {
		Prompt   string `json:"prompt"`
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(p.Prompt)
	for _, m := range p.Messages {
		var s string
		if err := json.Unmarshal(m.Content, &s); err == nil {
			b.WriteString(s)
			continue
		}
		var parts []struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(m.Content, &parts); err == nil {
			for _, part := range parts {
				b.WriteString(part.Text)
			}
		}
	}
	return b.String()
}
