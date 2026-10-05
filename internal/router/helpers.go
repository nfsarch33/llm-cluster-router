// Package router provides node selection helpers and routing
// utilities for the llm-cluster-router.
package router

import (
	"encoding/json"
	"strings"
)

// NodeEnabled returns true when a node's "enabled" config value
// resolves to an active state. Empty, "1", "true", "yes", and "on"
// are all truthy; anything else (including "false", "0") is falsy.
func NodeEnabled(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "" || value == "1" || value == "true" || value == "yes" || value == "on"
}

// SupportsModel returns true if the node's model list contains the
// requested model name (exact match).
func SupportsModel(models []string, model string) bool {
	for _, candidate := range models {
		if candidate == model {
			return true
		}
	}
	return false
}

// ExtractModel unmarshals just the "model" field from an
// OpenAI-compatible JSON request body.
func ExtractModel(body []byte) string {
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Model
}

// MetricLabel returns value trimmed, or fallback if value is empty.
func MetricLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// ApplyModelRewrite returns body with its "model" field replaced when the
// node carries a rewrite for the requested name, and nil when the body's
// model matches no rewrite key (or rewriting would be a no-op) — so the
// caller forwards the original bytes untouched instead of re-marshalling
// every request. All other fields are preserved verbatim.
func ApplyModelRewrite(body []byte, rewrites map[string]string) []byte {
	if len(rewrites) == 0 {
		return nil
	}
	from := ExtractModel(body)
	to, ok := rewrites[from]
	if !ok || to == "" || to == from {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	payload["model"] = to
	out, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return out
}
