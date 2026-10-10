// Package health implements upstream health-check probe logic for
// the llm-cluster-router.
package health

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProbeNode attempts to reach the upstream via the configured health
// path, falling back to /v1/models on 404. Returns true when the
// upstream is reachable and returns a 2xx status.
//
// ProbeNode sends no credentials, deliberately: probes have always been
// anonymous and most upstreams (llama-server, Ollama) expect that. An
// upstream that gates its health surface behind a token header is
// probed via ProbeNodeAuth instead.
func ProbeNode(parent context.Context, timeout time.Duration, healthPath string, baseURL *url.URL) bool {
	return ProbeNodeAuth(parent, timeout, healthPath, baseURL, "", "")
}

// ProbeNodeAuth is ProbeNode carrying an auth header. authHeader names
// the header and authValue is sent verbatim (no "Bearer " prefix) --
// the same wire shape the proxy uses for auth_header nodes, so a node
// that authenticates proxied traffic health-checks identically. An
// empty authHeader degrades to the anonymous ProbeNode behaviour.
func ProbeNodeAuth(parent context.Context, timeout time.Duration, healthPath string, baseURL *url.URL, authHeader, authValue string) bool {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	for _, path := range ProbePaths(healthPath) {
		ok, status := ProbeNodePathAuth(ctx, baseURL, path, authHeader, authValue)
		if ok {
			return true
		}
		if status != http.StatusNotFound {
			return false
		}
	}
	return false
}

// ProbePaths returns the ordered list of paths to try for a health
// check. The primary path is always first; /v1/models is appended
// as a fallback for Ollama-style upstreams that don't expose /health.
func ProbePaths(primary string) []string {
	paths := []string{primary}
	if primary != "/v1/models" {
		paths = append(paths, "/v1/models")
	}
	return paths
}

// ProbeNodePath issues a GET against baseURL+path and returns
// whether the response was 2xx, plus the actual status code.
func ProbeNodePath(ctx context.Context, baseURL *url.URL, path string) (bool, int) {
	return ProbeNodePathAuth(ctx, baseURL, path, "", "")
}

// ProbeNodePathAuth is ProbeNodePath with an optional auth header,
// attached only when both name and value are non-empty.
func ProbeNodePathAuth(ctx context.Context, baseURL *url.URL, path, authHeader, authValue string) (bool, int) {
	target := *baseURL
	target.Path = strings.TrimRight(baseURL.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false, 0
	}
	if authHeader != "" && authValue != "" {
		req.Header.Set(authHeader, authValue)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300, resp.StatusCode
}

// IsRetryableConnError returns true for connection-level errors that
// warrant a single transparent retry (idle conn resets, RST, EPIPE).
func IsRetryableConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "server closed idle connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}
