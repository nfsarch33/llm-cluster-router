// Package cdp provides a minimal, stdlib-only helper for talking
// to an existing Chrome / Chromium DevTools Protocol (CDP) endpoint
// over HTTP. It is a CONNECT-ONLY stub: it does NOT spawn a browser,
// does NOT install chromedp, and does NOT touch any operator
// profile directory. Future work may add chromedp / playwright
// integrations; for v18706 the goal is a single-purpose reachability
// check so operators and agents fail fast when Chrome isn't running.
//
// Reference: https://chromedevtools.github.io/devtools-protocol/
// Real-world shape of /json/version (Chrome 120+):
//
//	{
//	  "Browser": "Chrome/120.0.6099.130",
//	  "Protocol-Version": "1.3",
//	  "User-Agent": "Mozilla/5.0 (...)",
//	  "V8-Version": "12.0.267.8",
//	  "WebKit-Version": "537.36 (...)",
//	  "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/<uuid>",
//	  "Target": ""
//	}
package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Browser describes the /json/version response from a running
// Chrome / Chromium DevTools endpoint. Only the fields agents
// actually need to surface are decoded; the rest is dropped.
type Browser struct {
	Browser              string `json:"Browser"`
	ProtocolVersion      string `json:"Protocol-Version"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// DefaultTimeout is the fail-fast budget for Ping. Operators who
// want a longer wait can pass a parent context with a later
// deadline; the value here matches the plan's "respond 200 within
// 3s" requirement.
const DefaultTimeout = 3 * time.Second

// Ping does a single GET against <baseURL>/json/version and
// returns the parsed Browser description. It is a connectivity
// probe, NOT a session allocator — agents that need an
// interactive CDP session should layer chromedp / playwright on
// top of this once chromedp is vendored into go.mod.
//
// Errors returned by Ping:
//   - context.DeadlineExceeded if the endpoint does not respond
//     within ctx deadline.
//   - "decode <reason>" if the response body is not the expected
//     JSON shape.
//   - wrapped http / url errors otherwise.
func Ping(ctx context.Context, baseURL string) (Browser, error) {
	if strings.TrimSpace(baseURL) == "" {
		return Browser{}, errors.New("cdp.Ping: empty baseURL")
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/json/version"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Browser{}, fmt.Errorf("cdp.Ping: new request: %w", err)
	}
	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return Browser{}, fmt.Errorf("cdp.Ping: connect %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Browser{}, fmt.Errorf("cdp.Ping: %s: status %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Browser{}, fmt.Errorf("cdp.Ping: read body: %w", err)
	}
	var b Browser
	if err := json.Unmarshal(body, &b); err != nil {
		return Browser{}, fmt.Errorf("cdp.Ping: decode body: %w", err)
	}
	return b, nil
}
