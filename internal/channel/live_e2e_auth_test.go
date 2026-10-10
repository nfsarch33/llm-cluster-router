//go:build live_e2e

// Live security-boundary regressions for the reverse-proxy gateway leg.
//
// These lock in the v18771 hardening AGAINST THE REAL EDGE: the open-relay that
// was closed (an anonymous caller reaching a paid upstream with the server key),
// the X-HLXN-Token rename, and the route-table disclosure fix. Each is a SKIP,
// never a fail, when its inputs are absent, so the suite is safe in any lane.
//
//	go test -tags=live_e2e -count=1 -v -run TestLive_ ./internal/channel/
package channel

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// refusalEnvelope is the JSON body the reverse-proxy leg returns on a 401.
type refusalEnvelope struct {
	Error  string   `json:"error"`
	Hint   string   `json:"hint"`
	Header string   `json:"header"`
	Routes []string `json:"routes"`
}

// TestLive_ReverseProxyAuthBoundary is the open-relay regression, verified from
// OUTSIDE the edge. This is the exact class that made the pilot a funded relay:
// a caller with no gateway token, or the wrong one, must be refused at the
// gateway and reach no upstream. The status + error code are the observable
// proof from a client that cannot see the upstream directly.
func TestLive_ReverseProxyAuthBoundary(t *testing.T) {
	base := liveBase(t)
	token := liveGatewayToken(t)
	c := liveClient()

	get := func(setToken func(*http.Request)) (int, refusalEnvelope, []byte) {
		req, _ := http.NewRequest(http.MethodGet, base+"/minimax/v1/models", nil)
		if setToken != nil {
			setToken(req)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET /minimax/v1/models: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var env refusalEnvelope
		_ = json.Unmarshal(body, &env)
		return resp.StatusCode, env, body
	}

	t.Run("no token is refused as required, not invalid", func(t *testing.T) {
		code, env, body := get(nil)
		if code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body: %.200s", code, body)
		}
		if env.Error != "gateway_token_required" {
			t.Errorf("error = %q, want gateway_token_required", env.Error)
		}
		if len(env.Routes) != 0 {
			t.Errorf("refusal leaked the route table to an anonymous caller: %v", env.Routes)
		}
		if strings.Contains(string(body), "minimax") && env.Error == "" {
			t.Errorf("body looks like a provider response — the call may have reached the upstream: %.200s", body)
		}
	})

	t.Run("wrong token is refused as invalid, not required", func(t *testing.T) {
		code, env, body := get(func(r *http.Request) {
			r.Header.Set(GatewayTokenHeader, "not-the-real-token-"+strings.Repeat("x", 48))
		})
		if code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body: %.200s", code, body)
		}
		if env.Error != "gateway_token_invalid" {
			t.Errorf("error = %q, want gateway_token_invalid (a stale credential must be distinguishable from a missing one)", env.Error)
		}
	})

	t.Run("the OLD header name is refused, proving the rename is deployed", func(t *testing.T) {
		code, env, _ := get(func(r *http.Request) {
			r.Header.Set("X-HelixChannel-Token", token) // the pre-v18771 spelling
		})
		if code != http.StatusUnauthorized || env.Error != "gateway_token_required" {
			t.Errorf("old header X-HelixChannel-Token was accepted (status=%d error=%q) — the rename regressed, or an alias was reintroduced", code, env.Error)
		}
	})

	t.Run("the correct token is served", func(t *testing.T) {
		code, _, body := get(func(r *http.Request) { withGatewayToken(r, token) })
		if code != http.StatusOK {
			t.Fatalf("valid-token status = %d, want 200; body: %.200s", code, body)
		}
		if !strings.Contains(string(body), `"object"`) {
			t.Errorf("served body does not look like a provider list: %.200s", body)
		}
	})
}

// TestLive_TokenHeaderIsHLXN pins the deployed header name to X-HLXN-Token, in
// both the code constant and what the live edge actually challenges with. If a
// rollback or a re-alias put the old name back, this fails loudly rather than
// letting docs and reality drift.
func TestLive_TokenHeaderIsHLXN(t *testing.T) {
	base := liveBase(t)
	if GatewayTokenHeader != "X-HLXN-Token" {
		t.Fatalf("GatewayTokenHeader = %q, want X-HLXN-Token", GatewayTokenHeader)
	}
	resp, err := liveClient().Get(base + "/minimax/v1/models") // anonymous → a challenge
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `header="X-HLXN-Token"`) {
		t.Errorf("WWW-Authenticate = %q, want it to name header=\"X-HLXN-Token\"", got)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var env refusalEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("refusal body not JSON: %v (%.200s)", err, body)
	}
	if env.Header != "X-HLXN-Token" {
		t.Errorf("refusal body header = %q, want X-HLXN-Token", env.Header)
	}
}

// TestLive_HealthzHidesRouteTableFromAnonymous is the disclosure regression:
// after the hardening, anonymous /healthz names the posture (proxy_auth) but
// must NOT enumerate the route table or the connect flag — those moved behind
// the token. TestLive_HealthzReportsRouteSet covers the with-token half.
func TestLive_HealthzHidesRouteTableFromAnonymous(t *testing.T) {
	base := liveBase(t)
	resp, err := liveClient().Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous /healthz status = %d, want 200", resp.StatusCode)
	}
	// Decode into a raw map so we can assert on PRESENCE, not just zero-values:
	// an omitted "routes" and a present-but-empty "routes" are different leaks.
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("healthz not JSON: %v", err)
	}
	if _, leaked := raw["routes"]; leaked {
		t.Errorf("anonymous /healthz exposes the route table: %v", raw["routes"])
	}
	if _, leaked := raw["connect"]; leaked {
		t.Errorf("anonymous /healthz exposes the connect flag: %v", raw["connect"])
	}
	if _, ok := raw["proxy_auth"]; !ok {
		t.Error("anonymous /healthz should still name the auth posture in proxy_auth")
	}
	if svc, ok := raw["service"]; !ok || strings.Trim(string(svc), `"`) != "helixchannel-gateway" {
		t.Errorf("service = %s, want \"helixchannel-gateway\"", svc)
	}
}
