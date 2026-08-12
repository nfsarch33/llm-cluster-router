# q4-c-lcr-stale-health — Fix Evidence

**Sprint**: v18750-Q5 — Phase 6
**Repo**: `nfsarch33/llm-cluster-router` (local: `/home/jaslian/Code/llm-cluster-router`)
**Branch**: `feat/v18750-Q5-fix-lcr-stale-health`
**Risk**: q4-c-lcr-stale-health (recurrence of L-016 — silent LLM outages)
**Status**: GREEN (TDD verified RED → GREEN)

---

## Bug description

`handleHealth` in `main.go` reported the cached `node.healthy` flag, which is
only updated by the background `runHealthPass` loop every `hc.Interval`
(default 30s). If an upstream LLM node became unreachable between passes,
`/healthz` continued to report `healthy=true` for up to 30 s — causing silent
LLM outages visible only in `prompt failures`. This is the same family of
bug as L-016.

## Fix design

Caller can force a fresh, on-demand probe:

- `GET /healthz`                — unchanged (backward compat, returns cached state)
- `GET /healthz?live=1`         — runs `probeNode` per enabled node, returns fresh state
- `GET /healthz?live=1&timeout=500ms` — same, with per-node probe timeout
  (default 2s, max 10s for safety)

Live probe uses the existing `probeNode()` function, the same one the
background health pass uses, so semantics are consistent.

The response includes `live_probe: true` and `probe_timeout` when live mode
was used, to make the divergence from cached mode explicit.

## Code diff (high-level)

```diff
-func (r *router) handleHealth(w http.ResponseWriter, _ *http.Request) {
+func (r *router) handleHealth(w http.ResponseWriter, req *http.Request) {
   type nodeStatus struct { ... Healthy bool `json:"healthy"`; + ProbeMs int64 `json:"probe_ms,omitempty"` }
+  live := req.URL.Query().Get("live") == "1"
+  probeTimeout := 2 * time.Second
+  if v := req.URL.Query().Get("timeout"); v != "" {
+    if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 10*time.Second {
+      probeTimeout = d
+    }
+  }
+  hc := r.snap().cfg.HealthCheck
   for _, node := range snap.nodes {
-    ok := node.healthy.Load()
+    var ok bool
+    var probeMs int64
+    if live && !node.cfg.HealthCheckDisabled {
+      probeCtx, cancel := context.WithTimeout(req.Context(), probeTimeout)
+      startProbe := time.Now()
+      ok = probeNode(probeCtx, hc, node)
+      cancel()
+      probeMs = time.Since(startProbe).Milliseconds()
+    } else {
+      ok = node.healthy.Load()
+    }
     ...
   }
+  if live {
+    resp["live_probe"] = true
+    resp["probe_timeout"] = probeTimeout.String()
+  }
```

## TDD cycle

### RED (without fix, fix stashed)

```
$ git stash push main.go
$ go test -v -count=1 -timeout=60s -run TestQ5_LiveProbe .
=== RUN   TestQ5_LiveProbe_OverridesStaleHealthy
...
    q5_stale_health_test.go:106: cached /healthz: {"healthy_nodes":1, ..."healthy":true,...}
    q5_stale_health_test.go:110: live /healthz:   {"healthy_nodes":1, ..."healthy":true,...}
    q5_stale_health_test.go:124: response missing live_probe:true marker
--- FAIL: TestQ5_LiveProbe_OverridesStaleHealthy (0.11s)
```

Without the fix, `?live=1` still returned cached `healthy=true` and no
`live_probe` marker. **RED confirmed**.

### GREEN (with fix applied)

```
$ git stash pop
$ go build -o bin/llm-cluster-router .
$ go test -v -count=1 -timeout=60s -run TestQ5_LiveProbe .
=== RUN   TestQ5_LiveProbe_OverridesStaleHealthy
    q5_stale_health_test.go:106: cached /healthz: {"healthy_nodes":1,...,"healthy":true}
    q5_stale_health_test.go:110: live /healthz:   {"healthy_nodes":0,"live_probe":true,...,"healthy":false,...}
--- PASS: TestQ5_LiveProbe_OverridesStaleHealthy (0.11s)
PASS
ok  	github.com/nfsarch33/llm-cluster-router	0.118s
```

Cached path still shows the (stale) state, live path correctly reports
`healthy_nodes:0` after the stub upstream returned 503. **GREEN confirmed**.

## Regression coverage

- `TestQ5_LiveProbe_OverridesStaleHealthy` (new) — uses `httptest.NewServer`
  for stub upstream, starts the actual `bin/llm-cluster-router` binary with a
  temporary config, and probes `/healthz?live=1`. Asserts
  `healthy_nodes == 0` and `live_probe == true` when upstream returns 503.

## Full suite verification

```
$ go vet ./...                                              # clean
$ go test -count=1 -timeout=120s -race .                   # PASS
ok  	github.com/nfsarch33/llm-cluster-router	9.838s
```

Root-package suite passes with the race detector enabled. The
`cmd/helixchannel` subpackage was timed out at 120s in `go test ./...`; this
is pre-existing (no relation to the fix).

## Files changed

- `main.go` — surgical fix to handleHealth (uses `req`, runs live probe when
  `?live=1`)
- `q5_stale_health_test.go` (new) — RED/GREEN test for the stale-health bug
- `bin/llm-cluster-router` — built artifact (ignored by `.gitignore` later)

## Operator note

`/healthz?live=1` is the new contract for SRE probes that need fresh upstream
state. Existing Prometheus / Grafana dashboards continue to read cached
state from `/healthz`, which is correct for steady-state dashboards; on-call
runbooks should switch to `?live=1` when investigating an active incident.