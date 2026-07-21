# llm-cluster-router

OpenAI-compatible HTTP reverse-proxy for multi-node vLLM and Ollama clusters with global concurrency limiting and priority-based routing.

> **HelixChannel quickstart** — Build the doctor probe and validate
> release-readiness before deploying:
> ```bash
> go build -o helixchannel ./cmd/helixchannel
> ./helixchannel doctor   # JSON envelope: release-gate + ADR-085 + AES key + observability
> ```
> See [`cmd/helixchannel/`](cmd/helixchannel/) for `version`, `factory-probe`,
> `key-check`, and `header-stamp` subcommands.

> **Production ingress (v18714+)** — The HelixChannel production wire
> reaches operators and pilot consumers via `TCP/443` (TLS-terminating
> nginx → `127.0.0.1:14443` on the Lightsail instance), per
> [ADR-086](../cursor-global-kb/adrs/ADR-086-helixchannel-port-443-migration.md).
> The application-layer AES-256-GCM channel is unchanged; only the
> transport moved from SSH-22 (pilot) to TLS/443 (production pilot).
> Canonical reverse-proxy runbook:
> [`cursor-global-kb/sop/lightsail-port-443-reverse-proxy.md`](../cursor-global-kb/sop/lightsail-port-443-reverse-proxy.md).

## HelixChannel (encrypted dual-listener)

HelixChannel is the operator-facing name for the AES-256-GCM
application-layer encrypted HTTP channel that fronts every router
deployment. It is the brand name for the dual-listener design
introduced incrementally across v18704-v18710 and standardised by
ADR-085 (`adrs/ADR-085-helixchannel-prod-wire.md` in the
`cursor-global-kb` repo).

### Threat model

- Wire captures on the path between the router and the upstreams
  see ciphertext only; plaintext LLM prompts, completions, and
  bearer tokens never appear on the wire.
- An attacker who can R/W to the TCP socket cannot silently tamper
  with a request because every frame is AES-GCM authenticated.
  Tampering events are counted in
  `llm_cluster_router_decrypt_failed_total{listener="aes-mtls"}`
  and surface as an incident in Grafana.

### ListenerFactory contract

The router owns a `proxy.ListenerFactory` per channel. The
factory's `Channel()` returns a stable identifier (currently
`"aes-mtls"`) used for metrics, logging, and config keys. The
factory's `Listen(ctx, addr)` returns a bound `net.Listener` plus
the `ServeLoop` that should be run for it. The production
`main.go` constructs the AES/mTLS factory by default; the
`HELIXCHANNEL_ENABLED=false` env override keeps the legacy plain
HTTP listener for back-compat.

### Operator-facing config

| Key | Default | Notes |
| --- | --- | --- |
| `HELIXCHANNEL_ENABLED` | `true` | Toggle the AES/mTLS factory. `false` keeps the legacy plain HTTP listener for back-compat. |
| `HELIXCHANNEL_KEY` | demo placeholder | 32-byte AES-256 key. Production callers load this from a secret store (see `internal/proxy/listener.go`). |
| `HELIXCHANNEL_LISTEN` | `cfg.Listen` | Override the bind address (host:port). Falls back to the legacy `listen:` YAML key. |

The response header `HelixChannel-Version: <version>` is stamped
on every reply; `curl -I https://host/` is the canonical proof-of-name
artifact.

### Additive metric families (v18712-1)

Both legacy and new label keys are populated by the dual-listener
ServeLoop, so existing Grafana panels keep working:

- `llm_cluster_router_connections_total{listener="aes-mtls",direction="in"}`
  — legacy channel label
- `llm_cluster_router_helixchannel_connections_total{direction="in"}`
  — operator-facing alias

## Features

- **OpenAI-compatible API** — drop-in `/v1/chat/completions` and `/v1/models` proxy
- **Global queue + concurrency control** — configurable max queue depth and max concurrency protect upstreams from overload
- **Per-user fair-share queuing** — sliding-window token bucket per user (keyed by `X-User` header or bearer token hash) prevents any single user from monopolising the cluster (v0.2.0)
- **Multi-upstream** — route to multiple vLLM, Ollama, or any OpenAI-compatible backend
- **SSE streaming** — full Server-Sent Events pass-through for streaming completions
- **Tier-based routing** — assign nodes to tiers (agent, fast, reasoning) with priority and weight
- **Health checking** — automatic health probing with configurable thresholds; supports both vLLM (`/health`) and Ollama (`/v1/models`) backends
- **Per-upstream circuit breaker** — flapping nodes are dropped from rotation faster than the health-check loop notices; 5-failure threshold, 30s cooldown, exposed via `llm_router_circuit_state` gauge
- **Prometheus `/metrics`** — request latency + TTFT histograms (LLM-tuned 50ms..120s buckets), queue depth gauges, per-node health status, upstream error counters
- **Benchmark harness** — built-in `bench` subcommand with TTFT p50/p95, generation tokens/sec, and cancellation probes
- **GPU probing** — `probe-gpu` subcommand for NVIDIA GPU inventory, VRAM usage, and compute process bindings
- **Bearer auth** — optional bearer token authentication for `/v1/*` endpoints
- **Env var expansion** — `${ENV_VAR}` syntax in config YAML for secrets
- **SIGHUP reload** — atomic config reload (nodes, auth token, timeouts, health-check tuning) without dropping inflight requests; `listen`, `metrics_addr`, `debug_addr`, and `max_body_size` still require restart

## Quickstart

```bash
go install github.com/nfsarch33/llm-cluster-router@latest

# Or build from source
git clone https://github.com/nfsarch33/llm-cluster-router.git
cd llm-cluster-router
go build -o llm-cluster-router .

# Run with sample config
./llm-cluster-router serve -config router.sample.yml
```

## Configuration

Copy `router.sample.yml` and customise:

```yaml
listen: ":8080"
metrics_addr: ":9091"
log_level: info

# Optional bearer auth for /v1/* endpoints
# auth_token: ${ROUTER_AUTH_TOKEN}

defaults:
  max_queue_depth: 8
  max_concurrency: 2
  request_timeout: 120s

health_check:
  interval: 15s
  timeout: 5s
  path: /health
  unhealthy_threshold: 3
  healthy_threshold: 1

# Per-user fair-share (disabled by default)
fair_share:
  enabled: false
  max_requests_per_user: 10
  window: 60s
  burst: 3

nodes:
  - name: gpu-0-agent
    url: http://127.0.0.1:8001
    tier: agent
    priority: 0
    weight: 4
    models: ["qwen3.5-27b"]
  - name: gpu-1-fast
    url: http://127.0.0.1:8002
    tier: fast
    priority: 0
    weight: 2
    models: ["qwen3.5-9b"]
```

## Endpoints

| Endpoint | Description |
|---|---|
| `/v1/chat/completions` | OpenAI-compatible chat completions proxy |
| `/v1/models` | Aggregated model inventory from healthy upstreams |
| `/healthz` | Router health plus per-node status |
| `/metrics` | Prometheus metrics |
| `/debug/pprof/*` | Optional pprof (when `debug_addr` is set) |

## Grafana dashboard

Import `dashboards/llm-cluster-router.json` into Grafana 11+. The
dashboard exposes a `$datasource` template variable so it works in
any Grafana org without per-panel edits, plus `$model` and `$node`
filters wired to the metrics the router exports.

Panels:

- Healthy upstreams, inflight, queue depth, RPS (top-row stat panels)
- End-to-end latency p50 / p95 / p99 by model
- Time-to-first-byte (TTFT) p50 / p95 / p99 by model
- Requests/sec by node + status (stacked bars)
- Queue depth and inflight (timeseries)
- Per-node health (1 = healthy, 0 = unhealthy)
- Upstream health-probe p95 latency

A test in `dashboards/dashboard_test.go` enforces the dashboard
references every metric the router exports, so any future metric
additions must update both the router and the dashboard JSON in
the same commit.

## Reload

Send `SIGHUP` to the router process to atomically swap config without
dropping inflight requests:

```bash
kill -HUP $(pgrep -f 'llm-cluster-router serve')
```

What reloads:

- `nodes` (add, remove, change models, weights, priority, API keys)
- `auth_token` (rotate bearer token)
- `defaults.request_timeout`, `defaults.max_queue_depth`,
  `defaults.max_concurrency`
- `health_check.*` (interval, timeout, path, thresholds)

What still requires a process restart:

- `listen`, `metrics_addr`, `debug_addr` (listener sockets)
- `defaults.max_body_size` (bound at server boot)

A failed reload (file not found, YAML parse error, missing required
node fields) is rejected and the previous config stays in effect.
Inflight requests continue using the previous concurrency budget;
new requests use the new one. Both budgets coexist briefly during
the swap and resolve naturally as the old requests drain.

## Benchmark

```bash
./llm-cluster-router bench \
  -url http://127.0.0.1:8080 \
  -model qwen3.5-27b \
  -requests 8 \
  -concurrency 2 \
  -output benchmark-report.json
```

Reports include TTFT p50/p95, latency p50/p95, prompt and generation tokens/sec, queue depth, and cancellation probe results.

## Tests

Two suites:

```bash
# Unit tests (run on every push, fast, default lane)
go test -race ./...

# Integration tests (build-tagged so the default lane stays fast)
go test -tags=integration -timeout=2m -count=1 -race -v -run TestIT_ ./...
```

The integration suite (`it_test.go`, `//go:build integration`) starts the
router in-process with mock OpenAI-compatible upstream servers
(`net/http/httptest.NewServer`) and exercises:

- `TestIT_NoStarvationUnderConcurrentLoad` — burst load from multiple
  X-User producers; asserts every producer completes within ±20% of
  equal share (no header-based bias).
- `TestIT_StreamingSSEPassthrough` — Server-Sent Events from upstream
  reach the client unchanged with a `[DONE]` terminator.
- `TestIT_FailoverWhenUpstreamReturns502` — when the primary upstream
  starts returning HTTP 502, traffic continues to flow via the fallback
  upstream advertising the same model.
- `TestIT_ModelsAggregation` — `/v1/models` aggregates inventory from
  every healthy upstream.
- `TestIT_PrometheusExpositionFormat` — `/metrics` exposes
  `llm_router_requests_total`, `_request_duration_seconds`,
  `_queue_depth`, `_inflight_requests`, and `_node_healthy` with the
  expected types and labels.

CI runs both suites on every push and PR — see `.github/workflows/ci.yml`.

## Security

> **Do not** point this router at corporate or managed AI gateways.
> This tool is designed for self-hosted local GPU clusters only.

API keys in config support `${ENV_VAR}` expansion — never hardcode secrets in YAML files.

## Lightsail release readiness

See [`docs/release-readiness.md`](docs/release-readiness.md) for the full
release gate (`scripts/release-gate.sh`), ADR-083 / ADR-085 cross-links, and
Lightsail port-443 reverse-proxy procedure.

Quick validation: build `cmd/helixchannel` and run `./helixchannel doctor`
to confirm release-readiness checks before deploying.

## License

MIT — see [LICENSE](LICENSE).
