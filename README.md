# llm-cluster-router

> **MQ-style router + load balancer for multi-cloud, multi-cluster, multi-vendor LLM fleets.**
> OpenAI-compatible HTTP reverse-proxy with tiered routing, fair-share queuing, and optional
> end-to-end encrypted transport. Production-tested in single-tenant private clusters and
> multi-tenant pilot fleets.

[![CI](https://github.com/nfsarch33/llm-cluster-router/actions/workflows/ci.yml/badge.svg)](https://github.com/nfsarch33/llm-cluster-router/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/nfsarch33/llm-cluster-router)](https://goreportcard.com/report/github.com/nfsarch33/llm-cluster-router)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why

When you run multiple LLM inference backends (vLLM, Ollama, llama.cpp, hosted OpenAI
compatible APIs) across one or more clouds, regions, or vendors, you need:

- **One URL** for every client (Cursor, Claude Code, Codex CLI, Kilo Code, custom agents).
- **Fair-share queuing** so a single tenant cannot starve the cluster.
- **Tiered routing** (reasoning vs fast vs embed) with per-tier priority and weight.
- **Health-aware failover** so flapping nodes drop out of rotation faster than the
  health-check loop can react.
- **Per-upstream circuit breakers** to prevent cascading failures.
- **Vendor portability** — same config works against self-hosted GPU pools and
  hosted inference APIs.

`llm-cluster-router` is a single Go binary that fronts any mix of OpenAI-compatible
upstreams behind a single `/v1/chat/completions` and `/v1/models` endpoint.

## Features

- **OpenAI-compatible API** — drop-in `/v1/chat/completions` and `/v1/models` proxy.
- **Multi-cloud / multi-vendor** — route to self-hosted vLLM/Ollama plus hosted
  OpenAI-compatible APIs in a single config.
- **Tier-based routing** — assign nodes to tiers (reasoning, fast, embed, agent) with
  per-tier priority and weight.
- **Global queue + concurrency control** — configurable max queue depth and max
  concurrency protect upstreams from overload.
- **Per-tenant fair-share queuing** — sliding-window token bucket per tenant
  (keyed by `X-Tenant` header or bearer-token hash) prevents any single tenant
  from monopolising the cluster.
- **Health checking** — automatic probing with configurable thresholds; supports
  vLLM (`/health`), Ollama (`/v1/models`), and any HTTP 200-returning endpoint.
- **Per-upstream circuit breaker** — flapping nodes are dropped from rotation;
  5-failure threshold, 30s cooldown, exposed via `llm_router_circuit_state` gauge.
- **SSE streaming** — full Server-Sent Events pass-through for streaming completions.
- **Prometheus `/metrics`** — request latency + TTFT histograms (50ms..120s buckets),
  queue depth gauges, per-node health status, upstream error counters.
- **Bearer auth** — optional bearer token authentication for `/v1/*` endpoints.
- **Env var expansion** — `${ENV_VAR}` syntax in config YAML for secrets.
- **SIGHUP reload** — atomic config reload (nodes, auth token, timeouts,
  health-check tuning) without dropping inflight requests.
- **Optional encrypted transport** — AES-256-GCM application-layer channel
  (`HelixChannel`) for end-to-end encrypted HTTP between client and router.
  See [`docs/helixchannel-deployment.md`](docs/helixchannel-deployment.md).

## Quickstart

```bash
# Install
go install github.com/nfsarch33/llm-cluster-router@latest

# Or build from source
git clone https://github.com/nfsarch33/llm-cluster-router.git
cd llm-cluster-router
go build -o llm-cluster-router .

# Run with sample config
./llm-cluster-router serve -config router.sample.yml
```

## Configuration

Copy `router.sample.yml` and customise for your fleet:

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

# Per-tenant fair-share (disabled by default)
fair_share:
  enabled: false
  max_requests_per_tenant: 10
  window: 60s
  burst: 3

# Mix self-hosted and hosted upstreams behind the same /v1 endpoint
nodes:
  - name: selfhost-reasoning-27b
    url: http://<your-gpu-host>:8001
    tier: reasoning
    priority: 0
    weight: 4
    models: ["qwen3-27b"]
  - name: hosted-fast-api
    url: https://<your-vendor-host>/v1
    tier: fast
    priority: 1
    weight: 2
    models: ["<vendor-model-id>"]
    auth:
      env: VENDOR_API_KEY
      scheme: bearer
```

The router ships several reference configs in `configs/`:

- `router.sample.yml` — minimal local-only starting point.
- `router.fleet-2host.example.yml` — multi-host reference (use `your-host-1`,
  `your-host-2` placeholders for your fleet topology).
- `configs/router.minimax.live.yml` — operator-internal; **not for public mirroring**
  (see `docs/operator-internal.md`).

## Endpoints

| Endpoint | Description |
|---|---|
| `/v1/chat/completions` | OpenAI-compatible chat completions proxy |
| `/v1/models` | Aggregated model inventory from healthy upstreams |
| `/healthz` | Router health plus per-node status |
| `/metrics` | Prometheus metrics |
| `/debug/pprof/*` | Optional pprof (when `debug_addr` is set) |

## Grafana dashboard

Import `dashboards/llm-cluster-router.json` into Grafana 11+. The dashboard
exposes a `$datasource` template variable so it works in any Grafana org without
per-panel edits, plus `$model` and `$node` filters wired to the metrics the
router exports.

Panels:

- Healthy upstreams, inflight, queue depth, RPS (top-row stat panels)
- End-to-end latency p50 / p95 / p99 by model
- Time-to-first-byte (TTFT) p50 / p95 / p99 by model
- Requests/sec by node + status (stacked bars)
- Queue depth and inflight (timeseries)
- Per-node health (1 = healthy, 0 = unhealthy)
- Upstream health-probe p95 latency

A test in `dashboards/dashboard_test.go` enforces the dashboard references every
metric the router exports, so any future metric additions must update both the
router and the dashboard JSON in the same commit.

## Reload

Send `SIGHUP` to the router process to atomically swap config without dropping
inflight requests:

```bash
kill -HUP $(pgrep -f 'llm-cluster-router serve')
```

**What reloads:** `nodes`, `auth_token`, `defaults.request_timeout`,
`defaults.max_queue_depth`, `defaults.max_concurrency`, `health_check.*`.

**What still requires a process restart:** `listen`, `metrics_addr`, `debug_addr`
(listener sockets), `defaults.max_body_size` (bound at server boot).

A failed reload (file not found, YAML parse error, missing required node fields)
is rejected and the previous config stays in effect. Inflight requests continue
using the previous concurrency budget; new requests use the new one. Both
budgets coexist briefly during the swap and resolve naturally as the old
requests drain.

## Benchmark

```bash
./llm-cluster-router bench \
  -url http://127.0.0.1:8080 \
  -model <your-model> \
  -requests 8 \
  -concurrency 2 \
  -output benchmark-report.json
```

Reports include TTFT p50/p95, latency p50/p95, prompt and generation tokens/sec,
queue depth, and cancellation probe results.

## Tests

Two suites:

```bash
# Unit tests (run on every push, fast, default lane)
go test -race ./...

# Integration tests (build-tagged so the default lane stays fast)
go test -tags=integration -timeout=2m -count=1 -race -v -run TestIT_ ./...
```

The integration suite (`it_test.go`, `//go:build integration`) starts the router
in-process with mock OpenAI-compatible upstream servers
(`net/http/httptest.NewServer`) and exercises:

- `TestIT_NoStarvationUnderConcurrentLoad` — burst load from multiple X-Tenant
  producers; asserts every producer completes within ±20% of equal share.
- `TestIT_StreamingSSEPassthrough` — Server-Sent Events from upstream reach
  the client unchanged with a `[DONE]` terminator.
- `TestIT_FailoverWhenUpstreamReturns502` — when the primary upstream starts
  returning HTTP 502, traffic continues to flow via the fallback upstream.
- `TestIT_ModelsAggregation` — `/v1/models` aggregates inventory from every
  healthy upstream.
- `TestIT_PrometheusExpositionFormat` — `/metrics` exposes
  `llm_router_requests_total`, `_request_duration_seconds`, `_queue_depth`,
  `_inflight_requests`, and `_node_healthy` with the expected types and labels.

CI runs both suites on every push and PR — see `.github/workflows/ci.yml`.

## Security

- API keys in config support `${ENV_VAR}` expansion — **never hardcode secrets in YAML files**.
- The optional `HelixChannel` encrypted transport (`docs/helixchannel-deployment.md`)
  is recommended when the router sits between an untrusted network and your
  inference backends.
- Do not point this router at corporate or managed AI gateways you do not control.

## Documentation

- [`docs/helixchannel-deployment.md`](docs/helixchannel-deployment.md) — encrypted
  transport deployment, threat model, and operator config.
- [`docs/release-readiness.md`](docs/release-readiness.md) — release gate, ADR
  cross-links, and pre-deploy validation steps.
- [`CHANGELOG.md`](CHANGELOG.md) — version history.
- [`RELEASE-NOTES.md`](RELEASE-NOTES.md) — highlights per release.

## License

MIT — see [LICENSE](LICENSE).
