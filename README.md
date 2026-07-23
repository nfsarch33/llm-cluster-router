# llm-cluster-router

OpenAI-compatible HTTP reverse-proxy for multi-node vLLM and Ollama clusters
with global concurrency limiting, priority-based routing, and the optional
**HelixChannel** AES-256-GCM encrypted channel for production wire
deployment.

> **Encrypted production wire (HelixChannel)** — The router ships an
> AES-256-GCM encrypted channel (`HELIXCHANNEL_ENABLED=true`) for the
> production wire. The dual-listener design (AES/mTLS + legacy plain
> HTTP) is standardised by
> [ADR-085](https://github.com/nfsarch33/cursor-global-kb/blob/main/adrs/ADR-085-helixchannel-prod-wire.md).
> For the public hostname (`helixchannel.cylrl.dev`), DNS + Let's Encrypt + nginx
> reverse-proxy procedure, threat model, and operational runbooks, see
> [`docs/helixchannel.md`](docs/helixchannel.md) and
> [`docs/helixchannel-deployment.md`](docs/helixchannel-deployment.md).

## Features

- **OpenAI-compatible API** — drop-in `/v1/chat/completions` and `/v1/models` proxy
- **Global queue + concurrency control** — configurable max queue depth and
  max concurrency protect upstreams from overload
- **Per-user fair-share queuing** — sliding-window token bucket per user
  prevents any single user from monopolising the cluster
- **Multi-upstream** — route to multiple vLLM, Ollama, or any
  OpenAI-compatible backend
- **SSE streaming** — full Server-Sent Events pass-through for streaming
  completions
- **Tier-based routing** — assign nodes to tiers (agent, fast, reasoning)
  with priority and weight
- **Health checking** — automatic health probing with configurable thresholds
- **Per-upstream circuit breaker** — flapping nodes are dropped from rotation
- **Prometheus `/metrics`** — request latency + TTFT histograms, queue depth
  gauges, per-node health, upstream error counters
- **Benchmark harness** — built-in `bench` subcommand
- **GPU probing** — `probe-gpu` subcommand for NVIDIA GPU inventory
- **Bearer auth** — optional bearer token authentication for `/v1/*` endpoints
- **Env var expansion** — `${ENV_VAR}` syntax in config YAML for secrets
- **SIGHUP reload** — atomic config reload without dropping inflight requests
- **HelixChannel encryption** — application-layer AES-256-GCM channel for
  production wire deployment (`HELIXCHANNEL_ENABLED=true`)
- **`helixchannel` CLI** — `doctor`, `version`, `factory-probe`, `key-check`,
  `header-stamp`, `endpoint-check` subcommands (`cmd/helixchannel/`)

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

# Optional HelixChannel (AES-256-GCM production wire)
helixchannel:
  enabled: true
  listen: ":14443"
  aes_key_file: "/run/secrets/helixchannel-aes.key"
```

See [`router.sample.yml`](router.sample.yml) for the full annotated example
and [`docs/helixchannel.md`](docs/helixchannel.md) for HelixChannel-specific
configuration (key generation, channel preference, dual-listener semantics).

## Endpoints

| Endpoint | Description |
|---|---|
| `/v1/chat/completions` | OpenAI-compatible chat completions proxy |
| `/v1/models` | Aggregated model inventory from healthy upstreams |
| `/healthz` | Router health plus per-node status |
| `/metrics` | Prometheus metrics |
| `/debug/pprof/*` | Optional pprof (when `debug_addr` is set) |
| `/helixchannel/doctor` | HelixChannel release-gate JSON envelope |

## Reload

Send `SIGHUP` to the router process to atomically swap config without
dropping inflight requests:

```bash
kill -HUP $(pgrep -f 'llm-cluster-router serve')
```

What reloads: `nodes`, `auth_token`, `defaults.request_timeout`,
`defaults.max_queue_depth`, `defaults.max_concurrency`, `health_check.*`,
`helixchannel.enabled`.

What still requires a process restart: `listen`, `metrics_addr`,
`debug_addr`, `defaults.max_body_size`, `helixchannel.listen`,
`helixchannel.aes_key_file`.

## Grafana dashboard

Import `dashboards/llm-cluster-router.json` into Grafana 11+. The dashboard
exposes `$datasource`, `$model`, and `$node` template variables plus panels
for healthy upstreams, end-to-end latency, TTFT, queue depth, and per-node
health. A test in `dashboards/dashboard_test.go` enforces the dashboard
references every metric the router exports.

## Benchmark

```bash
./llm-cluster-router bench \
  -url http://127.0.0.1:8080 \
  -model qwen3.5-27b \
  -requests 8 \
  -concurrency 2 \
  -output benchmark-report.json
```

Reports include TTFT p50/p95, latency p50/p95, prompt and generation
tokens/sec, queue depth, and cancellation probe results.

## Tests

Two suites:

```bash
# Unit tests (run on every push, fast, default lane)
go test -race ./...

# Integration tests (build-tagged so the default lane stays fast)
go test -tags=integration -timeout=2m -count=1 -race -v -run TestIT_ ./...
```

See [`docs/testing.md`](docs/testing.md) for the full test catalogue
(`TestIT_NoStarvationUnderConcurrentLoad`,
`TestIT_StreamingSSEPassthrough`,
`TestIT_FailoverWhenUpstreamReturns502`, etc.) and CI workflow reference
(`.github/workflows/ci.yml`).

## Security

> **Do not** point this router at corporate or managed AI gateways.
> This tool is designed for self-hosted local GPU clusters only.

API keys in config support `${ENV_VAR}` expansion — never hardcode secrets
in YAML files. The HelixChannel AES key (`HELIXCHANNEL_KEY` /
`helixchannel.aes_key_file`) must be 32 bytes; generate with
`openssl rand -hex 32` and load from a secret store — never commit it.

## Release readiness

The one-command release gate (`scripts/release-gate.sh`) runs every
Lightsail-readiness check from
[ADR-083](https://github.com/nfsarch33/cursor-global-kb/blob/main/adrs/ADR-083-llm-cluster-router-lightsail-threat-model.md)
and reports a single GREEN/RED verdict. It is the canonical pre-deploy hook
for any Lightsail release. Full procedure, ADR cross-links, and
port-443 reverse-proxy runbook:
[`docs/release-readiness.md`](docs/release-readiness.md).

```bash
# Pre-deploy: validate the AES key + observability + ADR-085 gates
go build -o helixchannel ./cmd/helixchannel
./helixchannel doctor
```

## License

MIT — see [LICENSE](LICENSE).