# llm-cluster-router

OpenAI-compatible HTTP reverse-proxy for multi-node vLLM and Ollama clusters with fair-share per-user queuing.

## Features

- **OpenAI-compatible API** — drop-in `/v1/chat/completions` and `/v1/models` proxy
- **Fair-share queues** — per-user sliding-window rate limiting prevents any single consumer from starving others
- **Multi-upstream** — route to multiple vLLM, Ollama, or any OpenAI-compatible backend
- **SSE streaming** — full Server-Sent Events pass-through for streaming completions
- **Tier-based routing** — assign nodes to tiers (agent, fast, reasoning) with priority and weight
- **Health checking** — automatic health probing with configurable thresholds; supports both vLLM (`/health`) and Ollama (`/v1/models`) backends
- **Prometheus `/metrics`** — request latency histograms, queue depth gauges, per-node health status, upstream error counters
- **Benchmark harness** — built-in `bench` subcommand with TTFT p50/p95, generation tokens/sec, and cancellation probes
- **GPU probing** — `probe-gpu` subcommand for NVIDIA GPU inventory, VRAM usage, and compute process bindings
- **Bearer auth** — optional bearer token authentication for `/v1/*` endpoints
- **Env var expansion** — `${ENV_VAR}` syntax in config YAML for secrets

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

## Security

> **Do not** point this router at corporate or managed AI gateways.
> This tool is designed for self-hosted local GPU clusters only.

API keys in config support `${ENV_VAR}` expansion — never hardcode secrets in YAML files.

## License

MIT — see [LICENSE](LICENSE).
