# llm-cluster-router

An OpenAI-compatible router that spreads LLM traffic across a fleet of local and hosted model servers, with health checks, queueing, fair-share scheduling and circuit breaking.

Point any OpenAI-compatible client at one endpoint. The router picks a healthy upstream, applies per-tenant limits, and keeps a slow or dead node from taking the rest down with it.

## Table of Contents

- [Background](#background)
- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [HelixChannel](#helixchannel)
- [Observability](#observability)
- [Development](#development)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Background

A homelab or small cluster ends up with several inference endpoints: a couple of GPU boxes running llama.cpp or vLLM, an Ollama instance, and one or two hosted APIs for the jobs local hardware cannot handle. Clients should not have to know which is which, and one saturated node should not stall everything else.

`llm-cluster-router` sits in front of them and presents a single OpenAI-compatible API. It tracks upstream health, bounds queue depth and concurrency per node, sheds load when a node degrades, and shares capacity between callers instead of letting one client monopolise a GPU.

## Features

- **OpenAI-compatible surface** — `/v1/chat/completions`, `/v1/models`, `/v1/embeddings`; existing SDKs and tools work unchanged.
- **Health-aware routing** — periodic probes with configurable thresholds; unhealthy nodes leave the pool and rejoin automatically.
- **Bounded concurrency and queueing** — per-node `max_concurrency` and `max_queue_depth`, so a slow upstream applies backpressure instead of exhausting memory.
- **Circuit breaking** — repeated failures trip a breaker with a cooldown, and `/readyz` reflects it.
- **Fair-share scheduling** — optional per-user weighting so one caller cannot starve the others.
- **Tiered routing** — route by an `X-Tier` header to steer heavy jobs at bigger nodes.
- **Hot reload** — `SIGHUP` re-reads the config; nodes can be added or drained without dropping traffic.
- **Prometheus metrics and Grafana dashboards** — request rates, latencies, queue depth, breaker state.
- **[HelixChannel](#helixchannel)** — an optional encrypted egress path that keeps provider API keys off client machines and off the wire.

## Install

Prebuilt binaries are published on the [releases page](https://github.com/nfsarch33/llm-cluster-router/releases).

From source (Go 1.25 or newer):

```bash
git clone https://github.com/nfsarch33/llm-cluster-router
cd llm-cluster-router
go build -o llm-router .
```

With a container runtime:

```bash
podman build -t llm-cluster-router:local -f Containerfile .
```

## Usage

```bash
# Start with a config file
./llm-router serve -c router.sample.yml

# Then use it like any OpenAI endpoint
curl http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3-27b","messages":[{"role":"user","content":"hello"}]}'
```

Point a client at it by setting the base URL, for example `OPENAI_BASE_URL=http://127.0.0.1:8787/v1`.

Other subcommands:

```bash
./llm-router bench      # load-test the configured nodes
./llm-router probe-gpu  # report GPU capacity discovered on upstream hosts
```

## Configuration

The router reads a YAML file. A minimal example:

```yaml
listen: ":8787"
metrics_addr: ":9091"
log_level: info

defaults:
  max_queue_depth: 8
  max_concurrency: 2
  request_timeout: 120s
  circuit:
    threshold: 5
    cooldown: 30s

nodes:
  - name: gpu-1
    url: http://10.0.0.10:8001
    tier: large
    models: [qwen3-27b]
  - name: ollama
    url: http://10.0.0.11:11434
    tier: small
    models: [qwen3-8b, nomic-embed-text]

health_check:
  interval: 15s
  timeout: 3s
  path: /health
  unhealthy_threshold: 3
  healthy_threshold: 2
```

See [`router.sample.yml`](router.sample.yml) for the full annotated schema, including fair-share and per-tenant options. Secrets are referenced as `${ENV_VAR}` and resolved at load time; the router never stores credentials in its own config.

Send `SIGHUP` to reload after an edit:

```bash
kill -HUP "$(pgrep -f 'llm-router serve')"
```

## Endpoints

| Path | Purpose |
|---|---|
| `/v1/chat/completions`, `/v1/models`, `/v1/embeddings` | OpenAI-compatible API |
| `/healthz` | Liveness plus healthy-node count |
| `/readyz` | Readiness; fails while every node is unhealthy or breakers are open |
| `/metrics` | Prometheus exposition (on `metrics_addr`) |

## HelixChannel

HelixChannel is an optional component for a specific problem: getting agent traffic to a provider **without putting provider API keys on every client machine**, and without trusting the network in between.

A gateway runs on a host you control. Clients send requests with a placeholder credential; the gateway swaps in the real key held server-side and forwards to the provider over TLS. Adding, removing or switching off a provider is an edit to the gateway's config file:

```yaml
routes:
  - name: codex
    prefix: /codex/
    upstream: https://api.openai.com
    auth: inject          # server-held key replaces the client's placeholder
    key_file: /run/secrets/openai.key
    enabled: false        # feature flag — flip to true to switch it on
```

Two modes cover the clients you are likely to have:

- **`inject`** — the gateway supplies the credential. Right for API-key providers, and the reason a laptop never needs a copy of the key.
- **`passthrough`** — the caller's own credential is forwarded untouched. Right for clients holding a session token that must terminate at the provider.

For clients that cannot be pointed at a rewritten base URL without losing functionality, the gateway also offers an authenticated, allowlisted **CONNECT tunnel**: it pipes bytes without terminating the inner TLS, so the client's session stays end-to-end encrypted and opaque to every hop, gateway included.

```bash
# Server: one process, all routes
helixchannel gateway --config /etc/helixchannel/gateway.yml

# Client: a loopback proxy the agent points HTTPS_PROXY at
helixchannel proxy --gateway gateway.example.com:8443 --token-file ~/.config/helixchannel/connect.token
```

Guides: **[HelixChannel](docs/helixchannel.md)** · **[Kilo Code setup](docs/kilo-code-setup.md)** · **[Claude Code setup](docs/claude-code-setup.md)**

## Observability

Prometheus metrics are exposed on `metrics_addr`, covering request counts and latency by node and model, queue depth, in-flight requests, breaker state and health transitions. Dashboards live in [`dashboards/`](dashboards/); import the JSON into Grafana and point it at your Prometheus.

## Development

```bash
go test ./...                       # unit tests
go test -race ./...                 # race detector
go test -tags=integration ./...     # integration lane
golangci-lint run                   # lint
```

Integration and end-to-end tests are behind build tags so the default lane stays fast. Tests that need a live upstream skip rather than fail when credentials are absent, so a fresh clone is green without any secrets.

## Security

- Credentials are read from environment variables or files, never from argv, and are not written to logs. Audit records carry request metadata only — no bodies, no headers, no keys.
- The HelixChannel gateway replaces (rather than appends to) the caller's `Authorization` header in `inject` mode, so a client cannot reach the upstream as a different account.
- The CONNECT tunnel requires a shared token and an explicit host allowlist; an empty allowlist is rejected at startup rather than becoming an open relay.
- Container images run as a non-root user with a read-only root filesystem and no added capabilities.

To report a vulnerability, open a [security advisory](https://github.com/nfsarch33/llm-cluster-router/security/advisories/new) rather than a public issue.

## Contributing

Issues and pull requests are welcome. Please include tests with behaviour changes, keep `go test ./...` and `golangci-lint run` green, and use [Conventional Commits](https://www.conventionalcommits.org/) for commit subjects.

## License

[MIT](LICENSE) © nfsarch33
