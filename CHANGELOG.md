# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-05-25

### Added
- Per-user fair-share rate limiting via sliding-window token bucket (`internal/fairshare/`)
- Keyed by `X-User` header with fallback to bearer token hash
- Configurable `max_requests_per_user`, `window`, and `burst` via `fair_share:` config section
- Prometheus metric `llm_router_fairshare_rejected_total` by user
- Integration tests: `TestIT_FairShareNoStarvation`, `TestIT_FairShareRejectsHeavyUser`

### Changed
- Fair-share is disabled by default (additive, no regression on existing deployments)
- Layers after global semaphore: global cap = backpressure, per-user = starvation prevention

## [0.1.0] - 2026-05-02

### Added
- Initial public release; extracted from nfsarch33/ironclaw-ops
- OpenAI-compatible `/v1/chat/completions` and `/v1/models` proxy
- Global queue + concurrency control with bounded queue depth
- Multi-upstream routing with tier, priority, and weight controls
- SSE streaming pass-through for chat completions
- Automatic health checking for vLLM (`/health`) and Ollama (`/v1/models`) backends
- Prometheus `/metrics` endpoint with request latency, queue depth, and node health
- Built-in `bench` subcommand for throughput and latency benchmarking
- `probe-gpu` subcommand for NVIDIA GPU inventory via nvidia-smi
- Bearer token authentication for `/v1/*` endpoints
- Environment variable expansion (`${VAR}`) in YAML config
- Retry with alternate upstream on hard connection failures
