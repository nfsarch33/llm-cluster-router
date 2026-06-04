# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Tier-aware multi-hop failover: a request now fails over to the next untried
  upstream on a failover-worthy **response** (HTTP 429 or any 5xx), not only on
  transport errors. Combined with `priority` buckets this expresses an ordered
  capacity chain (e.g. `minimax-m3-key1` / `minimax-m3-key2` → local-GPU /
  M2.7 fallback) using the existing routing abstractions.
- `selectNodeFromSnapExcluding` — set-based node selection so a single request
  can walk the whole chain without re-trying an upstream (bounded by
  `maxFailoverAttempts`; no infinite loops, no lost requests).
- Per-attempt request-timeout contexts so failover still works after a primary
  *timeout* (a shared, already-expired deadline previously blocked it).
- `health_check_disabled` per-node config flag (default `false`). Documents and
  controls the "never recovers" footgun: a disabled node is skipped by the
  probe loop and so can never self-heal after being marked unhealthy.
- Injectable clock on the circuit breaker (`WithClock`) for deterministic,
  race-clean recovery tests.
- Chaos-engineering test suite (`chaos_test.go`): deterministic 502/429
  (with/without `Retry-After`)/latency-timeout/breaker-trip injection asserting
  automatic failover down the chain, breaker self-recovery via a fake clock,
  no lost request / no infinite loop, and fair spread across the two M3 keys.
- Unit tests for failover status classification, exclude-set selection, breaker
  open/half-open/close transitions, and health-loop self-heal.
- `router.sample.yml`: documented Tier-B (two independent M3 keys) → Tier-C
  (priority fallback) chain with self-heal guidance.

### Changed
- Breaker success/failure for proxied requests is now recorded exactly once
  inside the failover loop (was previously re-scored after streaming).
- When the whole chain is exhausted the router relays the real upstream status
  and body (e.g. a genuine 502) instead of a synthetic error, so callers see
  the true capacity signal.

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
