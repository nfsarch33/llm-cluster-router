# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **HelixChannel v18770 — pooled credentials, rotation and one secret seam.**
  Three parallel workstreams (secret provider, pooled auth, rotation) landed as
  a single reconciled design rather than three merges. Highlights:
  - `SecretProvider` is now the only way a credential is read. `env:`, `file:`
    and `op://<vault>/<item>/<field>` references are resolved by one
    scheme-dispatching `Resolver` with a success-only cache and singleflight
    dedup, so two routes naming the same 1Password item cause one `op`
    invocation and one biometric prompt. `key_ref` / `token_ref` expose it in
    config; `key_env` / `key_file` keep working and keep their precedence.
  - **Multi-key routes**: `key_envs` / `key_files` / `key_refs`, one key per
    slot, in a frozen slot order (envs, then files, then refs). A route is
    "pooled" if it uses the plural spelling — including a pool of one, which
    still leases, still reports `key_index` and still charges its budget.
  - **`auth: header`** for providers whose key is not a bearer token
    (`key_header`, optional `key_prefix`). It replaces any caller value in that
    header and strips an inbound `Authorization` it is not itself writing.
  - **Rotation**: `rotation: <policy>` or a block with `policy`, `budget` and
    `max_retry_after`. Policies are `round_robin`, `least_used` and
    `least_tokens`. Per-key tumbling-window budgets with a soft cap (planned
    rotation before a key errors) and a hard cap (drained).
  - **Exhaustion answers 503 with `Retry-After`, never 502**, without
    contacting the upstream: an operator paging on 502 is hunting a broken
    upstream, whereas a route whose plans are all spent is a billing question.
  - **`/healthz` now reports `keys`**: per route, the auth mode, whether it is
    pooled, how many credentials back it and how many are selectable. Counts
    only, never key material. Carrying the mode is what separates "no
    credential by design" (passthrough) from "no credential by accident" — a
    bare count rendered both as `0`.
  - **Audit events** gain `key_index` (a `*int`, so slot 0 survives
    `omitempty`), `tokens` and `tokens_estimated`, all `omitempty`. Single-key
    and passthrough lines are byte-identical to before.
  - New metric `llm_cluster_router_helixchannel_key_retired_total{route,reason}`
    with reasons `cap` / `quota` / `error`. The `gateway` subcommand registers
    it at startup, so the series actually exists for alerts to watch.

### Fixed
- **CONNECT auth bypass (confirmed).** A credential source holding only
  whitespace passed the old "is it non-empty?" test *before* it was trimmed,
  and collapsed to `""` afterwards. An empty CONNECT token then made
  `subtle.ConstantTimeCompare([]byte(""), []byte(""))` return 1, so the header
  `Proxy-Authorization: Bearer ` was **authorised** and the gateway became an
  allowlisted open relay. Three branches each patched this independently; the
  reconciled tree fixes it once, by deleting `readSecret` outright and making
  the providers trim before testing. `authorizeConnect` additionally refuses an
  empty configured token *and* an empty presented token, and `NewServer` refuses
  to construct a gateway holding a blank one. `internal/channel/secret_regression_test.go`
  is the single canonical regression set and names which layer each case pins.
- An inject route whose credential resolved to whitespace used to build a
  bearer injector with an empty key and 502 on every request; it is now a
  startup failure naming the route.

### Changed
- `rotation` on a single-key route is now an **error**, not a default. It
  previously either defaulted or was ignored, which let an operator write a
  budget that was never enforced and get no signal.
- `rotation.policy: least_tokens` is rejected on an `auth: header` route: those
  upstreams report no `usage.total_tokens`, so every sample is an estimate and
  the policy would silently behave as `least_used`.
- An upstream **402 Payment Required** now retires a key with reason `quota`
  alongside 429; header-auth providers commonly signal a spent plan that way.
- `deploy/helixchannel/gateway.example.yml` is the **only** example config and
  covers every reconciled decision. Two examples in two directories is how a
  node gets deployed from the one that was not updated.
- `docs/helixchannel.md` no longer claims that replacing `Authorization` means
  "a client cannot reach the upstream as another account". That was false: every
  non-hop-by-hop header is forwarded, so a provider that also accepts an
  alternative auth header will still receive whatever the caller put there. The
  guarantee is now stated as what it actually is, in the threat model too.

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
