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
- **The documentation named a security boundary that does not exist (confirmed,
  HIGH).** `docs/helixchannel.md` told operators to "treat the channel token as
  the real authorisation boundary: it decides who may use the gateway at all".
  The channel token is read at exactly one call site — `authorizeConnect`, inside
  `handleConnect` — and gates the `CONNECT` tunnel only. `handleProxy` reads no
  caller credential of any kind and no configuration makes it read one, so on the
  reverse-proxy leg reaching the socket is sufficient to spend every key on every
  enabled route. An operator who believed that sentence would deploy the gateway
  exposed and publish an open, funded relay to every provider whose key it holds.
  The doc now states the absence of caller authentication as a deployment
  constraint, in its own section, ahead of the configuration reference; the
  threat model leads with it instead of implying a channel token is required. The
  `curl` recipe no longer instructs clients to send `Authorization` — that header
  is stripped on every injecting mode — and the "cannot reach the upstream as
  another account" claim is now qualified as what it is: a **blocklist** of six
  header names plus the route's own `key_header`.
- **Budget caps were not admission-controlled (confirmed, HIGH).** `Store.reserve`
  selected on "is this key retired", never "would this reservation exceed the
  plan"; caps were evaluated exclusively at settlement. A settlement that has not
  happened yet cannot stop a request being dispatched, so every request in a
  concurrent burst saw the same uncharged key and went upstream: a 5-request cap
  under a 60-request burst produced 60 upstream calls, 60 × 200 and zero 503s — a
  12x overspend of the whole per-window plan. Sequential traffic was exact, which
  is why a suite full of sequential budget tests never saw it. The hard cap is now
  checked at reservation, counting in-flight leases. The request cap is exact; the
  token cap bounds the projected estimate, since `estimate_tokens` is the only
  figure available before a response exists. The soft cap is untouched, so the
  sequential boundary does not move.
- **A failed upstream was charged as spend (confirmed, HIGH).** Any response
  carrying no usage object was charged the full streaming estimate — including
  5xx, with only 429 special-cased. Four upstream HTTP 500s carrying zero real
  tokens drained both keys' 1000-token budgets through a 500-token estimate, and
  the route then answered 503 with `Retry-After: 3600` for a six-hour window,
  labelled `reason: cap`, having spent nothing: a transient upstream outage
  became a self-inflicted multi-hour quota outage. Charging is now decided from
  the status. 5xx settles as `OutcomeFailed` — no request, no tokens, `errors`
  incremented — and 3xx/4xx settle as a completed request charged only what the
  upstream actually reported, never an estimate: a refusal consumed upstream work
  and counts against a request plan, but generated no completion. The 4xx/5xx
  split is documented in `docs/helixchannel.md`.
- **The retirement metric over-counted on the default config (confirmed).**
  `retireForWindow` recomputed `now + DefaultQuotaCooldown` on every call when no
  `budget.window` was set, so the dedup guard never suppressed: 60 concurrent
  429s over two keys produced 60 increments for two real retirements. With a
  window it was correct — which meant the required alerting surface was unusable
  on exactly the minimal documented block, `rotation: {}`. The counter now counts
  keys *leaving* rotation; pushing an already-parked key further out is an
  extension, not a second retirement. Separately, the deadline was computed under
  one critical section and applied under another, so a window rollover landing
  between them rolled past the deadline just derived from it and silently
  downgraded the retirement to a no-op — the key stayed in rotation with no event
  to say so. Both are now one critical section.
- **Estimated charges were unrecoverable from the audit stream (confirmed).**
  `AuditEvent.Tokens` was set only from a real reported total, leaving the
  estimate path at `0` for `omitempty` to drop; only `tokens_estimated: true`
  survived. Summing the NDJSON therefore under-reported consumption by the whole
  of every streaming request — every request on a header-auth route. `tokens` is
  now the amount actually charged, so the stream reconciles to the store, and
  `tokens_estimated` is provenance for that figure rather than a replacement.
- **A fractional usage value was charged as an authoritative integer.**
  `parseUsageValue` stopped its digit scan at the first non-digit and accepted
  whatever byte that was as proof the number was complete, so
  `"total_tokens":1.5` was charged as `1` with `Estimated` false — the one
  combination that both under-charges the budget arbitrarily and suppresses
  `least_tokens`' degrade-to-request-ordering guard. Digits must now be followed
  by a byte that actually ends a JSON value; anything else demotes to the
  estimate, as every other unreadable shape already did.
- **Caller credential headers reached the upstream (confirmed, HIGH).** The forwarder
  copied every non-hop-by-hop inbound header verbatim, and the only deletion anywhere
  was of `Authorization`. A caller could therefore present `X-Api-Key` (Anthropic,
  Exa, Tavily), `Api-Key` (Azure OpenAI), `X-Goog-Api-Key` (Google) or `Cookie` and the
  provider received it **alongside** the injected key — on `inject` and on `header`,
  single-key and pooled alike, including a `header` route leaking a competing
  provider's credential. The gateway looked like a credential boundary while being a
  credential *adder*. Every mode that supplies its own credential now drops the
  caller's first, from the `callerCredentialHeaders` deny-set plus the route's own
  `key_header`, matched case-insensitively. `passthrough` is exempt by design, via an
  allow-list of modes rather than a hardcoded comparison, so a mode added later strips
  until someone deliberately exempts it.
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
- `docs/helixchannel.md` and the threat model now state the credential guarantee as
  what the code enforces — the deny-set, its contents, and the fact that
  `passthrough` is exempt — instead of the old wording, which conceded that a
  caller-supplied alternative auth header would reach the provider.

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
