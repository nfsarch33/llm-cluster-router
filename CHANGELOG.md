# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **BREAKING — the reverse-proxy leg now authenticates its callers.** A shared
  **gateway token**, configured through the same `SecretProvider` seam as every
  other credential (`gateway_auth.token_env` / `token_file` / `token_ref`) and
  presented by callers in the **`X-HelixChannel-Token`** header, is compared in
  constant time before the path is matched and before any key is leased.

  Until now `handleProxy` read no caller credential at all. `authorizeConnect`
  was called at exactly one site — inside `handleConnect` — so the channel token
  gated the `CONNECT` tunnel and nothing else. Measured against the running
  pilot gateway, an anonymous `curl -X POST http://…/minimax/v1/models` with no
  headers whatever reached MiniMax's production load balancer with the
  server-held key injected, and the provider's own request-id headers came back
  in the response. `/healthz` disclosed the route set and the per-route key
  counts to the same anonymous caller.

  - The gateway token is a **different secret** from `connect.token_*`, and
    resolving both to the same value is refused at startup. One gates spending
    every key on every enabled route; the other opens a tunnel bounded by an
    exact-match host allowlist.
  - It is **not** the `Authorization` header. Kilo Code's placeholder-bearer
    contract is unchanged: a placeholder `Authorization` plus a valid
    `X-HelixChannel-Token` is served, the placeholder is still stripped, and the
    server-held key is still what reaches the provider. The gateway token itself
    is stripped before forwarding on **every** mode, `passthrough` included.
  - **Loopback callers are exempt by default** (`gateway_auth.exempt_loopback`,
    default `true`), so every existing local client keeps working at cutover.
    The exemption is decided from the accepted connection's peer address and from
    no header: a caller cannot claim loopback with `X-Forwarded-For`. Presenting
    a *wrong* token is refused even from loopback — the exemption waives having
    to present one, not the check on one that was presented.
  - **No token configured is still a supported posture, and now says so.** The
    gateway **refuses to start** with `listen` on anything but a loopback
    address unless `gateway_auth.allow_unauthenticated: true` is written down
    (the shape for an authenticating terminator in front). `--listen`
    re-validates, so the override cannot smuggle a wildcard bind past the check.
    Both unauthenticated postures print a loud warning at every start.
  - The posture — `token`, `token_loopback_exempt`, `loopback_only`, `open` — is
    **derived** from the configuration rather than typed in a fifth place, and is
    reported on the startup banner (`proxy_auth=…`), in the `--print-routes`
    envelope, and on `/healthz`.
  - **`/healthz` liveness stays anonymous and stays `200`** in every posture; the
    `routes` / `keys` / `connect` inventory is now disclosed only to a caller the
    proxy leg would serve, gated by the same decision rather than a second rule.
    The 404 for an unknown prefix lists route names, so it too is now behind the
    gate.
  - Refusals answer `401` with
    `WWW-Authenticate: HelixChannel realm="helixchannel-gateway", header="X-HelixChannel-Token"`
    and a body naming `gateway_token_required` or `gateway_token_invalid`, and
    are recorded as `proxy_denied` in the NDJSON audit stream. `401`, not the
    `CONNECT` leg's `407`: on this leg the gateway is an origin server as far as
    the client is concerned.

  **Migration.** Non-loopback callers must add one header. Generate a token,
  distribute it to those clients *first* (nothing rejects it yet), then add the
  `gateway_auth` block and restart. Operators running a wide bind with no token
  will find the gateway refuses to start after upgrading — that is the intended
  failure, and the only moment anyone would have noticed. See
  `docs/helixchannel.md`, "Authenticating reverse-proxy callers".

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

### Changed

- **BREAKING — a host NAME is no longer a loopback `listen`, `localhost`
  included.** `listen: "localhost:14443"` with no `gateway_auth` token now
  refuses to start; write `listen: "127.0.0.1:14443"` (or `"[::1]:14443"`), or
  configure a token. The refusal says both.

  Loopback-ness of the *bind* is what relaxes three separate things — it waives
  the gateway-token requirement, it permits loopback `connect.allowed_hosts`
  entries, and it disarms the dial-time `CONNECT` guard — so trusting a spelling
  fails **open**. A host whose `/etc/hosts` mapped `localhost` to a routable
  address switched all three off silently, and nothing in the config text said
  so. Deciding a name honestly would mean resolving it during validation, which
  would let whoever answers the resolver choose the gateway's security posture;
  config validation still resolves nothing. Note the asymmetry that makes this
  consistent rather than contradictory: as a `CONNECT` **target** a reserved
  loopback name is still refused, because there the same answer fails closed.

- **Request budgets are the default; token budgets are advisory.** Operator
  decision: budget by requests, not tokens.

  A `rotation.budget.requests` cap is EXACT under concurrency — admission counts
  the leases already in flight and a request's cost is known before it is
  admitted — measured exact across a 12-combination pool-size × cap sweep at
  burst 60, with zero overspend, zero leaked in-flight and the charge always
  equal to what the upstream served.

  A `rotation.budget.tokens` cap bounds the ESTIMATE, not the charge: it admits
  `ceil(tokens/estimate_tokens)` leases at once and each settles whatever the
  upstream actually reported. MEASURED at `tokens: 1000`, `estimate_tokens: 100`
  and a real 5000-token response: 10 concurrent leases charged 50000 against a
  1000-token cap, a 50x overshoot, where the sequential worst case for the same
  numbers is 5000.

  - `deploy/helixchannel/gateway.example.yml` — the only example config — now
    budgets `minimax-pool` by requests. No shipped example configures a token
    budget.
  - Token budgets remain **supported**. Configuring one now produces a loud
    startup warning naming the overshoot ratio for that route's own numbers
    (`tokens/estimate_tokens`), so the magnitude arrives at start rather than on
    a bill. `Config.TokenBudgetAdvisories` is the one place that arithmetic
    lives, and it is asserted against what `admissibleLocked` actually grants.
  - Reserved-token accounting — reserving `estimate_tokens` at admission and
    reconciling it to the real total at settlement — is the known path to an
    exact token cap. It is deliberately NOT implemented; see the follow-up note
    in `docs/helixchannel.md` and on `channel.BudgetAdvisory`.

### Fixed
- **A loopback-only deployment could be refused its own loopback targets
  (confirmed).** Two disagreeing definitions of "loopback" lived in the package:
  the `CONNECT` target side implemented `inet_aton`'s grammar, while the bind
  predicate was `net.ParseIP` plus the literal string `"localhost"`. Measured,
  `listen: 127.1:14443` was read as a *wide* bind, so `allowed_hosts:
  ["127.0.0.1:9200"]` — a legitimate local target on a legitimate loopback-only
  deployment — was refused at startup, which on a fresh host presents as an
  inexplicable refusal to boot. There is now one procedure: `127.0.0.1`,
  `127.1`, `127.0.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `::1` and
  `::ffff:127.0.0.1` are one answer across the validator, the dial-time guard
  and the bind predicate. See the `Changed` entry above for the name half of
  the same fix.

- **A healthy route reported its keys as exhausted (confirmed).** The R1
  admission-control fix created a NEW refusal mode — a key at its hard cap once
  leases in flight are counted — and labelled it with the OLD one. While
  refusing, `/healthz` reported `{keys: 2, available: 2, degraded: false}` and
  every key state read `Selectable: true, Drained: false`, yet callers received
  `{"error":"keys_exhausted","hint":"every upstream key on this route is retired
  or drained"}`. `writeDrained`'s own doc comment argued against exactly that
  collapse: an operator paging on it hunts a billing problem that does not exist,
  while the one signal that could have contradicted them agreed with the truth
  instead of with the error. The two refusals are now distinct end to end —
  `admission_limited` with its own hint and `Retry-After: 1` (it clears when an
  in-flight lease settles, not when a window rolls) against `keys_exhausted` with
  the wait the store can actually name — and they are counted under separate
  reasons of a new
  `llm_cluster_router_helixchannel_admission_refused_total{route,reason}`, so one
  is page-worthy and the other is a capacity signal rather than both being noise
  on the same series. `Store.reserve` reports which of its two filters emptied
  the candidate set, decided inside the same critical section and against the
  same clock reading as the selection itself.
- **A redirect replayed the server-held credential to wherever the upstream said
  (confirmed, CRITICAL).** `NewHTTPForwarder` left `http.Client.CheckRedirect`
  nil — `rg CheckRedirect --type go .` matched nothing in the tree — which
  selects the standard library default: follow up to ten hops, replaying the
  outbound headers on each. On an injecting route those headers carry the
  credential the gateway holds and the caller is never shown. Measured
  cross-domain, with Go's own cross-domain strip fully in force, the redirect
  target received `x-api-key` from a single-key header route and from a pooled
  one; `Authorization` survived only because `net/http` happens to strip that one
  header name across a domain change, which is an accident of the library and no
  help on a same-domain redirect. The shipped `exa-pool` route is exactly that
  shape. Two more findings shared the root cause: a redirect drove the gateway to
  a host in no configuration and returned the body to an unauthenticated caller
  (**SSRF**), and a chain inside one forward became up to nine extra upstream
  round trips charged as one request (**spend**). No redirect is now followed on
  any mode — there is no same-host exception, and an upstream that needs one
  followed is a configuration change — the `3xx` is relayed to the caller with
  its `Location`, and the audit line names the outcome
  `error: redirect_not_followed`.
- **The audit line could not record where a request actually went (confirmed).**
  Every `proxy_request` event carried `rt.Route.Upstream`, the host the route was
  CONFIGURED to contact, so a gateway that had just been driven to a host in no
  configuration recorded that it had gone where it was told. Lines that obtained
  a response now also carry `upstream_host`, the `host:port` read back from the
  request `net/http` actually sent. Intent and fact are both recorded, so a
  divergence is an assertable signature rather than an invisible one.
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
