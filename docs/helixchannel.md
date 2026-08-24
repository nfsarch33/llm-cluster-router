# HelixChannel

HelixChannel keeps provider API keys off client machines and keeps agent traffic opaque to the network in between.

Without it, every laptop running an agent holds a copy of every provider key. Rotating one means touching every machine, a leaked key is hard to attribute, and the traffic itself is only as private as whatever network the laptop is on.

With it, keys live on one host you control. Clients authenticate to the channel, not to the provider.

## How it works

```
agent  ──►  TLS  ──►  HelixChannel gateway  ──►  TLS  ──►  provider
                       (holds the real key)
```

Two request styles are supported, because agents differ in how they authenticate.

### Reverse proxy (path prefixes)

The client sends an ordinary OpenAI-compatible request to `https://gateway/<route>/v1/...`. The gateway matches the prefix, strips it, applies credentials and forwards. The client's base URL is the only thing that changes.

Use this for anything driven by an API key: Kilo Code, Cursor, Codex CLI, scripts, CI jobs.

### CONNECT tunnel

Some clients cannot be pointed at a rewritten base URL without losing features, and some hold a session credential that has to terminate at the provider. For those, the gateway accepts an authenticated `CONNECT`, dials an allowlisted target and copies bytes. It never terminates the inner TLS, so the client's session is end-to-end encrypted and unreadable by the gateway itself.

Use this for Claude Code (see [Claude Code setup](claude-code-setup.md)).

## Auth modes

| Mode | Who supplies the credential | Use for |
|---|---|---|
| `inject` | The gateway, from `key_ref`, `key_env` or `key_file` (or a pool: `key_envs` / `key_files` / `key_refs`). Every caller-supplied credential header is **stripped** before the gateway applies its own, so the placeholder a client is told to configure never leaves the gateway. | API-key providers |
| `header` | The gateway, into an operator-named header (`key_header`, optionally prefixed with `key_prefix`). Same strip as `inject`, and the named header is written afterwards, so a caller can neither supply it nor smuggle a competing provider's. | Providers whose key is not a bearer token (Exa `x-api-key`, Tavily) |
| `passthrough` | The caller. Forwarded untouched — the one mode exempt from the strip, because carrying the client's own credential is its entire purpose. | Clients holding their own session token |

### What "stripped" does and does not buy you

On every mode where the **gateway** holds the credential — `inject` and `header`,
single-key and pooled alike — a caller-supplied credential header is dropped
before the request is forwarded. It is not overwritten and it is not renamed: it
does not leave the gateway.

The deny-set is **data**, in `callerCredentialHeaders`
(`internal/channel/forward.go`), and covers:

| Header | Why it is on the list |
|---|---|
| `Authorization` | every bearer provider |
| `Proxy-Authorization` | also hop-by-hop; listed so the guarantee does not rest on that |
| `X-Api-Key` | Anthropic, Exa, Tavily |
| `Api-Key` | Azure OpenAI |
| `X-Goog-Api-Key` | Google Generative Language |
| `Cookie` | a provider session the caller is already signed in to |

— plus whatever the route names in `key_header`, whatever it is called. Matching
is case-insensitive. Onboarding a provider whose key travels in a new header is
**one line in that slice**: not a change to an authenticator, to the handler, or
to the forwarder body.

So the guarantee is:

- on an `inject` or `header` route the upstream sees exactly one credential —
  the gateway's — and no caller-supplied credential header of any listed kind
  reaches it, whether or not the gateway writes that same header itself; and
- `passthrough` is deliberately exempt. That mode exists to carry the client's
  own credential to the provider, so nothing is stripped there.

It is still **not** a general impersonation control. Everything that is neither
on the deny-set nor hop-by-hop is forwarded unchanged — content types,
idempotency keys, provider-specific options — because that is what makes the
gateway a transparent proxy. A provider that accepts a credential through some
*other* header that nobody has listed yet would still receive it.

Treat the channel token as the real authorisation boundary: it decides **who may
use the gateway at all**. If a route's upstream honours an auth header that is
not on the list above, add it to `callerCredentialHeaders` — that is the seam it
exists for — or terminate it in front of the gateway.

## Credentials

A route names **where** its credential lives, never the credential itself.
Three schemes are understood, and any of them may be given as a `key_ref`:

| Scheme | Example | Resolved by |
|---|---|---|
| `env:` | `env:MINIMAX_KEY` | the process environment |
| `file:` | `file:/run/secrets/minimax.key` | reading the file, surrounding whitespace trimmed |
| `op://` | `op://<vault>/<item>/<field>` | `op read --no-newline <ref>`, the 1Password CLI |

Precedence within a single-key route is `key_ref`, then `key_env`, then
`key_file` — the first source that yields a value wins. The CONNECT leg mirrors
this with `token_ref`, `token_env` and `token_file`.

Two guarantees hold regardless of scheme:

- **Startup fails loud.** A source that is missing, unreadable, or holds only
  whitespace is a startup error naming the route and the reference. The gateway
  never falls through to an empty credential, and it never starts holding one.
  A blank `token_env` used to produce an empty CONNECT token, which authorised
  the header `Proxy-Authorization: Bearer ` — see the changelog.
- **Values never reach a log.** Errors carry the reference (committed config,
  not secret) and a bounded diagnostic. The credential itself, and the `op`
  CLI's stdout, are never placed in an error or an audit event.

Resolution happens once, at construction: two routes naming the same 1Password
item cause one `op` invocation and one biometric prompt, not two. A disabled
route is never resolved, so a broken credential on a switched-off route cannot
take the gateway down.

### Multi-key routes

A route may hold a **pool** of keys, each with its own paid plan. Use the
plural fields; there is one spelling, and it is the plural of the singular one:

```yaml
  - name: minimax-pool
    prefix: /minimax-pool/
    upstream: https://api.minimaxi.com
    auth: inject
    key_files:                        # one key per file
      - /run/secrets/minimax-1.key
      - /run/secrets/minimax-2.key
    key_refs:                         # any scheme the resolver understands
      - op://Infra/minimax/key-3
    # key_envs: [MINIMAX_KEY_A, MINIMAX_KEY_B]   # one key per env var
    rotation: round_robin
    enabled: true
```

Rules the validator enforces at startup, not at request time:

- Singular (`key_env`/`key_file`/`key_ref`) and plural
  (`key_envs`/`key_files`/`key_refs`) sources are **mutually exclusive** on one
  route. Silently preferring one is how a route ends up serving from a key you
  thought was retired.
- A declared list must not be empty or blank, and must not name the same source
  twice (file paths are compared after cleaning, so two spellings of one path
  cannot inflate a pool).
- Every key is resolved when the gateway starts. A missing, blank or duplicated
  key is a **boot failure**, never a 502 later: a pool that silently shrinks at
  boot is a capacity lie that surfaces weeks later as a quota alarm. Two
  distinct sources resolving to the same account is caught too, and reported by
  slot label rather than by value.
- A `rotation` block requires a pool. On a single-key route it would advertise a
  budget that is never enforced, so it is rejected.

Slot order is fixed: `key_envs`, then `key_files`, then `key_refs`, in
declaration order. That is what makes the `key_index` in an audit line mean the
same account on every node running the same config.

A pool of **one** is still a pool: it leases, it reports `key_index`, and it
charges its budget. Pooling is a property of the spelling, not of the count —
otherwise a two-key route that lost a key would silently become an unaccounted
single-key route.

## Configuration

```yaml
listen: "127.0.0.1:14445"    # bind loopback when a TLS terminator fronts it
timeout: 90s
audit_log: /var/log/helixchannel/gateway.ndjson   # empty = stdout

routes:
  - name: minimax
    prefix: /minimax/
    upstream: https://api.minimaxi.com
    auth: inject
    key_file: /run/secrets/minimax.key
    enabled: true

  - name: codex
    prefix: /codex/
    upstream: https://api.openai.com
    auth: inject
    key_file: /run/secrets/openai.key
    enabled: false          # feature flag

connect:
  enabled: true
  token_file: /run/secrets/connect.token
  dial_timeout: 10s
  allowed_hosts:            # exact host:port matches; empty is rejected
    - api.anthropic.com:443

tls:                        # only needed when the gateway owns a public socket
  cert_file: /etc/helixchannel/tls.crt
  key_file: /etc/helixchannel/tls.key
```

Adding a provider is one entry. Turning it on is one boolean. Nothing is compiled in: route names, prefixes, upstreams and auth modes are all data, and the config is validated at startup so a typo in a route that is switched off today does not become an outage the day it is switched on.

`enabled: false` routes are not registered at all — requests to their prefix return 404, and `/healthz` lists only what is actually being served.

`/healthz` also reports `keys`: per enabled route, the auth mode, whether the route is pooled, how many server-held credentials back it and how many are selectable right now. It is **counts only** — never a key, prefix, suffix, length or fingerprint, because any per-key hint on an unauthenticated endpoint is an oracle for correlating which account served which request.

Reporting the mode alongside the count is the point. A bare number cannot tell `"this route holds no credential by design"` (a `passthrough` route, where the caller holds it) from `"this route holds no credential by accident"` — both render as `0`. `degraded: true` means a pool whose every key is currently retired or drained, which is a page; `keys: 0, pooled: false` on a passthrough route is not.

## Running it

### Container (recommended)

```bash
podman build -t helixchannel-gateway:local -f deploy/helixchannel/Containerfile.gateway .

podman run -d --name helixchannel-gateway \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v ./gateway.yml:/etc/helixchannel/gateway.yml:ro,Z \
  -v ./secrets:/run/secrets:ro,Z \
  -p 127.0.0.1:14445:14443 \
  helixchannel-gateway:local
```

The image is distroless with no shell and runs as a non-root user. Under rootless Podman, add `--userns=keep-id --user "$(id -u):$(id -g)"` so the container can read host-owned secret files.

### Binary with systemd

```ini
[Service]
ExecStart=/usr/local/bin/helixchannel gateway --config /etc/helixchannel/gateway.yml
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
```

Use this on small hosts where a container runtime is not worth its memory.

### Behind a TLS terminator

For the reverse-proxy routes, bind the gateway to loopback and let nginx or Caddy terminate TLS. Forward the **full path** — the gateway matches on the prefix itself:

```nginx
location /minimax/ { proxy_pass http://127.0.0.1:14445; }   # no trailing slash
location = /healthz { proxy_pass http://127.0.0.1:14445/healthz; }
```

Proxy `/healthz` to the gateway rather than answering it from a literal. A static health response cannot tell "edge is up" from "upstreams are configured", and that difference is exactly what an outage looks like.

The CONNECT leg cannot be relayed by an ordinary HTTP reverse proxy. Give it its own port with `tls:` configured so the gateway owns that socket.

## Verifying

```bash
# Live route set — reflects the enabled flags, not a hardcoded string
curl -s https://gateway.example.com/healthz
# {"status":"ok","service":"helixchannel-gateway","routes":["minimax","qwen"],
#  "keys":{"minimax":{"mode":"inject","pooled":false,"keys":1,"available":1,"degraded":false},
#          "qwen":{"mode":"inject","pooled":true,"keys":3,"available":2,"degraded":false}},
#  "connect":true}

# A route end-to-end
curl -s https://gateway.example.com/minimax/v1/models -H "Authorization: Bearer $CLIENT_TOKEN"

# The CONNECT leg, and that the certificate is the provider's
curl -v -x http://127.0.0.1:47810 https://api.anthropic.com/ 2>&1 | grep -E 'subject:|verify'
# subject: CN=api.anthropic.com ... SSL certificate verify ok
```

That last check is the one worth keeping: if the tunnel were being intercepted, the certificate would be the gateway's.

## Audit log

One NDJSON line per event, with request metadata only — no bodies, no headers, no credentials:

```json
{"ts":"2026-08-20T01:14:09Z","event":"connect_established","request_id":"5c470a65","target":"api.anthropic.com:443","status":200,"latency_ms":1}
{"ts":"2026-08-20T01:09:11Z","event":"connect_denied","target":"example.com:443","status":403,"error":"host_not_allowlisted"}
```

Errors are recorded as classes (`timeout`, `refused`, `dns`, `tls`, `upstream_error`) rather than raw strings, so a URL carrying a token cannot reach the log.

Pooled routes add three `omitempty` fields to each `proxy_request` event, so existing consumers of the NDJSON stream are unaffected and single-key lines stay byte-identical:

| field | meaning |
|---|---|
| `key_index` | which slot served the request — an index, never a value |
| `tokens` | tokens **charged** — the upstream's reported total, or `budget.estimate_tokens` when it reported none |
| `tokens_estimated` | true when the charge came from `budget.estimate_tokens` |

`tokens` is the amount the budget was actually charged, so summing it across the
stream reconciles to the store. `tokens_estimated` is *provenance* for that
figure, not a substitute for it: an estimated charge that recorded only the flag
made every streaming request — which is every request on a header-auth route —
invisible to anyone totalling consumption from the NDJSON. A zero really is zero
(a failed request, or no `estimate_tokens` configured), so `omitempty` stays
correct and unchanged lines stay unchanged.

`key_index` appears on the 502 line too: during a per-key outage, which account failed is exactly what an operator needs.

## Threat model

**Protects against:** provider keys spreading across client machines; credential theft from a laptop; passive observation or tampering on the path between agent and provider; a caller reaching the upstream as a different account by presenting its own `Authorization`, `X-Api-Key`, `Api-Key`, `X-Goog-Api-Key` or `Cookie` on an `inject` or `header` route.

**Does not protect against:** a compromised gateway host — it holds the keys; a malicious client that has a valid channel token, within its allowlisted scope; a caller presenting a credential in some **other** header that the upstream also accepts and that is not on the deny-set, since every remaining non-hop-by-hop header is forwarded (see [What "stripped" does and does not buy you](#what-stripped-does-and-does-not-buy-you)); provider-side logging. The CONNECT allowlist bounds what a stolen token can reach, which is why it is required and why it should stay short.

---

## Rotation, budgets and exhaustion

A pooled route may carry a `rotation` block. Two spellings, one shape:

```yaml
rotation: round_robin        # shorthand for {policy: round_robin}
```

```yaml
rotation:
  policy: least_tokens       # round_robin (default) | least_used | least_tokens
  max_retry_after: 1h        # clamps the Retry-After on a 503; 0 selects 1h
  budget:
    window: 1h               # tumbling per-key accounting window; 0 disables ALL caps
    tokens: 2000000          # hard per-key cap; 0 = uncapped
    requests: 0              # hard per-key cap; 0 = uncapped
    soft_ratio: 0.8          # retire at 80% of the cap; 0 selects the default
    estimate_tokens: 1500    # charged when a response reports no usage
```

A **single-key** route is unaffected by all of this. It resolves to the same
bearer injector as before, no accounting store is built for it, its outbound
request is byte-for-byte what it is today, and its audit line carries no
`key_index`.

### Selection policies

| policy | picks | ties |
|---|---|---|
| `round_robin` (default) | next key in index order | n/a |
| `least_used` | fewest settled requests **plus outstanding leases** this window | round-robin |
| `least_tokens` | fewest tokens charged this window | round-robin |

Counting outstanding leases is what stops a simultaneous burst — which sees no
settled usage at all — from stampeding one key.

`least_tokens` falls back to request ordering for any selection where **any**
candidate carries an estimated sample. Comparing a real token total against an
estimate is exactly the skew the estimate marker exists to prevent.

### Soft and hard caps

- **Soft cap** (`soft_ratio`, default `0.8`): the key leaves rotation for the
  rest of the window while it still has headroom. This is a *planned* rotation —
  the key is never discovered dead by an upstream error.
- **Hard cap** (100% of `tokens` or `requests`): the key is marked **drained**.

Both are unselectable, but they are reported separately: "spent its whole plan"
and "parked early on purpose" are different operational facts.

The **hard cap is admission-controlled**: it is checked when a request is
*reserved*, counting leases already in flight, not only when one settles. A cap
that is evaluated at settlement alone is invisible to a concurrent burst — every
request in the burst sees the same not-yet-charged key and is dispatched before
any of them settles, so a per-window plan is overspendable by the concurrency
factor. Sequential traffic is exact either way, which is why this only ever bites
in production.

The request cap is therefore **exact**: the number of requests admitted in a
window can never exceed `requests`. The token cap is a **bound on the estimate**:
before a response exists, `estimate_tokens` is the only figure available to
project an outstanding lease by, so a response reporting more than the estimate
can still overshoot at settlement, where the hard cap catches it as before.
Admission enforces the hard cap only — the soft cap remains the planned early
exit that decides when a key leaves rotation under normal traffic.

The window is **tumbling** and rollover is **lazy** — evaluated from the clock on
every call. The gateway therefore starts no timer goroutine for rotation, and a
test can advance an injected clock instead of sleeping. An explicit retirement
whose deadline outlives the window (a one-hour provider cooldown, for instance)
survives a five-minute accounting boundary.

### Exhaustion is 503, never 502

When every key on a route is retired or drained the gateway answers:

```
HTTP/1.1 503 Service Unavailable
Retry-After: 90
Content-Type: application/json

{"error":"keys_exhausted","route":"minimax-pool","retry_after_seconds":90, ...}
```

The upstream is **not** contacted. This is deliberately distinct from the
existing `502 upstream unavailable`: an operator paging on 502 is hunting a
broken upstream, whereas a route whose plans are all spent is a billing
question. Collapsing the two is how a quota outage gets triaged as an outage.

`Retry-After` is the true minimum wait across all keys, floored at 1s (a
`Retry-After: 0` tells a client nothing) and clamped to `max_retry_after`
(default 1h — several agents treat an hours-long value as fatal). A client that
retries early simply receives another 503 with a fresh value.

Neither the 503 body nor the audit line ever carries key material: only the
route name, the reason and the wait.

An upstream **429** or **402** retires the serving key with reason `quota` before
the lease settles, so the next selection already skips it. 402 is included
because header-auth providers commonly signal a spent plan with Payment
Required, and treating that as a generic upstream error would keep re-selecting
the dead key until the window rolled.

### Streaming responses and the estimate fallback

Token usage is read from the response as it streams past, from a rolling 8 KiB
tail scanned for the last `"total_tokens": N`. One implementation serves both
plain JSON and SSE, because a rolling tail is agnostic to chunk boundaries and
to the `data: ` frame wrapper.

Many SSE completions carry no `usage` object at all. That case is **not** charged
as zero — zero is a real, trustworthy count, and conflating the two is how an
all-streaming route would under-charge its budget forever and never rotate.
Instead the sample's token count is structurally unknown, `budget.estimate_tokens`
is charged, the key is marked **estimated** (which makes `least_tokens` degrade
to request ordering), and the audit line records `"tokens_estimated": true`.

`Config.Validate` rejects `budget.tokens > 0` with `estimate_tokens: 0` at
startup, so the silent-skew configuration cannot be deployed. A usage object
that falls outside the retained tail is treated the same way — an estimate,
never a zero.

A request that fails before producing a response (dial error, timeout, client
disconnect) releases its lease and increments an error counter but charges no
requests and no tokens: a dead upstream must not make a healthy key look like
the most-used one.

### What a failed response is charged

"No usage object" looks identical on a completed stream and on an upstream that
fell over, so the charge is decided from the response status:

| status | charged | rationale |
|---|---|---|
| 2xx | reported total, else `estimate_tokens` | unchanged |
| 3xx / 4xx | reported total, else **nothing** — but it counts as a request | the upstream served the request and refused it: that consumed upstream work and counts against a request plan, but a refusal generates no completion to estimate |
| 5xx | **nothing at all** — no request, no tokens, `errors` incremented | the upstream did not serve the request |

The 5xx rule matters more than it looks. Charging the streaming estimate for a
5xx turns a transient upstream outage into a self-inflicted quota outage: four
HTTP 500s carrying zero real tokens were enough to drain two 1000-token plans
through a 500-token estimate, after which the route answered 503 with an
hour-long `Retry-After` for a six-hour window — labelled `reason: cap`, having
spent nothing. A 5xx that somehow *did* report usage is still treated as a
failure: a response the gateway could not deliver as a success is not evidence
of spend.

`429` and `402` are 4xx and follow the 4xx rule, and additionally retire the key
with reason `quota` (above).

A usage figure the gateway cannot read in full — a fractional or exponent value,
digits running into something else, or a number cut off by the 8 KiB tail — is
treated as **no usage at all** and demoted to the estimate. It is never charged
as the digits that happened to parse: a malformed or hostile upstream sending
`"total_tokens":1.5` must not be able to bill a plan 1 token while the sample is
marked authoritative.

### `auth: header` with a budget

Header-auth upstreams report no `usage.total_tokens`, so **every** sample on such
a route is an estimate. Budget those routes by `requests`, not by `tokens`.

`policy: least_tokens` is **rejected at config load** on an `auth: header` route:
with every sample estimated it would behave exactly as `least_used` while
claiming to balance tokens. Everything else composes normally — a pooled header
route leases, retires, emits `auth_mode: header` alongside `key_index`, and
answers the same 503 with `Retry-After`.

### Metric

```
llm_cluster_router_helixchannel_key_retired_total{route,reason}
```

`reason` is one of:

| reason | meaning |
|---|---|
| `cap` | this gateway's own accounting — the soft cap or the hard cap |
| `quota` | an upstream quota signal (HTTP 429 or 402) |
| `error` | repeated upstream failure that is not a quota signal |

The counter counts keys **leaving** rotation, once per departure, for every
reason. Late settlements of in-flight leases cannot inflate `cap`, and a key
that is already parked and is pushed further out is an *extension*, not a second
retirement — so a burst of concurrent 429s all answering for the same key
increments `quota` once, not once per response. Without that rule the minimal
documented block (`rotation: {}`, no `budget.window`) inflated the series by the
concurrency factor — 60 increments for two real retirements — which made the
alerting surface unusable on the default configuration.

Registration is explicit — `channel.RegisterMetrics(reg)` — rather than an
`init()`, so importing the package never mutates the default Prometheus
registry and a test can use its own `prometheus.NewRegistry()`. The `gateway`
subcommand performs that registration on the process registry at startup; an
alert written against this series with nothing calling `RegisterMetrics` would
be dead on arrival.
