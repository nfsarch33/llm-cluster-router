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

If a route's upstream honours an auth header that is not on the list above, add
it to `callerCredentialHeaders` — that is the seam it exists for — or terminate
it in front of the gateway.

### Authenticating reverse-proxy callers

This is the part that decides how you may deploy it, so it is stated before the
configuration reference rather than in a footnote.

The reverse-proxy leg takes a **gateway token**: a shared secret presented in the
`X-HLXN-Token` request header and compared in constant time, **before**
the path is matched and before any key is leased.

```yaml
gateway_auth:
  token_file: /run/secrets/gateway.token   # or token_env: / token_ref:
  exempt_loopback: true                    # the default
```

It is a **different secret from the channel token**, and the split is the point.
`connect.token_*` is read at exactly one call site — `authorizeConnect`, inside
`handleConnect` — and gates the `CONNECT` tunnel and nothing else, bounded by an
exact-match host allowlist. `gateway_auth.token_*` gates the ability to spend
every key on every enabled route. Pointing both at one source is **refused at
startup**: a single secret granting both powers grants whichever one the
operator was not thinking about.

It is also **not the `Authorization` header**. Clients of an `inject` route are
told to configure a placeholder bearer — Kilo Code will not send a request
without some API key — and the forwarder strips that placeholder before the
request leaves. Admission must not depend on a value clients were told was
meaningless. A placeholder `Authorization` **plus** a valid `X-HLXN-Token`
is the supported shape, and the server-held key is still what reaches the
provider.

#### Four postures, derived rather than typed

The posture is derived from two facts an operator writes down — is a token
source named, and is unauthenticated operation explicitly accepted — so the
posture the gateway *reports* cannot drift from the one it *enforces*. It is
printed at startup (`proxy_auth=…` on the banner) and served on `/healthz`.

| `proxy_auth` | configuration | reverse-proxy leg |
| --- | --- | --- |
| `token_loopback_exempt` | a token source, `exempt_loopback` absent or `true` | token required from every non-loopback caller; loopback served anonymously |
| `token` | a token source, `exempt_loopback: false` | token required from **every** caller, loopback included |
| `loopback_only` | no token source | **authenticates nobody**; startup refuses any non-loopback `listen` |
| `open` | no token source, `allow_unauthenticated: true` | **authenticates nobody**, on any `listen` |

Two rules are worth stating outright because they are not symmetrical:

- The exemption exempts a caller from **having** to present a token. It does not
  exempt a presented token from being **checked**. A local client configured with
  a stale token is refused rather than quietly served, so it fails on the bench
  instead of the day it moves off the box.
- A gateway token is stripped from the request before it is forwarded, on
  **every** auth mode including `passthrough`. `passthrough` is exempt from the
  caller-credential deny-set by design, and without this it would hand the
  gateway's own admission credential to the provider.

#### The loopback exemption cannot be claimed

The exemption reads `RemoteAddr` — the peer of the accepted TCP connection — and
**nothing else**. `X-Forwarded-For`, `X-Real-IP` and `Forwarded` are
caller-supplied strings; honouring any of them would let a remote caller type
`127.0.0.1` into a header and become local. There is no configuration switch to
make it trust one. Anything unparseable (a UNIX peer, an empty `RemoteAddr`) is
**not** loopback: the safe answer is the one that asks for a token.

If the gateway genuinely runs behind a proxy on the same host and you want that
proxy's callers authenticated, set `exempt_loopback: false` and give the
terminator a token. Do not reach for a forwarded-header rule; there isn't one.

#### ...and it cannot be reached through the gateway's own tunnel

Reading `RemoteAddr` and nothing else is necessary but was not sufficient. The
`CONNECT` leg dials its target verbatim, so a gateway that allowlisted its **own**
address would dial itself: the tunnelled request arrives over the loopback
interface, `RemoteAddr` really is `127.0.0.1`, and the exemption applies. A remote
holder of the `CONNECT` token — a credential that is supposed to be bounded by
`allowed_hosts` — could launder itself into a local caller and spend every key on
every enabled route. It was reproduced over a real socket with
`listen: 0.0.0.0:P` and `allowed_hosts: [127.0.0.1:P]`.

Two checks close it, and the split between them is deliberate.

**At load, `allowed_hosts` may not name this machine.** On a bind that is *not*
loopback-only, every local target is refused on every port; on a loopback-only
bind only the gateway's own listen port is (there every client is already a local
process, so a tunnel to a local service grants it nothing it could not open
itself). The gateway's own routable address paired with its own bind is refused
too. The same rule is **re-run after the bind**, against the address the socket
actually got, so an allowlist that load-time accepted on the strength of a
loopback-looking `listen` string is refused at startup if the socket turns out to
be reachable — see [What counts as a loopback `listen`](#what-counts-as-a-loopback-listen).
What "names this machine" covers:

| Decided | How |
| --- | --- |
| `127.0.0.0/8`, `::1`, `::ffff:127.0.0.1`, `0.0.0.0`, `::`, an empty host | parsed as an address |
| `127.1`, `127.0.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `017700000001` | parsed with `inet_aton`'s grammar, so this is the whole class of numeric spellings, not a list of them |
| `localhost`, `localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, anything under `.localhost` | **a blocklist of literal names**, and only that |

The name row is the honest limit: any name at all can have a `127.0.0.1` A record,
and deciding that here would mean a DNS lookup during startup — which makes
booting depend on a resolver and lets a poisoned answer decide whether the gateway
runs. Config validation resolves nothing. The whole table is also a **target-side**
answer: as the *bind* address neither the names nor the numeric spellings prove
anything, because there the answer relaxes rather than restricts — see
[What counts as a loopback `listen`](#what-counts-as-a-loopback-listen). It also cannot tell one of the host's
own routable addresses from a neighbour's under a wildcard bind, because that
needs an interface enumeration that is stale the moment an address is added.

**At dial, the opened socket is checked.** Before a byte moves, a peer that is
loopback or unspecified — or whose address equals the gateway's own end of that
same socket, which is what dialling one of your own addresses looks like — is
refused with `403` and a `connect_denied` audit line. This is the layer that sees
what a *name* resolved to, so it covers both gaps above, including an answer that
changed after startup. It is skipped when the gateway's **socket** reaches
loopback only — decided from the bound address, never from the `listen` string —
because there is no remote caller to launder there and tunnelling to a local
service is the ordinary use.

#### If no token is configured

Nothing is authenticated, exactly as before this existed — and the gateway
**refuses to start** unless the socket it binds reaches loopback only.
`listen: "0.0.0.0:…"` or `":14443"` with no `gateway_auth` block is a startup
error, not a warning: that combination was a funded, unauthenticated relay to
every provider whose key the process holds, and it looked identical to a correct
config. `--listen` re-validates, so the override cannot smuggle a wildcard bind
past the config-time check either.

The decision is made **after the bind, from the socket** — `listen` is only ever
a request, and what it binds can be a resolver's answer. The gateway binds,
reads back `ln.Addr()`, and only then judges the tokenless posture; if the answer
is "reachable from other hosts", it closes the listener and exits with an error
naming the address it actually got. Nothing is served in that window, not even a
request already sitting in the accept backlog. See
[What counts as a loopback `listen`](#what-counts-as-a-loopback-listen).

The one legitimate wide-bind-without-a-token shape is an **authenticating**
terminator (mTLS, an OIDC-verifying proxy, a signed-header check) that is the
sole reachable path to the socket. That is what `allow_unauthenticated: true` is
for. It is refused together with a token source, and it prints a loud warning at
every start. Writing it down is the whole of the difference between that
deployment and the accident it is otherwise indistinguishable from.

Note what the bind address does **not** cover: a container that binds loopback
inside its own netns and is published with `-p 0.0.0.0:14443:…` is reachable from
the network while `listen` still reads `127.0.0.1`, and its callers arrive from
the bridge address, not from loopback. Under `loopback_only` they are served. A
token is the only thing that closes that, and it is the reason the shipped
example config configures one.

#### What counts as a loopback `listen`

Two questions in this gateway say "loopback". They get **different** answers, on
purpose, and the difference is which of them is ours to decide.

A `CONNECT` **target** is decided by this code and by nothing else, and deciding
"loopback" *refuses* the entry — so a generous reading fails **closed**, and the
table above is deliberately generous: every `inet_aton` spelling, plus a
blocklist of reserved names.

A **`listen`** address is not ours to decide at all. `net.Listen` may hand the
string to the platform resolver — hosts file and DNS included — so what actually
gets bound can be a resolver's answer, while deciding "loopback" *relaxes* three
separate things: it waives the gateway-token requirement, it permits loopback
`connect.allowed_hosts` entries, and it disarms the dial-time `CONNECT` guard. A
generous reading fails **open**, and a *narrow* reading is still only a guess.

So the gateway stops guessing.

**The bound socket is the authority.** After `listen` is bound and before a
single request is served, `ln.Addr()` — the address the kernel actually assigned,
which is spelling-independent, resolver-independent and true by construction —
decides whether the socket reaches loopback only. All three relaxations hang on
that answer. A **wildcard** bind (`0.0.0.0`, `::`, an empty host) is judged
**not** loopback-only, because it accepts remote peers. If a tokenless
configuration, or a loopback `allowed_hosts` entry, turns out to be sitting on a
socket other hosts can reach, startup fails loudly and the listener is closed:
not one request is answered in between.

**The config-time check is an early warning, and only that.** It still runs at
`LoadConfig`, because a refusal an operator reads while looking at the file beats
one they meet at startup, and both beat one they never meet. But nothing is
*granted* on the strength of it any more. It reads `listen` as an address
**literal**:

`127.0.0.1`, anywhere in `127.0.0.0/8`, `::1`, `::ffff:127.0.0.1`, and `[::1%lo]`
— an IPv6 zone is split off and the remainder parsed as a literal, by this code
and by `net.Listen` alike. Nothing else.

Three spellings that look as though they ought to count, and do not:

| Written as `listen` | Why it is not accepted |
| --- | --- |
| `localhost`, `localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, anything under `.localhost` | a name is decidable only by resolving it, and resolving it at startup lets whoever answers the resolver choose this gateway's security posture |
| `127.1`, `127.0.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `017700000001` | `net.Listen` does not parse these as literals either — it hands them to the platform resolver, hosts file and DNS included — so the socket that actually opens is a resolver's answer, not anything the config text decided |
| `127.0.0.1%eth0`, `127.1%lo`, any zone on an IPv4-looking host | **only IPv6 has zones.** Go reads the address family from the first `.` or `:` in the string, so a zone after a dotted quad makes the *whole string* a host name and `net.Listen` resolves it. `[::1%lo]` is the legitimate spelling and is accepted |

None of these rows is theoretical, and together they are why the authority moved
to the socket rather than into a fourth predicate case:

- With `listen: "0x7f000001:45425"` trusted as loopback, a hosts-file entry put
  the socket on a **routable** address while the predicate still said loopback:
  tokenless startup accepted, an anonymous caller served `200`, the upstream key
  spent. The same attack spelled `localhost` was already refused.
- With `listen: "127.0.0.1%evil:14443"`, the zone was stripped before parsing —
  unconditionally — so the predicate read `127.0.0.1` and said loopback, while
  `net.Listen`, which knows IPv4 has no zones, treated the string as a host name,
  resolved it, and bound `172.29.144.56`. All three relaxations fired on a
  routable socket.

Each of those was closed by teaching the predicate about one more spelling, and
each fix was what invited the next one: every accommodation added a new string
the predicate trusted and the OS read differently. Predicting what `net.Listen`
will do with a string cannot be made sound — it is allowed to ask a resolver and
this code is not. Reading back what it did can, and costs one line at startup.

Refusing the numeric forms at load time also costs a shipped deployment nothing.
Every container image builds with `CGO_ENABLED=0`, and the pure-Go resolver never
reads an `inet_aton` spelling as an *address* — it looks the string up as a
*name*. Measured on a host with no such entry, all six fail to bind at all
(`listen tcp: lookup 127.1: no such host`; `0x7f000001` went as far as DNS), while
the same six bind fine under a cgo build. So accepting them rescued no real
loopback deployment: it traded a legible startup error for an obscure runtime
failure.

So `listen: "localhost:14443"`, `listen: "127.1:14443"` and
`listen: "127.0.0.1%eth0:14443"` with no `gateway_auth` block are startup errors.
Two fixes, and the message names both, along with which spelling it could not
decide:

- write the address as a literal — `listen: "127.0.0.1:14443"` (or
  `"[::1]:14443"`, or `"[::1%lo]:14443"` if the zone is meant); or
- configure `gateway_auth.token_env` / `token_file` / `token_ref`, which is
  correct whatever the string resolves to.

#### `/healthz`

Liveness stays anonymous and stays `200` in every posture — a probe that answers
`401` is a probe an orchestrator reads as *down*. The **inventory** does not:
`routes`, `keys` and `connect` are disclosed only to a caller that
`authorizeProxy` would let through, which is the same decision that gates the
proxy leg rather than a second rule with its own edge cases. Under `token` and
`token_loopback_exempt` an unauthenticated stranger sees only:

```json
{"status":"ok","service":"helixchannel-gateway","proxy_auth":"token_loopback_exempt"}
```

The route table, each route's auth mode, and a live count of how many plans are
still selectable are reconnaissance, and the per-route counts are an oracle for
correlating which account served which request. Under `loopback_only` and `open`
the inventory is served to everyone, because in those postures so is the traffic.

The 404 for an unknown prefix lists the enabled route names, so it is behind the
same gate: an unauthenticated caller is refused before the path is matched.

#### Migrating

**This is a breaking change for non-loopback callers.** Any client reaching the
gateway from another host must add one header:

```bash
curl -H "X-HLXN-Token: $(cat /run/secrets/gateway.token)" \
     https://gateway.example.com/minimax/v1/models
```

The order that does not drop traffic:

1. Generate a token (`openssl rand -hex 32`) and place it where the gateway can
   read it — a root-owned file, an env var, or a vault item named by `token_ref`.
2. Distribute it to every non-loopback client **first**. Nothing rejects it yet.
3. Add the `gateway_auth` block and restart. Loopback clients are unaffected;
   the startup banner now reads `proxy_auth=token_loopback_exempt`.
4. Optionally tighten to `exempt_loopback: false` once local clients carry it too.

Operators who were relying on a wide bind with no token will find the gateway
**refuses to start** after upgrading. That is the intended failure: it is the
only moment anyone would have noticed.

The `CONNECT` leg is unchanged by all of this. Its allowlist — not its token —
is still what bounds where a stolen channel token can go.

### Redirects are never followed

The gateway does not follow a `3xx` from an upstream. On **every** auth mode,
`inject`, `header` and `passthrough` alike, the redirect is relayed to the caller
with its `Location` intact and the caller decides what to do with it. The audit
line for that request carries `error: redirect_not_followed`.

This is a security property, not a preference. `http.Client.CheckRedirect` was
nil, which selects the standard library's default: follow up to ten hops,
**replaying the outbound headers on each one**. On an injecting route those
headers carry the credential the gateway holds and the caller is never shown, so
an upstream — or anything able to answer as one — could exfiltrate a server-held
key by answering `302`. Measured on this build with the provider and the target
on different domains, so Go's own cross-domain header strip was fully in force,
the target received the route's `x-api-key` from a single-key header route and
from a pooled one. `Authorization` stayed behind only because `net/http` happens
to strip that one header name across a domain change, which is an accident of the
standard library and no help at all on a same-domain redirect. The shipped
`exa-pool` route is exactly the leaking shape.

Two further consequences shared that one root cause and are fixed by the same
line:

- **SSRF.** A redirect made the gateway fetch a host named in no configuration
  and hand the body back to an unauthenticated caller.
- **Spend.** A chain inside a single forward was up to nine extra upstream round
  trips, all charged as one request against the budget.

There is deliberately **no same-host exception**. A same-host redirect still
multiplies round trips, still charges them as one, and still lets the upstream
choose the request path; and a "same host?" comparison in the forwarder would be
a security control in exactly the place this defect lived. An upstream that
genuinely needs a redirect followed is a **configuration** change: point the
route's `upstream` at the redirect target.

Because no redirect is followed, the host the gateway contacts is always the host
its route configured — and the audit line proves it rather than assuming it, by
recording `upstream_host` read back from the request that was actually sent.

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
listen: "127.0.0.1:14445"    # a non-loopback bind REQUIRES gateway_auth below
timeout: 90s
audit_log: /var/log/helixchannel/gateway.ndjson   # empty = stdout

# Only when a same-host TLS terminator (nginx, Caddy) relays PUBLIC traffic
# to a gateway bound on loopback: every request then arrives with a loopback
# peer, which is why exempt_loopback below must be false in that shape. This
# flag recovers the real caller address for the AUDIT LOG ONLY — it is never
# consulted by any admission decision. See auditClientAddr in
# internal/channel/proxy_auth.go for the exact boundary.
trust_forwarded_for_audit: false   # default; set true only behind a same-host relay

gateway_auth:               # caller auth for the reverse-proxy leg
  token_file: /run/secrets/gateway.token          # or token_env: / token_ref:
  exempt_loopback: true     # default; peer address only, never a header — and
                             # MUST be false when the loopback caller is a relay,
                             # not a local client (see trust_forwarded_for_audit above)
  # allow_unauthenticated: true   # only behind an authenticating terminator

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
  allowed_hosts:            # exact host:port matches; empty is rejected, and so
    - api.anthropic.com:443 # is any entry naming this gateway's own host

tls:                        # only needed when the gateway owns a public socket
  cert_file: /etc/helixchannel/tls.crt
  key_file: /etc/helixchannel/tls.key
```

Adding a provider is one entry. Turning it on is one boolean. Nothing is compiled in: route names, prefixes, upstreams and auth modes are all data, and the config is validated at startup so a typo in a route that is switched off today does not become an outage the day it is switched on.

`enabled: false` routes are not registered at all — requests to their prefix return 404, and `/healthz` lists only what is actually being served.

`/healthz` also reports `keys`: per enabled route, the auth mode, whether the route is pooled, how many server-held credentials back it and how many are selectable right now. It is **counts only** — never a key, prefix, suffix, length or fingerprint, because any per-key hint is an oracle for correlating which account served which request. Once a gateway token is configured that inventory is disclosed only to callers the proxy leg would serve; liveness stays anonymous. See [Authenticating reverse-proxy callers](#authenticating-reverse-proxy-callers).

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
# Anonymous liveness — 200 in every posture, and it names the posture
curl -s https://gateway.example.com/healthz
# {"status":"ok","service":"helixchannel-gateway","proxy_auth":"token_loopback_exempt"}

# The inventory needs the gateway token (or a loopback peer, when exempt).
# It reflects the enabled flags, not a hardcoded string.
GW=$(cat /run/secrets/gateway.token)
curl -s -H "X-HLXN-Token: $GW" https://gateway.example.com/healthz
# {"status":"ok","service":"helixchannel-gateway","proxy_auth":"token_loopback_exempt",
#  "routes":["minimax","qwen"],
#  "keys":{"minimax":{"mode":"inject","pooled":false,"keys":1,"available":1,"degraded":false},
#          "qwen":{"mode":"inject","pooled":true,"keys":3,"available":2,"degraded":false}},
#  "connect":true}

# Anonymous from a non-loopback peer: refused before the route is matched.
curl -si https://gateway.example.com/minimax/v1/models | head -3
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: HelixChannel realm="helixchannel-gateway", header="X-HLXN-Token"
# {"error":"gateway_token_required",...}

# A route end-to-end. No PROVIDER credential is needed or wanted: the gateway
# supplies its own. On inject and header modes — single-key and pooled alike —
# an inbound Authorization, Proxy-Authorization, X-Api-Key, Api-Key,
# X-Goog-Api-Key or Cookie is DROPPED before the request is forwarded, so a
# placeholder a client insists on sending never leaves the gateway. Only
# passthrough forwards it. The gateway token rides in its own header and is
# stripped on every mode.
curl -s -H "X-HLXN-Token: $GW" https://gateway.example.com/minimax/v1/models

# The Kilo Code shape: a placeholder bearer AND the gateway token. The
# placeholder is stripped, the server key reaches MiniMax, the request is served.
curl -s https://gateway.example.com/minimax/v1/models \
  -H "X-HLXN-Token: $GW" \
  -H "Authorization: Bearer placeholder"

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

Errors are recorded as classes (`timeout`, `refused`, `dns`, `tls`, `upstream_error`, `redirect_not_followed`) rather than raw strings, so a URL carrying a token cannot reach the log.

Every `proxy_request` line that obtained a response also carries `upstream_host`: the `host:port` the gateway **actually** contacted, read back from the request `net/http` sent. `upstream` remains the route's **configured** base URL.

The two fields are different shapes, and that shows on every line:

```
"upstream":"http://127.0.0.1:19811"   "upstream_host":"127.0.0.1:19811"
```

So **do not alert on `upstream != upstream_host`.** A URL is never equal to a bare host, so that rule matches 100% of lines and pages on entirely healthy traffic. A comparison that means anything has to parse the host out of `upstream` first.

And once it does, it has nothing to find. The forwarder refuses every redirect (see [Redirects are never followed](#redirects-are-never-followed)) and nothing else can move a forward off the host its route configured, so **while redirects are refused there is no reachable divergence between these two fields** — the same conclusion this document reaches from the other direction above. `upstream_host` is not a live alerting signal, and no alert should be written against it.

What it is for is corroboration. This stream used to carry one field holding the *configured* value, so the record this document presents as the forensic one restated configuration back at the reader and was structurally incapable of recording an SSRF the gateway had just performed. Reading the host back off the wire makes "the request went where the route said" a fact the log *states* rather than an assumption the log *inherits* — checkable after the event, and correct on the day some future change does move a request.

The alertable signal in this area is `"error":"redirect_not_followed"`: a reachable, countable outcome that names an upstream that *tried* to move a request off its configured host. A line with no response to read the host from (a `502` after a dial failure) omits `upstream_host`.

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

**Protects against:** an unauthenticated caller spending the gateway's keys, once `gateway_auth` is configured — the reverse-proxy leg refuses before the route is matched, the compare is constant-time, and the loopback exemption is decided from the TCP peer address alone so no header can claim it (see [Authenticating reverse-proxy callers](#authenticating-reverse-proxy-callers)); an upstream exfiltrating the gateway's own credential by answering `3xx` — no redirect is followed on any mode, so no header is ever replayed to a host the route did not name (see [Redirects are never followed](#redirects-are-never-followed)); provider keys spreading across client machines; credential theft from a laptop; passive observation or tampering on the path between agent and provider; a caller reaching the upstream as a different account through one of the **named** headers on the deny-set — `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Api-Key`, `X-Goog-Api-Key`, `Cookie`, plus whatever the route names in `key_header` — on an `inject` or `header` route.

That last one is a **blocklist**, and its scope is exactly the eight names in `callerCredentialHeaders` plus the route's own `key_header`. It is not "a caller cannot reach the upstream as another account"; it is "a caller cannot reach the upstream as another account *through one of these headers*". A provider that also honours a credential in a header nobody has listed yet still receives it. That is a property of the construction, not a gap waiting to be closed by one more name: forwarding is the default and the list is the exception to it, so only an allow-list could make the stronger promise, and an allow-list on a transparent reverse proxy breaks every client that sends a header the gateway has not heard of.

Two of the eight are not credentials at all. `OpenAI-Organization` and `OpenAI-Project` are **spend direction**: on `auth: inject` the gateway supplies the key, so a caller that sets them chooses which organisation or project inside the *gateway's* account is billed. They are stripped for the same reason a credential is — the question the deny-set answers is "whose money does this request spend", not "what authenticates it".

**Does not protect against:**

- **An unauthenticated caller on the reverse-proxy leg when no `gateway_auth` token is configured** — `proxy_auth: loopback_only` or `open`. In those postures reaching the socket is still sufficient to spend every key on every enabled route; `loopback_only` cannot bind a non-loopback address, and `open` is the operator's written-down acceptance that something in front is doing the authenticating. A container that binds loopback and is published with `-p` is reachable from the network in `loopback_only`, and its callers are not loopback peers. Configure a token. See [Authenticating reverse-proxy callers](#authenticating-reverse-proxy-callers).
- **A stolen gateway token**, which is a bearer secret with no allowlist behind it: unlike the `CONNECT` token, whose blast radius is bounded by `allowed_hosts` — a bound that holds only because `allowed_hosts` may no longer name the gateway itself, since such an entry would let a tunnel launder a remote caller into a loopback one and hand it this very token's powers (see [...and it cannot be reached through the gateway's own tunnel](#and-it-cannot-be-reached-through-the-gateways-own-tunnel)) — a gateway token holder can reach every enabled route. Rotate it by changing the source and restarting; there is deliberately no second, overlapping token to make that a zero-downtime operation.
- A compromised gateway host — it holds the keys.
- A client with a valid channel token on the `CONNECT` leg, within its allowlisted scope. The allowlist is what bounds a stolen token, which is why it is required, why it may not name the gateway's own host, and why it should stay short. Note what the load-time half of that check does *not* decide: an allowlisted **name** whose address is loopback is caught only at dial time, and one of the host's own routable addresses under a wildcard bind likewise.
- A caller presenting a credential in some **other** header that the upstream also accepts and that is not on the blocklist, since every remaining non-hop-by-hop header is forwarded (see [What "stripped" does and does not buy you](#what-stripped-does-and-does-not-buy-you)).
- Provider-side logging.

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
    requests: 5000           # hard per-key cap; 0 = uncapped — the default shape
    soft_ratio: 0.8          # retire at 80% of the cap; 0 selects the default
    # tokens: 2000000        # SUPPORTED but ADVISORY; warned about at startup
    # estimate_tokens: 1500  # REQUIRED when tokens is set (see below)
```

**Budget by requests.** A request cap is exact under concurrency; a token cap
bounds the estimate and can overshoot it by `tokens / estimate_tokens`. Both are
supported and neither is going away — see
[Request budgets are exact; token budgets are advisory](#request-budgets-are-exact-token-budgets-are-advisory).

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

Admission enforces the hard cap only — the soft cap remains the planned early
exit that decides when a key leaves rotation under normal traffic.

### Request budgets are exact; token budgets are advisory

The two caps are not two spellings of one feature.

| | `budget.requests` | `budget.tokens` |
|---|---|---|
| what admission counts | settled requests **plus** leases in flight | tokens charged **plus** `estimate_tokens` per lease in flight |
| what a lease costs at settlement | exactly 1 — known before it is admitted | whatever the upstream reports — unknown until it is over |
| worst case in a window | **exact**: never more than the cap | cap plus the overshoot of every admitted lease |
| measured | exact across a 12-combination pool-size × cap sweep at burst 60: zero overspend, zero leaked in-flight, charged always equal to upstream hits | **50x** overspend on the numbers below |

A request cap is exact because `requests + inFlight` is invariant across a
settlement and rises only on reservation, and because a request's cost is known
before it is admitted: it is one request.

A token cap has no such figure. Before a response exists, `estimate_tokens` is
the only thing admission can project an outstanding lease by, so the cap admits
`ceil(tokens / estimate_tokens)` leases at once and each of them then settles
whatever the upstream actually reported.

**Measured.** `tokens: 1000` per key, `estimate_tokens: 100`, real usage 5000
tokens per response. Admission admits `1000/100 = 10` concurrent leases; each
settles 5000; **50000 is charged against a 1000-token cap** — a 50x overshoot.
Driven sequentially the same numbers charge 5000, because the first settlement
drains the key. Concurrency therefore multiplies the overshoot one request
already carries by exactly `tokens / estimate_tokens`.

Token budgets are **supported and are not deprecated**. They are **advisory**:
the hard cap still stops the key at settlement, so the plan is bounded — just
not by the number written in the config. Configure one and the gateway says so
at startup, naming the ratio for that route's own numbers:

```
WARNING: route "minimax-pool" budgets by TOKENS (rotation.budget.tokens=1000,
estimate_tokens=100, window=1h0m0s), and a token cap bounds the ESTIMATE, not the
charge. Admission projects every unsettled lease at estimate_tokens, so this cap
admits up to 10 requests at once (tokens/estimate_tokens = 10) and a concurrent
burst charges the plan up to 10x whatever ONE response overshoots its estimate
by. ...
```

Every shipped configuration budgets by requests. `deploy/helixchannel/gateway.example.yml`
is the only example config, and it is what a node is deployed from; an example
that budgets by tokens is a default an operator inherits without ever making the
decision.

> **Follow-up, not implemented (deliberately).** The known path to an exact
> token cap is **reserved-token accounting**: a lease reserves `estimate_tokens`
> against the cap when it is admitted and *reconciles* that reservation at
> settlement — releasing the reserved figure and charging the real one — so the
> projection is self-correcting and a window's overshoot is bounded by what a
> single in-flight request exceeds its estimate by rather than by
> `ceil(cap/estimate)` of them. It changes the store's accounting model and
> every caller that settles a lease. The operator chose request budgets over it
> for now; this note is the record of that choice, so that "token caps are
> advisory" reads as a decision rather than as an unnoticed defect.

### Unsettled leases are reclaimed after 30 minutes

Counting leases in flight has a corollary: a reservation that is never settled
holds a slot, and window rollover cannot take it back — rollover has no way to
tell a leaked slot from a request that is still running, and zeroing in-flight
counts would strand every live lease. Left alone, N leaks against a cap of N
retire a key for the lifetime of the process, with `/healthz` reporting it
selectable, available and not degraded throughout.

The gateway itself does not leak: `handleProxy` defers `Settle` on every path,
including panics. The exposure is `RotationStore.Next`, which is exported and
documented for direct use and hands back a bare index with no lease to settle.

So a reservation left outstanding longer than the **lease timeout** — 30 minutes
by default, `WithLeaseTimeout` to change it — has its slot returned. The value is
a deliberate over-estimate of the longest legitimate request: reclaiming a slot
whose request is genuinely still running lets that one request be re-admitted,
which is the only case in which the request cap is not exact. `Reclaimed` in a
key's snapshot counts these for the store's lifetime, and is not reset by a
rollover: a non-zero value is a bug in a caller of `Next`, not a condition of the
upstream, and a leak whose evidence clears every window is a leak nobody finds.

The window is **tumbling** and rollover is **lazy** — evaluated from the clock on
every call. The gateway therefore starts no timer goroutine for rotation, and a
test can advance an injected clock instead of sleeping. An explicit retirement
whose deadline outlives the window (a one-hour provider cooldown, for instance)
survives a five-minute accounting boundary.

### Refused before dispatch: two 503s, never a 502

A request can be refused before any upstream call for **two different reasons**,
and they are two different operational facts. Both answer `503` with
`Retry-After`; the `error` code, the hint and the wait tell them apart, and so
does the metric.

**`keys_exhausted` — the plans are spent.** No key on the route is selectable:
every one is drained by its own budget or parked by an upstream quota signal.

```
HTTP/1.1 503 Service Unavailable
Retry-After: 90
Content-Type: application/json

{"error":"keys_exhausted","route":"minimax-pool","retry_after_seconds":90, ...}
```

`Retry-After` is the true minimum wait across all keys — a time the store can
actually name, since it is until a window rolls or a retirement expires — floored
at 1s (a `Retry-After: 0` tells a client nothing) and clamped to
`max_retry_after` (default 1h; several agents treat an hours-long value as
fatal). `/healthz` reports `degraded: true`. **Page on it.** It is a billing
question and the traffic is not being served.

**`admission_limited` — the keys are healthy, the concurrency is not.** At least
one key is selectable and none is retired or drained, but every selectable key is
already at its hard cap once the leases **in flight** are counted.

```
HTTP/1.1 503 Service Unavailable
Retry-After: 1
Content-Type: application/json

{"error":"admission_limited","route":"minimax-pool","retry_after_seconds":1, ...}
```

`Retry-After` is the **floor**, because the condition clears when an outstanding
lease settles and that is not a time anything here can name. `/healthz` reports
the route **undegraded**, with every key `available` — and it is right to.
**Do not page on it.** It means the route is being offered more concurrency than
its per-window plan allows; the answer is a larger `budget`, more keys, or less
concurrency, not a billing investigation.

Reporting the second as the first is a defect this document previously described
as correct behaviour. A route refusing on admission reported `{keys: 2,
available: 2, degraded: false}`, every key `Selectable` and none `Drained`, while
telling callers "every upstream key on this route is retired or drained" — which
sent an operator hunting a billing problem that did not exist, with the only
contradicting signal on their screen at the same time.

In both cases the upstream is **not** contacted. That is deliberately distinct
from `502 upstream unavailable`: an operator paging on 502 is hunting a broken
upstream, and a request refused before dispatch may have made no upstream contact
at all. Collapsing the two is how a quota outage gets triaged as an outage.

Neither 503 body nor either audit line ever carries key material: only the route
name, the reason and the wait.

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

The estimate is also what makes a token cap inexact rather than merely
approximate, since it is what admission projects an unsettled lease by; a
configured token budget is warned about at startup for that reason. See
[Request budgets are exact; token budgets are advisory](#request-budgets-are-exact-token-budgets-are-advisory).

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

Every route should budget by `requests`. On a header route the alternative is
not merely inexact but meaningless: header-auth upstreams report no
`usage.total_tokens`, so **every** sample is an estimate and a token cap would be
spent entirely in `estimate_tokens` increments that no upstream figure ever
corrects.

`policy: least_tokens` is **rejected at config load** on an `auth: header` route:
with every sample estimated it would behave exactly as `least_used` while
claiming to balance tokens. Everything else composes normally — a pooled header
route leases, retires, emits `auth_mode: header` alongside `key_index`, and
answers the same 503 with `Retry-After`.

### Metric

```
llm_cluster_router_helixchannel_key_retired_total{route,reason}
llm_cluster_router_helixchannel_admission_refused_total{route,reason}
```

The first counts **keys leaving rotation**. `reason` is one of:

| reason | meaning |
|---|---|
| `cap` | this gateway's own accounting — the soft cap or the hard cap |
| `quota` | an upstream quota signal (HTTP 429 or 402) |
| `error` | repeated upstream failure that is not a quota signal |

The second counts **callers turned away before any upstream call**, and its
`reason` is exactly the `error` code in the 503 body and in the audit line, so
one vocabulary spans the response, the log and the series:

| reason | meaning | alert |
|---|---|---|
| `keys_exhausted` | no key is selectable; the plans are spent | page — billing |
| `admission_limited` | keys are healthy; every one is at its cap with leases in flight | do not page — capacity |

They are separate families because a retirement and a refused caller are
different events: one key leaving rotation can refuse thousands of callers, and
one refused caller need not mean any key left. An alert written against the
retirement series cannot see an admission refusal at all, and an alert written
against `admission_refused_total` without the `reason` label would page on the
harmless half.

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
