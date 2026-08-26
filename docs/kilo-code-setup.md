# Kilo Code through HelixChannel

End-to-end setup for the [Kilo Code](https://marketplace.visualstudio.com/items?itemName=kilocode.Kilo-Code) VS Code extension against a HelixChannel gateway. Kilo speaks the OpenAI-compatible API, so it uses the reverse-proxy routes: you change one base URL and never put a provider key in the editor.

The same steps work for any OpenAI-compatible client — Cursor, Continue, Codex CLI, `curl`.

## 1. Gateway side

A route per provider, each with its own feature flag:

```yaml
listen: "127.0.0.1:14445"
audit_log: /var/log/helixchannel/gateway.ndjson

gateway_auth:                 # required unless listen is loopback
  token_file: /run/secrets/gateway.token

routes:
  - name: minimax
    prefix: /minimax/
    upstream: https://api.minimaxi.com
    auth: inject
    key_file: /run/secrets/minimax.key
    enabled: true
```

Keys stay in root-owned files that only the gateway can read:

```bash
sudo install -d -m 0750 /run/secrets
printf '%s' "$PROVIDER_KEY" | sudo tee /run/secrets/minimax.key >/dev/null
sudo chmod 640 /run/secrets/minimax.key

# The gateway token, the same way. This one is the CLIENT's credential: it
# authorises using the gateway at all, and it is a different secret from the
# CONNECT channel token.
openssl rand -hex 32 | sudo tee /run/secrets/gateway.token >/dev/null
sudo chmod 640 /run/secrets/gateway.token
```

Start it (container or systemd — see [HelixChannel](helixchannel.md#running-it)) and confirm the route is live:

```bash
# Anonymous: liveness only, and it names the posture in force.
curl -s https://gateway.example.com/healthz
# {"status":"ok","service":"helixchannel-gateway","proxy_auth":"token_loopback_exempt"}

# With the token: the live route set.
curl -s -H "X-HelixChannel-Token: $GW_TOKEN" https://gateway.example.com/healthz
# {"status":"ok","service":"helixchannel-gateway","proxy_auth":"token_loopback_exempt",
#  "routes":["minimax"],"keys":{...},"connect":false}
```

`routes` reflects what is actually enabled. If a provider is missing here, its `enabled` flag is off.

## 1b. The gateway token (every client that is not on the gateway host)

**This is a breaking change if you already run a gateway.** Once `gateway_auth`
is configured, a caller reaching the gateway from another host must send the
token in its own header:

```
X-HelixChannel-Token: <the contents of /run/secrets/gateway.token>
```

It is **not** the `Authorization` header — that one still carries the harmless
placeholder described below, and the gateway still strips it. Requests without
the gateway token are answered `401` with a
`WWW-Authenticate: HelixChannel …` header naming where it goes, and they never
reach the provider.

Callers whose TCP peer is loopback (anything on the gateway host itself) are
exempt by default and need no token, so nothing on that host changes. The
exemption is decided from the connection's peer address, so it cannot be claimed
with `X-Forwarded-For`.

Both clients this repo documents can send it: Kilo Code has a **Headers** field
on the OpenAI-Compatible provider, and Claude Code has `ANTHROPIC_CUSTOM_HEADERS`
(one `Name: Value` pair per line). Neither needs a workaround.

If some other client cannot send a custom header at all, the supported answer is
to make it a loopback caller — reach the gateway over an SSH tunnel or a tailnet
address bound on loopback — or to put an authenticating terminator in front and
let it hold the token. Do not disable `gateway_auth` to work around it.

**A caution about `exempt_loopback` when a terminator is involved.** The
exemption asks "is the TCP peer on 127.0.0.0/8", and it answers that honestly.
It does not, and cannot, ask "is the caller trustworthy". If an nginx or Caddy
server block on the same host proxies *public* traffic to a loopback-bound
gateway, then every public request arrives with a loopback peer and the default
`exempt_loopback: true` waives the token for all of them — a gateway that looks
configured and authenticates nobody. Set `exempt_loopback: false` on any gateway
whose loopback callers are relays rather than local clients.

Roll it out in this order so no traffic is dropped: create the token, configure
every remote client with it *first* (nothing rejects it yet), then add the
`gateway_auth` block to the gateway and restart.

## 2. Verify the wire before touching the editor

```bash
helixchannel kilo-verify \
  -base-url https://gateway.example.com/minimax/v1 \
  -model MiniMax-M3
```

**Run this from the gateway host** when `gateway_auth` is configured.
`kilo-verify` sends no `X-HelixChannel-Token`, so from anywhere else it is
refused `401` and reports a broken wire that is not broken. From the gateway
host it is a loopback caller and is exempt (use `-base-url
http://127.0.0.1:14445/minimax/v1`).

```json
{"verdict":"pass","base_url":"https://gateway.example.com/minimax/v1","model":"MiniMax-M3","latency_ms":1884,"error_class":"none"}
```

Exit codes: `0` pass, `1` fail (wire broken — read `error_class`), `2` skip (no client key configured). Add `-insecure` if the gateway still serves a self-signed certificate.

Doing this first means that if the extension misbehaves later, you already know whether the wire is good.

## 3. Configure the extension

Extensions panel → search "Kilo Code" → Install. Open the Kilo Code panel, then the settings gear:

| Field | Value |
|---|---|
| API Provider | `OpenAI Compatible` |
| Base URL | `https://gateway.example.com/minimax/v1` |
| API Key | any non-empty placeholder, e.g. `helixchannel-client` |
| **Headers** | `X-HelixChannel-Token` → the gateway token |
| Model | `MiniMax-M3` |
| Max Tokens | `2048` |
| Temperature | `0.7` |

The **Headers** field is the one that matters and the one people miss. Kilo
Code's own documentation describes it as *"Headers (optional) — Custom HTTP
headers as key-value pairs"*, and the extension merges those into every request
it sends. This was verified rather than assumed: the field is documented for the
OpenAI-Compatible provider, and `customHeaders` is applied in the extension's
own request path.

One consequence of how that merge works is worth knowing. The extension sets
`Authorization: Bearer <API Key>` **after** merging your custom headers, so an
`Authorization` entry in the Headers field is overwritten and cannot be used to
carry anything. `X-HelixChannel-Token` is unaffected.

Recent Kilo Code builds are rebuilt on the Kilo CLI and share one JSONC config
across the CLI, VS Code and JetBrains, so the same provider can be written
directly to `~/.config/kilo/kilo.jsonc` instead of clicking through the panel:

```jsonc
{
  "provider": {
    "helixchannel-minimax": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "HelixChannel (MiniMax)",
      "options": {
        "baseURL": "https://gateway.example.com/minimax/v1",
        "apiKey": "helixchannel-client",
        "headers": { "X-HelixChannel-Token": "<the gateway token>" }
      },
      "models": { "MiniMax-M3": { "name": "MiniMax-M3" } }
    }
  }
}
```

Check which layout your installed build uses before scripting this: older
versions kept provider settings in VS Code `globalStorage` instead.

Three details that cause most failures:

- **The route prefix is part of the base URL.** `https://gateway.example.com/v1` will 404 — the gateway needs `/minimax/v1` to know which upstream you mean. The 404 body lists the routes that are available.
- **The API key is a placeholder.** The gateway replaces it with the real key. That is the entire point: the editor never holds a provider credential. If the gateway is running in `passthrough` mode instead, then the key you enter *is* the one used.
- **The gateway token is a separate field.** If the gateway requires one (see [1b](#1b-the-gateway-token-every-client-that-is-not-on-the-gateway-host)), it goes in **Headers**, not in API Key. Putting it in the API Key field would send it to the provider rather than to the gateway — on an inject route the gateway strips that field before forwarding, so the token would be discarded and the request refused; on a `passthrough` route it would be forwarded to the provider verbatim, which is worse.

If the gateway serves a self-signed certificate, enable the extension's TLS-skip option. Prefer a CA-issued certificate and leave verification on.

## 4. Confirm end to end

Send a message in the Kilo Code panel, then check the gateway:

```bash
tail -2 /var/log/helixchannel/gateway.ndjson
```

```json
{"ts":"2026-08-20T01:20:11Z","event":"proxy_request","route":"minimax","auth_mode":"inject","method":"POST","path":"/minimax/v1/chat/completions","status":200,"latency_ms":1435}
```

`auth_mode: inject` confirms the server-side key was applied, and no credential appears in the log.

## Adding another provider

Append a route and restart the gateway:

```yaml
  - name: codex
    prefix: /codex/
    upstream: https://api.openai.com
    auth: inject
    key_file: /run/secrets/openai.key
    enabled: true
```

Clients switch by changing base URL to `https://gateway.example.com/codex/v1`. Turning a provider off again is `enabled: false` — its prefix then returns 404 and the key is no longer read.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `404` with a `routes` list | Missing or wrong route prefix in the base URL | Use `/<route>/v1`; compare against the list in the response |
| `404` and your route is absent from the list | Route disabled | Set `enabled: true` and restart |
| `401`/`403` from the provider | Server-side key rejected | Check the key file contents and provider quota; `error_class` in the audit log narrows it |
| `502` with `error_class: dns` or `refused` | Gateway cannot reach the upstream | Check egress from the gateway host |
| `502` with `error_class: timeout` | Upstream slow | Raise `timeout` on the route |
| TLS errors in the extension | Self-signed certificate | Issue a proper certificate, or enable TLS-skip while piloting |

## Local models through the router

To use the local Qwen3.8-27B (200k context, `qwen-local.service` on the GPU
host) instead of a hosted provider, point Kilo Code at the router:

- **Base URL:** `http://127.0.0.1:8787/v1`
- **Model:** `qwen3.8-27b-local` — or `auto` to let the smart-route policy
  pick per task (code / long-context / chat).
- **API key:** the router's `auth_token` (fetch via 1Password `op` CLI; the
  router accepts it as a Bearer token). Never a provider key — provider keys
  stay server-side.
- Optionally set the `X-Helixon-Agent: kilo-code` header so the per-agent
  gate and metrics identify the caller precisely (User-Agent sniffing covers
  the default Kilo Code UA otherwise).

### Troubleshooting additions

| Symptom | Cause | Fix |
|---|---|---|
| `403 route disabled for agent "kilo-code"` | The agent's boolean is off in the smart-route policy | `scripts/agent-route.sh kilo-code on` |
| `model "auto" not found` | `smart_route` disabled in router config | set `smart_route.enabled: true` + `policy_file` |

> Note: the same steps apply to Codex CLI, but the shipped policy gates
> `codex` **off** by default — flip it with `scripts/agent-route.sh codex on`.
