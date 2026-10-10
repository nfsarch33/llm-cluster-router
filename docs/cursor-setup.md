# Cursor setup — routing Cursor through llm-cluster-router

Cursor's desktop app supports a custom OpenAI-compatible endpoint ("Override
OpenAI Base URL" in Cursor Settings → Models). This guide wires it to the
router so Cursor's traffic lands on the local model pool — with per-agent
gating, task-aware routing, and quota-aware fallback behind one URL.

## Settings

| Cursor setting | Value |
|---|---|
| OpenAI Base URL | `http://127.0.0.1:8787/v1` (router on the same host) — from another LAN/Tailscale machine use that host's address, never an internet-exposed one |
| OpenAI API Key | **the router's `auth_token`** — see below |
| Model | `qwen3.8-27b-local`, or any model name when `force_class` is set (see below) |

### Which key goes in the key field

The router authenticates callers with its own bearer token (`auth_token` in
the router config, provisioned via 1Password). That is the value Cursor
needs. Fetch it with the `op` CLI on the router host (service account is
already configured on the router host):

```bash
op read "op://<vault>/<router-auth-item>/credential"
```

Provider keys (MiniMax plans, etc.) are **never** entered into Cursor — they
live server-side on the router/gateway and are attached per-request with
quota-aware rotation. Cursor only ever holds the router token, which you can
rotate without touching any provider account.

## The model-name problem, solved by force_class

Cursor's UI insists on sending model ids it knows (`gpt-4o`, ...). Rather
than fighting the UI, pin ALL cursor traffic to a policy class in the
smart-route policy:

```yaml
agents:
  cursor:
    enabled: true
    force_class: code     # every cursor request routes as class "code",
                          # whatever model id the UI sends
```

With that in place the model field in Cursor is cosmetic: the router rewrites
the request to the class's model (e.g. `qwen3.8-27b-local`) and injects the
class's sampling parameters. Turn Cursor's route off entirely with:

```bash
scripts/agent-route.sh cursor off     # -> Cursor gets 403 at the router
scripts/agent-route.sh cursor on
```

## Identification

Cursor is auto-detected from its User-Agent. If you front the router with
anything that strips UAs, add the explicit header in Cursor's custom-header
settings (when available): `X-Helixon-Agent: cursor`.

## Hosted-provider path (MiniMax plans)

When policy routes a class to the MiniMax node, the router carries the three
token plans (`api_keys`) itself: per-key cooldown on quota exhaustion,
same-node retry on the surviving keys, then tier fallback. Nothing about
plans or keys is visible from the Cursor side. Reference config:
[`configs/router.minimax.example.yml`](../configs/router.minimax.example.yml).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401` from the router | wrong/absent router token | re-read the token from 1Password; check `auth_token` in the router config |
| `403 route disabled for agent "cursor"` | Cursor's boolean is off | `scripts/agent-route.sh cursor on` |
| Responses from a model you didn't pick | `force_class` is set (working as intended) | remove `force_class` from the `cursor:` entry to honour explicit model ids |
| Slow first token at very long context | 200k-context prompt processing | expected: ~1.7k tok/s prompt speed; see [benchmarks.md](benchmarks.md) |
