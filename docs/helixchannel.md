# HelixChannel — encrypted production wire

This document is the canonical reference for the **HelixChannel** encrypted
channel. It is the operator-facing name for the AES-256-GCM application-layer
encrypted HTTP channel that fronts every router deployment. It is the brand
name for the dual-listener design introduced incrementally across
v18704-v18710 and standardised by
[ADR-085](https://github.com/nfsarch33/cursor-global-kb/blob/main/adrs/ADR-085-helixchannel-prod-wire.md).

For DNS + Let's Encrypt + nginx reverse-proxy procedure on the public
hostname (`helixchannel.cylrl.dev`), see
[`docs/helixchannel-deployment.md`](helixchannel-deployment.md). For the
release-gate procedure, see
[`docs/release-readiness.md`](release-readiness.md).

## Threat model

- Wire captures on the path between the router and the upstreams see
  ciphertext only; plaintext LLM prompts, completions, and bearer tokens
  never appear on the wire.
- An attacker who can R/W to the TCP socket cannot silently tamper with a
  request because every frame is AES-GCM authenticated. Tampering events
  are counted in
  `llm_cluster_router_decrypt_failed_total{listener="aes-mtls"}` and
  surface as an incident in Grafana.

## ListenerFactory contract

The router owns a `proxy.ListenerFactory` per channel. The factory's
`Channel()` returns a stable identifier (currently `"aes-mtls"`) used for
metrics, logging, and config keys. The factory's `Listen(ctx, addr)`
returns a bound `net.Listener` plus the `ServeLoop` that should be run for
it. The production `main.go` constructs the AES/mTLS factory by default;
the `HELIXCHANNEL_ENABLED=false` env override keeps the legacy plain HTTP
listener for back-compat.

## Operator-facing config

| Key | Default | Notes |
| --- | --- | --- |
| `HELIXCHANNEL_ENABLED` | `true` | Toggle the AES/mTLS factory. `false` keeps the legacy plain HTTP listener for back-compat. |
| `HELIXCHANNEL_KEY` | demo placeholder | 32-byte AES-256 key. Production callers load this from a secret store (see `internal/proxy/listener.go`). |
| `HELIXCHANNEL_LISTEN` | `cfg.Listen` | Override the bind address (host:port). Falls back to the legacy `listen:` YAML key. |

The response header `HelixChannel-Version: <version>` is stamped on every
reply; `curl -I https://host/` is the canonical proof-of-name artifact.

## Additive metric families (v18712-1)

Both legacy and new label keys are populated by the dual-listener
ServeLoop, so existing Grafana panels keep working:

- `llm_cluster_router_connections_total{listener="aes-mtls",direction="in"}`
  — legacy channel label
- `llm_cluster_router_helixchannel_connections_total{direction="in"}`
  — operator-facing alias

## Per-tenant channel preference (v18714-7)

Both encrypted channels are simultaneously live and operators / clients
choose which one to dial. The default for new tenants is the AES-256-GCM
channel on `helixchannel.cylrl.dev:443` (more secure); the SSH-22 SOCKS5
channel on `helixon-tunnel:22` is the fallback when AES/mTLS fails or when
a consumer (e.g. the Kilo Code pilot, CI runners) prefers the
lower-friction SSH path.

| Preference | Behaviour |
|---|---|
| `--channel prefer-aes-mtls` (default) | Try AES-256-GCM first; fall back to SOCKS5 on transport failure. |
| `--channel prefer-socks5` | Try SSH-22 SOCKS5 first; fall back to AES-256-GCM on transport failure. |
| `--channel aes-mtls` | Force AES-256-GCM. Hard fail if unreachable. |
| `--channel socks5` | Force SOCKS5. Hard fail if unreachable. |
| `--channel auto` | Probe both, pick the faster path per session. |

Equivalent env var: `LLMROUTER_CHANNEL_PREFERENCE` (one of
`prefer-aes-mtls|prefer-socks5|aes-mtls|socks5|auto`). The default when
unset is `prefer-aes-mtls`.

The canonical observability signal is
`helixchannel_session_total{channel="...",outcome="..."}` (per v18714-3),
and the Grafana dashboard
`observability/grafana/helixchannel-sessions-dashboard.json` visualises
the channel mix. Per-tenant routing decisions are recorded under the
`channel` label so operators can audit which tenants lean on which
transport.

Decision rationale (full Bayesian analysis): see
[`cursor-global-kb/reports/research/v18714-7-channel-decision-socks5-vs-aesmtls.md`](https://github.com/nfsarch33/cursor-global-kb/blob/main/reports/research/v18714-7-channel-decision-socks5-vs-aesmtls.md)
(posterior P(both, configurable per-tenant) = 0.86; second-place SOCKS5-only
at 0.09; acceptance threshold 0.70).

## Production ingress (v18714+)

The HelixChannel production wire reaches operators and pilot consumers via
`TCP/443` (TLS-terminating nginx → `127.0.0.1:14443` on the Lightsail
instance `helixon-tunnel` at `52.64.8.153`), per
[ADR-086](https://github.com/nfsarch33/cursor-global-kb/blob/main/adrs/ADR-086-helixchannel-port-443-migration.md).
The application-layer AES-256-GCM channel is unchanged; only the
transport moved from SSH-22 (pilot) to TLS/443 (production pilot).
Canonical reverse-proxy runbook:
[`cursor-global-kb/sop/lightsail-port-443-reverse-proxy.md`](https://github.com/nfsarch33/cursor-global-kb/blob/main/sop/lightsail-port-443-reverse-proxy.md).

## Public hostname (v18714-11)

Pilots (Kilo Code, Peer, and any IDE that refuses to pin an
OpenAI-compatible endpoint to a raw IP) target
`https://helixchannel.cylrl.dev/v1`. The DNS A-record is managed via
DreamHost and points at the Lightsail static IP `52.64.8.153`; TLS is
terminated by Let's Encrypt via `certbot` on the Lightsail host. See
[`docs/helixchannel-deployment.md`](helixchannel-deployment.md) for the
full DNS + cert + nginx runbook.

```bash
# Probes both transports and recommends the better path.
./helixchannel endpoint-check
# uses HELIXCHANNEL_BASE_URL env > --base-url flag > default
# https://helixchannel.cylrl.dev to derive the host.
```

## `helixchannel` CLI (`cmd/helixchannel/`)

```bash
go build -o helixchannel ./cmd/helixchannel

./helixchannel doctor           # JSON envelope: release-gate + ADR-085 + AES key + observability
./helixchannel version          # prints HelixChannel-Version + channel preference
./helixchannel factory-probe    # asserts ListenerFactory contract for the active channel
./helixchannel key-check        # validates the AES key length + format (32 bytes)
./helixchannel header-stamp     # exercises HelixChannel-Version response header
./helixchannel endpoint-check   # probes both transports and recommends the better path
```

The `doctor` subcommand is the canonical pre-deploy hook for any Lightsail
release; it returns GREEN/RED + a JSON envelope citing
[ADR-085](https://github.com/nfsarch33/cursor-global-kb/blob/main/adrs/ADR-085-helixchannel-prod-wire.md),
the AES key file presence, and the live observability signal.