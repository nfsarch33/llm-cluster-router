# HelixChannel Distribution (v18716.6)

This directory is the canonical source for distributing HelixChannel
on the Helixon fleet. It produces:

| Artefact | Path | Purpose |
| --- | --- | --- |
| Container image | `Containerfile.helixchannel` (multi-stage Go 1.26) | Runtime image containing the daemon, the operator CLI, and the observability smoke binary |
| Quadlet unit | `quadlet/helixchannel-tunneld-minimax.container` | systemd-managed podman service that runs the daemon against the operator's MiniMax TokenPlanMax subscription |
| Quadlet unit | `quadlet/helixchannel-tunneld-qwen.container` | systemd-managed podman service that runs the daemon against the Aliyun DashScope Qwen Token Plan |
| Quadlet unit | `quadlet/helixchannel-nginx.container` | Lightsail-side reverse-proxy that terminates TLS on :443 and forwards to the tunneld over the AES-256-GCM envelope (ADR-085) |

## Build

```bash
cd ~/Code/llm-cluster-router
podman build \
    -f deploy/helixchannel/Containerfile.helixchannel \
    -t helixon/tools-helixchannel:v0.2.0 \
    .
```

Expected: exit 0 in ~90s on wsl3; the image tag is the canonical
local registry name used by the Quadlet units.

## Smoke

```bash
# Daemon health: requires a router.yml in place.
timeout 30 podman run --rm \
    -v "$PWD/router.sample.yml:/etc/helixchannel/router.yml:ro" \
    helixon/tools-helixchannel:v0.2.0 --help | head -20

# CLI smoke:
timeout 30 podman run --rm helixon/tools-helixchannel:v0.2.0 \
    helixchannel --help

# Dual-listener-demo smoke (observability path):
timeout 30 podman run --rm helixon/tools-helixchannel:v0.2.0 \
    dual-listener-demo --aes-addr 127.0.0.1:18080 \
    --socks5-addr 127.0.0.1:11080 --metrics-addr 127.0.0.1:18090 \
    --mock-body "hi" --agentrace-log /tmp/agentrace-router.ndjson
```

## Quadlet deploy (Lightsail + win1-wsl1)

```bash
# 1. Copy the units into the operator's systemd tree:
mkdir -p ~/.config/containers/systemd
cp deploy/helixchannel/quadlet/helixchannel-*.container \
    ~/.config/containers/systemd/

# 2. Pull the image into the local registry (one-time per image
# tag; the units reference helixon/tools-helixchannel:v0.2.0).
podman pull helixon/tools-helixchannel:v0.2.0

# 3. Render secrets via op inject so the keyring file lands with
# 0600 perms and never appears in argv:
op inject -i deploy/helixchannel/keys/minimax.json.tpl \
    -o ~/.local/share/helixchannel/keys/minimax.json
chmod 0600 ~/.local/share/helixchannel/keys/minimax.json

# 4. Reload systemd + start the units:
systemctl --user daemon-reload
systemctl --user enable --now \
    helixchannel-tunneld-minimax.service \
    helixchannel-tunneld-qwen.service \
    helixchannel-nginx.service

# 5. Confirm /healthz:
curl -fsS http://127.0.0.1:8080/healthz
```

## Kilo Code → HelixChannel path (operator quickstart)

This is the canonical configuration for the Kilo Code VS Code
extension (v18716.1 / ADR-085 / ADR-086). The full walkthrough is
in `docs/kilo-code-setup.md`; the trimmed configuration is:

```jsonc
// Kilo Code → Settings → Providers → Custom OpenAI
{
    "openAiBaseUrl": "https://52.64.8.153/minimax/v1",
    "openAiApiKey":  "<value from 1Password: HelixonSafe / minimax-api-1>",
    "openAiModel":   "MiniMax-M3"
}
```

After saving, the Kilo Code panel in VS Code will route every
prompt through:

```
VS Code Kilo Code
  → HTTPS POST https://52.64.8.153/minimax/v1/chat/completions
  → Lightsail nginx (TLS termination on :443)
  → helixchannel-tunneld-minimax (host network :8080)
  → AES-256-GCM application-layer encrypted tunnel (ADR-085)
  → upstream LLM (MiniMax-M3)
  → response back to Kilo Code in the same pipe
```

### Verifying the wire

```bash
# 1. Endpoint reachable?
helixon/tools-helixchannel:v0.2.0 helixchannel endpoint-check \
    --host 52.64.8.153

# 2. Kilo Code smoke test (curl):
curl -fsS https://52.64.8.153/minimax/v1/chat/completions \
    -H 'Authorization: Bearer <1password-key>' \
    -H 'Content-Type: application/json' \
    -d '{"model":"MiniMax-M3","messages":[{"role":"user","content":"hello"}]}'

# 3. Kilo Code smoke test (kilo-verify; production parity):
podman run --rm helixon/tools-helixchannel:v0.2.0 \
    helixchannel kilo-verify \
    --host 52.64.8.153 \
    --provider minimax
```

## Observability wiring (cross-link)

The runtime image carries the v18716.5 observability surface
(channel-tagged Agentrace bridge, periodic `engram.doctor` ingest,
OTel collector + Grafana dashboard). On a fresh deploy, point the
Quadlet units at the operator's OTel collector via:

```bash
# /etc/helixchannel/router.yml (or env override):
otlp_endpoint: "http://127.0.0.1:4317"
agentrace_bridge_path: "%h/logs/helixchannel/agentrace-tunneld.ndjson"
```

The collector config + dashboard ship with this repo at:

- `configs/otel/collector-config.yaml`
- `configs/grafana/dashboards/helixchannel-overview.json`

## Why Quadlet (not docker-compose / helm)

- Per `cursor-config/rules/00-p0-podman-only.mdc`, podman is the
  fleet container runtime.
- Quadlet is systemd-managed; `Restart=on-failure` is built in.
- The unit files are plain text, reviewable, and live next to
  every other Helixon service unit (`~/.config/containers/systemd/`).
- `helixon doctor fleet` already enumerates Quadlet units; the
  helixchannel units join that surface without a new discovery
  path.

## Cross-references

- `docs/kilo-code-setup.md` — full operator walkthrough.
- `docs/release-readiness.md` — v18716 release checklist.
- `configs/otel/collector-config.yaml` — OTel collector config.
- `configs/grafana/dashboards/helixchannel-overview.json` — Grafana dashboard.
- `cmd/helixchannel/` — operator CLI (hardened in v18716.3).
- `cmd/dual-listener-demo/` — observability smoke (v18709 / v18716.5).

## Versioning

| Version | Date | Sprint | Notes |
| --- | --- | --- | --- |
| v0.2.0 | 2026-07-22 | v18716.6 | Initial Quadlet distribution + multi-binary Containerfile. |