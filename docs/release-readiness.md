# Release Readiness

This document is the canonical reference for the `llm-cluster-router` Lightsail
release gate and the surrounding release-readiness procedure. It is referenced
from the top-level [README](../README.md) so the README stays a quickstart.

## Release gate (`scripts/release-gate.sh`)

The router ships with a one-command release gate that runs every
Lightsail-readiness check from [ADR-083](../adrs/ADR-083-llm-cluster-router-lightsail-threat-model.md)
and reports a single GREEN/RED verdict. It is the canonical pre-deploy
hook for any Lightsail release.

```bash
# Full gate (sentrux + ADR-083 + pentest + decrypt-forward + realmodel + doctor)
bash scripts/release-gate.sh

# Skip the realmodel E2E (requires DashScope credentials) or the
# per-fleet doctor when running offline / in CI.
bash scripts/release-gate.sh --no-realmodel
bash scripts/release-gate.sh --no-doctor

# Machine-readable output (single JSON envelope on stdout).
bash scripts/release-gate.sh --json
```

### Gate rows

| # | Row | What it checks |
|---|---|---|
| 1 | `sentrux` | Structural regression vs saved baseline (modularity, coupling, depth) |
| 2 | `adr083-checklist` | ADR-083 file exists + frontmatter + ≥12 post-conditions C1..C13 paired with verifiers |
| 3 | `pentest` | Go adversarial tests (SOCKS5 fuzz + redaction + metric integrity) |
| 4 | `decrypt-forward` | Wire-doctor E2E (no-plaintext + tamper-rejected binary post-conditions) |
| 5 | `realmodel` | DashScope streaming SSE bridge through SSH-22 SOCKS5 (requires `DASHSCOPE_API_KEY`) |
| 6 | `doctor` | `runx workspace doctor --quick` + sentrux shell-leak scan |
| 7 | `run_prod_wire` | HelixChannel production wire smoke (`scripts/release-gate.sh run_prod_wire`) — exercises the dual-listener factory through `cmd/helixchannel factory-probe` and verifies the `HelixChannel-Version` header round-trip |

The corresponding ADR-083 / ADR-085 metrics surface on `/metrics`:

- `llm_cluster_router_connections_total{listener,outcome}` — connection
  counts partitioned by `socks5`/`aes-mtls` listener and outcome
  (`success`, `rejected`, `tampering`).
- `llm_cluster_router_decrypt_failed_total{listener}` — AES-GCM
  authentication failures per listener. Any non-zero rate over a
  1-minute window is an incident.

See [ADR-083](../adrs/ADR-083-llm-cluster-router-lightsail-threat-model.md)
for the threat model and binary post-conditions.

## Cross-references

- **ADR-083** — Lightsail threat model
  (`../adrs/ADR-083-llm-cluster-router-lightsail-threat-model.md`)
- **ADR-085** — HelixChannel production wire (lives in
  `cursor-global-kb/adrs/ADR-085-helixchannel-prod-wire.md`, supersedes ADR-084)
- **Lightsail port-443 reverse-proxy procedure** —
  `cursor-global-kb/sop/lightsail-port-443-reverse-proxy.md` (v18714-1;
  supersedes the v18712-3 stub; ADR-086 path A2). The TCP/443 firewall
  rule + nginx reverse-proxy in front of `127.0.0.1:14443` is the
  operator-facing ingress for the HelixChannel production wire once
  v18714-1 lands. AES-256-GCM application-layer channel is preserved
  on the inner tunnel; only the transport moves from SSH-22 to TLS/443.
- **Operator red-triage runbook** —
  `cursor-global-kb/sop/operator-red-triage.md` (v18712-5a)
- **HelixChannel doctor probe** — `cmd/helixchannel/` binary with
  `version`, `factory-probe`, `key-check`, `header-stamp`, `doctor`
  subcommands. The `doctor` subcommand runs the same release-readiness
  checks as the shell gate but reports a JSON envelope suitable for
  automation.

## Pre-deploy quick validation

```bash
# 1. Build the doctor probe
go build -o helixchannel ./cmd/helixchannel

# 2. Confirm AES key length and observability importable
./helixchannel doctor

# 3. Bind an ephemeral port via the listener factory (no upstream required)
./helixchannel factory-probe --addr :0

# 4. Print the canonical HelixChannel-Version header
./helixchannel header-stamp

# 5. Run the full shell gate for the GREEN/RED verdict
bash scripts/release-gate.sh
```

A GREEN `release-gate.sh` verdict plus a GREEN `./helixchannel doctor` JSON
envelope is the binary post-condition for any Lightsail release.

## Why this document was relocated

This section previously lived in `README.md` (lines 248-289 in the
pre-v18713 file). It was extracted into `docs/release-readiness.md` in
v18713 to keep `README.md` a quickstart surface and to give the
release-gate material room to grow without bloating the README. The
`README.md` retains a 3-line redirect and a HelixChannel quickstart
banner at the top.

## References

- v18712-2 — HelixChannel production wire shipped (`feat/proxy: v18712`)
- v18712-3 — Lightsail port-443 reverse-proxy SOP
- v18712-5a — Operator red-triage runbook
- v18713-2 — `cmd/helixchannel` doctor probe binary shipped
- ADR-085 supersedes ADR-084 (HelixChannel production wire)