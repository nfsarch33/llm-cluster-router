# Release Readiness

This document is the canonical reference for the `llm-cluster-router`
release gate and the surrounding release-readiness procedure. It is
referenced from the top-level [README](../README.md) so the README stays
a quickstart.

## Release gate (`scripts/release-gate.sh`)

The router ships with a one-command release gate that runs every
release-readiness check and reports a single GREEN/RED verdict. It is
the canonical pre-deploy hook for any release.

```bash
# Full gate (sentrux + adversarial tests + decrypt-forward + realmodel + doctor)
bash scripts/release-gate.sh

# Skip the realmodel E2E (requires vendor credentials) or the
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
| 2 | `pentest` | Go adversarial tests (fuzz + redaction + metric integrity) |
| 3 | `decrypt-forward` | Wire-doctor E2E (no-plaintext + tamper-rejected binary post-conditions) |
| 4 | `realmodel` | Live vendor streaming SSE bridge (requires `<VENDOR>_API_KEY`) |
| 5 | `doctor` | Workspace doctor + sentrux shell-leak scan |
| 6 | `run_prod_wire` | HelixChannel production wire smoke — exercises the dual-listener factory through `cmd/helixchannel factory-probe` and verifies the `HelixChannel-Version` header round-trip |

The corresponding metrics surface on `/metrics`:

- `llm_cluster_router_connections_total{listener,outcome}` — connection
  counts partitioned by listener and outcome
  (`success`, `rejected`, `tampering`).
- `llm_cluster_router_decrypt_failed_total{listener}` — AES-GCM
  authentication failures per listener. Any non-zero rate over a
  1-minute window is an incident.

## Cross-references

- **HelixChannel deployment** — [`docs/helixchannel-deployment.md`](helixchannel-deployment.md)
- **Encrypted transport config** — see the operator-facing config table in
  [`docs/helixchannel-deployment.md`](helixchannel-deployment.md#operator-facing-config)
- **Threat model + binary post-conditions** — same document, §
  [Threat model](helixchannel-deployment.md#threat-model)
- **Production ingress (TLS reverse proxy)** — same document, §
  [Production ingress](helixchannel-deployment.md#production-ingress)
- **HelixChannel doctor probe** — `cmd/helixchannel/` binary with
  `version`, `factory-probe`, `key-check`, `header-stamp`, `doctor`,
  `endpoint-check` subcommands. The `doctor` subcommand runs the same
  release-readiness checks as the shell gate but reports a JSON envelope
  suitable for automation.

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

A GREEN `release-gate.sh` verdict plus a GREEN `./helixchannel doctor`
JSON envelope is the binary post-condition for any release.

## Why this document was relocated

This section previously lived in `README.md` (older releases). It was
extracted into `docs/release-readiness.md` to keep `README.md` a
quickstart surface and to give the release-gate material room to grow
without bloating the README. The `README.md` retains a 3-line redirect
to this document and to the HelixChannel deployment guide.
