# Kilo Code (VS Code) — HelixChannel Setup

End-to-end setup walkthrough for the Kilo Code VS Code extension
against the HelixChannel production wire (v18716.1 / ADR-085 /
ADR-086). Operator-facing only; this doc does NOT cover upstream
LLM deployment.

## What this gives you

Kilo Code in VS Code sends every prompt over an OpenAI-compatible
HTTP wire. When the extension is pointed at the HelixChannel
production base URL, every prompt flows:

```
VS Code Kilo Code
  → HTTPS POST https://52.64.8.153/minimax/v1/chat/completions
  → Lightsail nginx (TLS termination on :443)
  → AES-256-GCM application-layer encrypted tunnel
  → upstream LLM (MiniMax-M3 / Qwen / etc.)
  → response back to Kilo Code in the same pipe
```

The AES-256-GCM encryption is application-layer; the nginx
TLS termination at :443 is the transport envelope. Both are
transparent to Kilo Code — it sees an ordinary OpenAI-compatible
HTTPS endpoint.

## Prerequisites

| Prereq | Where | Status (v18716) |
| --- | --- | --- |
| Lightsail `helixon-tunnel` reachable on TCP/443 | `aws lightsail get-instance --instance-name helixon-tunnel` | GREEN (see `helixchannel endpoint-check --host 52.64.8.153`) |
| nginx reverse-proxy installed + reloaded on the instance | `ssh ubuntu@52.64.8.153 sudo systemctl status nginx` | GREEN (v18714-1) |
| MiniMax Token Plan key in 1Password | `HelixonSafe / minimax-api-1` (UUID `ripotpfq43jzlreor4zo2ay734`) | LIVE |
| Go 1.25+ on the operator host | `go version` | Optional — needed only for the Go integration test |

## Quick path (operator checklist)

### 1. Validate the wire end-to-end (5 min)

```bash
# Build the operator-facing CLI binary
cd ~/Code/llm-cluster-router
go build -o helixchannel ./cmd/helixchannel

# Smoke 1: doctor (Lightsail TCP/443 reachability)
./helixchannel doctor            # expect all checks "pass"

# Smoke 2: kilo-verify (live MiniMax-M3 round-trip)
KILO_CODE_API_KEY="$(op read op://HelixonSafe/ripotpfq43jzlreor4zo2ay734/tagc4supdfgjj3rujdpb67ygm -o /tmp/.kilo && cat /tmp/.kilo && rm /tmp/.kilo)"
HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY=1 ./helixchannel kilo-verify
# expect: {"verdict":"pass","base_url":"https://52.64.8.153/minimax/v1","model":"MiniMax-M3",...}, exit 0
```

If `helixchannel kilo-verify` exits 2 (SKIP), the wire is intact but
a 1Password item is stale; rotate `HelixonSafe/minimax-api-1` and retry.

If it exits 1 (FAIL), inspect `error_class`:

| `error_class` | Meaning | Fix |
| --- | --- | --- |
| `tls` | Lightsail cert lacks IP SAN for `52.64.8.153` | Use `--insecure` or set `HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY=1` (see TLS note below) |
| `timeout` | Upstream MiniMax quota exhausted | Wait for quota refresh, then retry |
| `refused` | nginx down on Lightsail | `ssh ubuntu@52.64.8.153 sudo systemctl restart nginx` |
| `upstream_4xx` | API key rejected | Rotate `HelixonSafe/minimax-api-1` |

### 2. Install Kilo Code in VS Code

VS Code Marketplace → search "Kilo Code" → install.

### 3. Configure Kilo Code to use HelixChannel

Open VS Code Settings (JSON) — `Ctrl+Shift+P` → "Preferences: Open
User Settings (JSON)" — and add:

```json
{
  "kilocode.openAiBaseUrl": "https://52.64.8.153/minimax/v1",
  "kilocode.openAiApiKey":  "<paste value from 1Password HelixonSafe/MiniMax Token Plan Key>",
  "kilocode.openAiModel":   "MiniMax-M3"
}
```

> **Do not** commit `settings.json` to git. Add
> `.vscode/settings.json` to `.gitignore` for any repo you want to
> keep clean.

### 4. Launch VS Code with TLS skip-verify (temporary)

The Lightsail nginx cert is valid for a hostname but NOT for the
IP `52.64.8.153`. Browsers and VS Code reject IP-only certs by
default. Until the operator attaches a domain + ACME cert
(see `CF-v18716-KiloCode-TLSCert`), launch VS Code with the
bypass:

```bash
HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY=1 code ~/Code/cursor-global-kb
```

For dev only — never ship this to a customer fleet.

### 5. Send a test prompt

Open the Kilo Code panel (left sidebar icon) and send a prompt.
Expected: response in ~1-2 s with content from `MiniMax-M3`.

## Swap to Qwen (same wire)

The HelixChannel wire is upstream-agnostic; you can swap MiniMax for
Qwen by changing two settings:

```json
{
  "kilocode.openAiBaseUrl": "https://52.64.8.153/qwen/v1",
  "kilocode.openAiModel":   "qwen3.5-plus"
}
```

Then validate with:

```bash
KILO_CODE_BASE_URL=https://52.64.8.153/qwen/v1 \
KILO_CODE_MODEL=qwen3.5-plus \
  HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY=1 \
  ./helixchannel kilo-verify
```

## Production TLS fix (operator decision)

The TLS skip-verify workaround is acceptable for internal dev only.
For production, attach a hostname + ACME cert to the Lightsail
instance:

**Option A (preferred) — Domain + Let's Encrypt via Cloudflare proxy:**

1. Register a cheap domain (e.g. `helix.helixon.dev`) on Cloudflare.
2. Create a Cloudflare Tunnel or DNS-only A record pointing at
   `52.64.8.153`.
3. Cloudflare terminates TLS at the edge with a managed cert
   (no IP-SAN issue; cert is for the hostname).
4. Operator trusts the Cloudflare root CA in the system trust store.

**Option B — Lightsail load balancer with managed TLS:**

1. Provision a Lightsail load balancer in front of `helixon-tunnel`.
2. Attach the load balancer's auto-managed ACM cert (Lightsail
   provisions via ACME if you supply a domain you own).
3. Update Kilo Code `openAiBaseUrl` to `https://<domain>/minimax/v1`.

**Option C — Self-managed ACME on Lightsail:**

1. `ssh ubuntu@52.64.8.153 sudo apt install certbot`.
2. `sudo certbot certonly --nginx -d <your-domain>` (DNS must point
   at 52.64.8.153 already).
3. Update nginx `ssl_certificate` directives to point at the new
   `/etc/letsencrypt/live/<domain>/fullchain.pem`.
4. Update Kilo Code `openAiBaseUrl` to `https://<domain>/minimax/v1`.

Pick one before exposing the wire outside the operator host.

## Verification matrix

After every setup change, run the full E2E pipeline:

```bash
# 1. Doctor (Lightsail TCP/443 + Lightsail cert)
./helixchannel doctor
# Expect: all checks "pass" or "skipped" (skip is OK in offline/CI)

# 2. Kilo-verify (live MiniMax-M3)
KILO_CODE_API_KEY="$(op read op://HelixonSafe/ripotpfq43jzlreor4zo2ay734/tagc4supdfgjj3rujdpb67ygm -o /tmp/.kilo && cat /tmp/.kilo && rm /tmp/.kilo)" \
  HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY=1 \
  ./helixchannel kilo-verify
# Expect: exit 0, verdict=pass, latency_ms in single-digit ms × 1000

# 3. Go integration test (CI gate)
go test -tags=realmodel -count=1 -v -run TestKiloCodeE2E ./internal/tunnel/integration/...
# Expect: PASS TestKiloCodeE2E_MiniMaxRoundTrip + TestKiloCodeE2E_SkipsWhenKeyMissing
```

## Anti-patterns

- ❌ Do NOT commit the API key to git (use 1Password via `op read`).
- ❌ Do NOT use `--insecure` (CLI) or `HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY=1`
   in production fleet / customer-facing deployments.
- ❌ Do NOT point Kilo Code at `minimax.io` (wrong platform).
   Canonical host: `52.64.8.153` (Lightsail reverse-proxy).
- ❌ Do NOT paste the API key into VS Code settings.json if the file
   is tracked in git. Use a workspace settings file under `.vscode/`
   and add it to `.gitignore`, OR pipe via the VS Code launch env.
- ❌ Do NOT disable the AES/mTLS tunnel thinking it is a bug. The
   encryption is intentional and standard-compliant (ADR-085).

## Cross-references

- HelixChannel architecture: `adrs/ADR-085-helixchannel-prod-wire.md`
  in `cursor-global-kb`.
- Production ingress (TCP/443): `adrs/ADR-086-helixchannel-port-443-migration.md`
  in `cursor-global-kb`.
- Release readiness gate: `docs/release-readiness.md` + `scripts/release-gate.sh`.
- Lightsail reverse-proxy SOP: `cursor-global-kb/sop/lightsail-port-443-reverse-proxy.md`.
- Operator CLI subcommands: `cmd/helixchannel/main.go` (`version`,
  `factory-probe`, `key-check`, `header-stamp`, `doctor`,
  `endpoint-check`, `kilo-verify`).
- Kilo Code E2E Go integration test: `internal/tunnel/integration/kilo_code_e2e_test.go`.
- Kilo Code shell smoke: `scripts/kilo-code-smoke.sh`.

## Carry-forwards

- `CF-v18716-KiloCode-TLSCert` — Lightsail cert has no IP SAN;
  TLS skip-verify used during dev. Production fix is operator-attached
  domain + ACME cert.
- `CF-v18716-KiloCode-Operator` — VS Code extension install + Kilo Code
  panel configuration is operator UI action; this doc provides the
  checklist.