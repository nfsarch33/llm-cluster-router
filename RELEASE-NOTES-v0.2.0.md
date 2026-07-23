# HelixChannel v0.2.0 — Production-Pilot

**Released:** 2026-07-24
**Previous:** v0.1.0 (2026-07-22) — encrypted LLM tunnel MVP
**Repo:** https://github.com/nfsarch33/llm-cluster-router
**Public pilot:** https://helixchannel.cylrl.dev (Lightsail `ap-southeast-2`)

## Highlights

- **Public-facing README** — restructured to 207 LoC (down from 328);
  detailed HelixChannel docs moved to [`docs/helixchannel.md`](docs/helixchannel.md),
  testing docs to [`docs/testing.md`](docs/testing.md). ADR cross-links
  resolve to canonical GitHub blobs in `cursor-global-kb`.
- **`cmd/helixchannel` v2 subcommands** — two new operator diagnostics:
  - `helixchannel cipher-list` — enumerates AES-256-GCM/TLS-1.3 cipher
    preferences (RFC 8446 canonical: `TLS_AES_256_GCM_SHA384`). Supports
    `--recommended-only` filter and `--as-yaml` (nginx ssl_ciphers block).
  - `helixchannel cert-pin` — fetches the live SPKI SHA-256 digest of
    `helixchannel.cylrl.dev:443`, asserts `--expect-pin` (exit 2 on
    mismatch), supports `--insecure` for the pilot self-signed cert.
- **DNS binding** — `helixchannel.cylrl.dev` → `52.64.8.153` (Lightsail
  `helixon-tunnel`, `ap-southeast-2`) verified live via DreamHost API
  and direct TLS handshake.
- **Live TLS pin captured** — `965B+jrNsmf4r7Z/dQmrG+NQ4+5zldzdwKRKfTftqMI=`
  (subject `CN=helixon-tunnel`, self-signed pilot cert; LE cert rotation
  tracked as v18730 follow-up).

## Compatibility

- Existing router / balancer functionality unchanged. HelixChannel is
  opt-in via `HELIXCHANNEL_ENABLED=true`.
- The dual-listener design (AES/mTLS + legacy plain HTTP) is unchanged
  from v0.1.0; ADR-085 still the canonical design doc.
- New subcommands are additive; existing CLI consumers are unaffected.

## Production-Pilot Status

| Surface | Status |
|---|---|
| DNS A-record `helixchannel.cylrl.dev` | ✅ live |
| TLS-443 handshake (self-signed pilot cert) | ✅ live |
| HTTP `/healthz` | ✅ 200 |
| HTTP `/` (router JSON envelope) | ✅ live |
| `/minimax/v1/models` upstream routing | ⚠ nginx 502 — v18730-1 |
| `/qwen/v1/models` upstream routing | ⚠ nginx 502 — v18730-1 |
| Let's Encrypt cert for `helixchannel.cylrl.dev` | ⚠ pending — v18730-1 |

The two 502s are upstream-routing items, not v0.2.0 blockers — the
TLS listener and router framework are alive. The pilot is operational
for any client that does not require LE chain validation.

## Tests

```
go test -short -count=1 ./...   # 18 packages, all GREEN
```

New tests added in this release (5):

- `TestCipherList_EmitsCanonicalSuite`
- `TestCipherList_RecommendedOnlyFilter`
- `TestCipherList_AsYAMLEmitsSSLCiphers`
- `TestCertPin_OfflineFailsClean`
- `TestCipherList_UnknownFlagErrors`

## Security

- Shell-leak scan on staged changes: **0 findings**.
- Public-repo-gate on full repo: **0 findings**.
- No new credential material exposed in the release.

## Verification

- DNS resolution: `helixchannel.cylrl.dev` → `52.64.8.153` ✓
- TCP 443 reachability: ✓
- TLS handshake (cert-pin subcommand): ✓
- HTTP `/healthz`: 200 ✓
- HTTP `/`: router JSON envelope emitted ✓

## Companion docs

- [`docs/helixchannel.md`](docs/helixchannel.md) — design, threat
  model, operator config, ListenerFactory contract, metrics.
- [`docs/testing.md`](docs/testing.md) — unit/integration/fuzz
  catalogue.
- [`docs/release-readiness.md`](docs/release-readiness.md) — release
  gate procedure (for v0.3.0).
- ADR-085 `helixchannel-prod-wire` — canonical design.
- ADR-086 `tls-443-fallback` — TCP/443 rationale over SSH/22.