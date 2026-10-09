# HelixChannel ephemeral-key channel — threat model (v2, security-review round)

Status: DECIDED — Option A (Noise_IKpsk2 via github.com/flynn/noise).
Supersedes the custom handshake at 5342c52 (branch-local, never
deployed; the custom protocol is dead, no rollout compat needed).
Companion QA plan: docs/qa/helixchannel-ephemeral-keys-qa-plan.md.

## Assets

A1 Router upstream auth material (upstream API keys at the router) — out
of channel scope but reachable if the channel is broken.
A2 Request/response CONTENT (LLM prompts, completions, MCP payloads).
A3 Channel AUTHORIZATION: who may open a channel at all (per-tenant).
A4 Server long-term identity key (X25519 static).
A5 Per-tenant PSK (client authentication; stored per client device and
server-side, addressed by 1Password UUID — never in this repo).
A6 Channel availability (per-tenant DoS is out of scope; the outer
TCP/TLS layer owns generic DoS posture).

## Attacker capabilities

| attacker | capability |
|---|---|
| P0 passive | reads all traffic on any network segment, forever |
| P1 active MITM | injects, drops, reorders, replays, modifies bytes; can strip the negotiation marker to force the legacy static mode |
| P2 compromised client | holds one tenant's PSK + the (public) server key |
| P3 compromised server long-term key | holds A4 but NOT the PSKs; wants to impersonate the server to clients |
| P4 compromised server process | full server; nothing below defends against it (trust boundary) |

## Required properties (and who they defend against)

| property | definition | defeats |
|---|---|---|
| PR1 server authentication | a channel opens only if the peer holds A4 | P1, P2 |
| PR2 client authentication | a channel opens only if the peer holds the tenant PSK A5 | P1, P0 |
| PR3 forward secrecy | post-hoc A4 compromise does not decrypt past sessions | P3 (later) |
| PR4 KCI resistance (client) | a compromised client static/PSK cannot impersonate the SERVER to other clients | P2 |
| PR5 replay/reorder/reflection | in-session record replay, reorder, drop and reflection are detected and rejected | P1 |
| PR6 downgrade resistance | an active attacker cannot force the weaker static-key mode when the policy forbids it | P1 |
| PR7 content confidentiality + integrity | P0/P1 learn nothing about A2 and cannot alter it | P0, P1 |

## Option comparison

| axis | A: Noise_IKpsk2_25519_AESGCM_SHA256 (flynn/noise) | B: custom double-DH + fixes |
|---|---|---|
| PR1 server auth | IK: first message encrypted to the pinned server static — inherent | current DH1+HMAC tag (correct but hand-rolled) |
| PR2 client auth | psk2 in message 2 — standard | must design a PSK binder by hand |
| PR3 FS | ephemerals, standard | DH2 today, OK |
| PR4 KCI | IKpsk2: impersonating the server to a client requires the PSK, not just public data | needs a second hand-rolled binder |
| PR5 replay/reorder | CipherState counter nonces, separate k1/k2 per direction — library-owned | must replace random nonces with counters + per-direction keys by hand |
| KAT quality | official cacophony vectors (the library's own suite) | self-generated vectors only (reviewer finding F4) |
| review surface | ~1.2k LOC audited lib, widely used (WireGuard-adjacent ecosystem) vs ~600 new LOC ours | all review on us |
| wire format | Noise messages; changes our record layer | unchanged |

Decision: **Option A** — every PR7 gap the reviewer found maps to a
library-owned property, and the known-answer problem disappears. The
supply-chain evidence note is appended below; if it had failed, Option B
would be the fallback with hand-rolled counters + PSK binder.

## Wire + rollout

Negotiation keeps the sniff: `HCX2` magic → Noise channel; legacy static
wrap only when the listener policy allows it. The custom `HCX1` protocol
never shipped (branch-local), so HCX1 is retired in this same drop — no
deployed compat obligation; documented here for archaeology only.
Record layer after handshake: `[u32 BE length][Noise ciphertext]` per
record, per-direction CipherStates, counter nonces; the existing tamper
counter/tap semantics are preserved (tap observes ciphertext frames).

Downgrade policy (PR6):
- client: static fallback OFF unless `-allow-static-fallback`; when
  used: WARN log + `hcclient_static_fallback_total` counter.
- server: per-listener `RequireEphemeral` — when true, Negotiate refuses
  any non-HCX2 conn (closes it); the migration path is: dual-mode
  (default) → verify metrics → flip require_ephemeral per tenant.

## Threat-model test obligations (mapped to QA plan v2)

- PR1: wrong-server-key rejected (U-B).
- PR2: wrong/absent PSK rejected (U-C).
- PR5: replay, reorder, reflection record tests (U-E).
- PR6: marker-strip refused under RequireEphemeral (N-B); client never
  falls back without the flag (E-F).
- KAT: cacophony IK+psk2 vectors (U-A).
- F6: keygen private material never on stdout/logs (U-H).

## Supply-chain evidence note — github.com/flynn/noise

- Version pinned: see go.mod on this branch (v0.2.0 or the latest tag at
  integration; recorded post-`go get`).
- Licence: BSD-2-Clause (Prime Directive, Inc.) — permissive,
  compatible.
- govulncheck ./... with the dep present: ZERO findings in
  github.com/flynn/noise (36 findings exist but all in go1.26 stdlib
  and golang.org/x/net — pre-existing toolchain-level, unrelated).
- Code-path read (evidence): handshake.go implements the Noise RFC
  state machine (message patterns from a table, mixKey/mixHash
  per spec); cipher_suite.go wraps stdlib crypto/aes+GCM and
  golang.org/x/crypto/chacha20poly1305; no network I/O in the library —
  it is pure bytes-in/bytes-out, which bounds the attack surface to the
  handshake state machine and the AEAD wrappers.
- Provenance: no release signing for Go modules; module hash pinned via
  go.sum (module authentication via the Go checksum database) — the
  standard supply-chain posture for this ecosystem.

## Appendix — the six reviewer findings, dispositions

F1 downgrade → PR6 fixes (policy + flag + metric + tests).
F2 no client auth → PR2 via IKpsk2 (PSK per tenant).
F3 single key/random nonces → PR5 via CipherState split + counters.
F4 custom KAT → U-A cacophony vectors.
F5 no fuzz → three fuzz targets in this drop.
F6 keygen stdout → U-H: private half to 0600 file only.
