# HelixChannel ephemeral-key upgrade — QA/eval plan (v1)

Written and committed BEFORE implementation (TDD contract). Spec:
`cursor-global-kb/backlogs/helixchannel-ephemeral-keys-spec.md` (personal
fleet only; company-managed devices out of scope).

## Design under test (frozen for this plan)

- Pre-wrap handshake on the raw conn, then the EXISTING `Wrap(conn, key)`
  AES-256-GCM record format unchanged (full backward compatibility).
- Wire: CH = `"HCX1" || clientEphPub[32] || keyIDLen[1] || keyID`;
  SH = `"HCX1" || serverEphPub[32] || tag[16]`.
- Noise-IK-shaped double DH, stdlib only: DH1 = X25519(clientEph,
  serverLongTerm) authenticates the server; DH2 = X25519(clientEph,
  serverEph) gives forward secrecy. sessionKey = HKDF-SHA256(DH1||DH2,
  salt=SHA256(transcript), info="HCX1 session key aes-256-gcm"), 32B.
  tag = HMAC-SHA256(HKDF(DH1, …"handshake tag"), transcript)[:16] —
  unforgeable without the server long-term key; client verifies BEFORE
  any payload key is used; handshake failure closes the conn (fail
  closed, same posture as cert pinning today).
- Negotiation: server peeks 4 bytes; `HCX1` magic → ephemeral path;
  anything else → legacy static-key Wrap with the peeked bytes replayed
  (one port serves both). Client fallback: ephemeral attempt fails →
  reconnect on static key (auto chain).
- Keys: server env HELIXCHANNEL_EPHEMERAL_KEY (b64 X25519 priv + id);
  previous key retained for rotation (keyID selects). Client pins
  server long-term pub + keyID.
- New client: `cmd/helixchannel-client` — local raw-TCP forwarder
  (listen plain → upstream wrapped). Protocol-blind by construction.

## Test matrix (all must be RED before implementation exists)

Unit (`internal/crypto/handshake_test.go`):
- U1 Deterministic vectors: fixed client/server ephemerals + long-term
  key → both sides derive the SAME 32B session key AND a pinned hex
  constant (catches derivation drift).
- U2 tag verification: wrong server long-term key → client rejects,
  conn closed, no payload sent.
- U3 replayed/modified CH or SH → handshake error (tag covers the full
  transcript).
- U4 unknown keyID → server refuses; keyID rotation (old id still
  accepted while both configured).
- U5 malformed frames (bad magic, short pub, oversized keyID) → typed
  error, no panic (mirrors the fuzz harness posture).

Negotiation (`internal/crypto/sniffconn_test.go`):
- N1 legacy client bytes replayed byte-exact through the prefix conn.
- N2 sniff splits correctly on HCX1 vs first TLS/static bytes.

Integration / E2E (`internal/crypto/ephemeral_e2e_test.go` — loopback
with REAL sockets, no mocks on the data path):
- E1 REST + SSE: http.Server over the wrapped listener via
  cmd-forwarder-style client; JSON POST + streamed SSE lines asserted.
- E2 gRPC: unary + server-streaming RPC through the forwarder
  (google.golang.org/grpc, promoted from indirect).
- E3 MCP: JSON-RPC-over-HTTP request/response through the forwarder.
- E4 no-plaintext capture: tap on the underlying socket; NONE of the
  plaintext markers (paths, JSON keys, SSE payloads) appear in captured
  bytes (reuses the wire-doctor tap pattern).
- E5 tamper: flip one ciphertext byte mid-stream → read error wraps
  ErrTampered, TamperCount() increments (metric feed unchanged).
- E6 fallback: ephemeral client against static-only server → auto
  fallback to static key, data flows.
- E7 backward compat: OLD static client against NEW dual server →
  static path works (N2 replay proves the same port).
- E8 perf smoke: full handshake + first request round trip < 150 ms on
  loopback (handshake itself < 25 ms).

Gates: `go vet ./...`, `go test ./... -race` green, coverage of
internal/crypto ≥ 85%, no new golangci issues at repo baseline, and the
existing wire_security_fuzz harness still green (handshake fuzz cases
are follow-up work per the spec, not this drop).

## Out of scope (spec non-goals restated)

Metadata protection; company-device deployment; concealing VPN state.
Lightsail rollout is an operator step; this drop proves the wire at
loopback fidelity.

## v2 delta (security-review round, 2026-10-09) — what changed and why

The custom handshake was REPLACED by Option A per the frozen threat
model (docs/design/helixchannel-ephemeral-keys-threat-model.md):
Noise_IKpsk2_25519_AESGCM_SHA256 via github.com/flynn/noise v1.1.0
(supply-chain gate PASSED: pinned tag, BSD-2-Clause, govulncheck zero
findings in the dependency, code-path read recorded in the threat
model). Changes to this plan:

- Negotiation magic is now `HCX2` (the never-deployed custom `HCX1`
  protocol is deleted from the branch — no rollout compat owed).
- NEW properties tested: client auth via per-tenant PSK (U-C, psk2
  semantics: the server answers blind at m1; a wrong-PSK client can
  never authenticate m2 — single-PSK listeners reject at handshake),
  per-direction keys + counter nonces (U-E: replay AND reflection both
  rejected with tamper-count assertions), downgrade resistance
  (N-B: marker-strip refused under requireEphemeral; E6 split into
  E6a flag-OFF = channel unusable, E6b flag-ON = fallback works AND
  increments hcclient_static_fallback_total).
- KAT: the Noise state machine is validated by the library's own
  cacophony-verified suite; OUR layer pins direction separation and
  channel-binding behaviour (U-A) rather than self-generated vectors.
- Fuzzing added IN THIS DROP (F5): FuzzHandshakeClientHello,
  FuzzHandshakeServerHello, FuzzNegotiatePeek, 60 s each; corpus
  totals 13 / 11 / 10, zero failures.
- keygen-ephemeral (F6): private half written 0600 to a file, stdout
  carries ONLY public key + key id.
- cmd/helixchannel-client requires HELIXCHANNEL_PSK (32 bytes) +
  HELIXCHANNEL_TENANT; -allow-static-fallback defaults OFF.
