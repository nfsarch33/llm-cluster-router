# v18712-2 evidence — ListenerFactory wired into prod main.go

Captured: 2026-07-22T00:21+10:00
Machine-Id: win3-wsl3
Sprint: v18712

## What was delivered

1. `internal/proxy/listener_selector.go` — `plainHTTPListenerFactory` +
   `SelectListenerFactory(enabled bool) ListenerFactory`.
2. `internal/proxy/listener_selector_test.go` — selector tests + plain HTTP
   listener contract tests.
3. `main.go` — replaced hardcoded `server.ListenAndServe()` with the
   ListenerFactory selector driven by the `HELIXCHANNEL_ENABLED` env knob
   (`helixChannelEnabledFromEnv`).
4. `main_helixchannel_test.go` — env-knob parser tests.
5. `scripts/release-gate.sh` — new row 7/7 `run_prod_wire` asserts the
   selector symbol, env-knob reader, and selector unit tests are wired.
6. `~/Code/cursor-global-kb/adrs/ADR-085-helixchannel-prod-wire.md` —
   ADR-085 supersedes ADR-084 wire-now deferral.

## Verifier — `go test -race ./...`

```
ok  	github.com/nfsarch33/llm-cluster-router	0.041s
ok  	github.com/nfsarch33/llm-cluster-router/cmd/dual-listener-demo	0.013s
ok  	github.com/nfsarch33/llm-cluster-router/internal/config	0.003s
ok  	github.com/nfsarch33/llm-cluster-router/internal/proxy	0.036s
ok  	github.com/nfsarch33/llm-cluster-router/internal/proxy/integration	0.004s
ok  	github.com/nfsarch33/llm-cluster-router/internal/proxy/observability	0.004s
```

Exit code: 0

## Verifier — `scripts/release-gate.sh`

All 7 rows GREEN (realmodel + doctor SKIP via flags):

```
[release-gate] summary
ROW                    STATUS   DETAIL
----                   ------   ------
sentrux                GREEN    no structural degradation vs baseline
adr083-checklist       GREEN    ADR-083 GREEN (passes=4, fails=0)
pentest                GREEN    adversarial + redaction + metric-integrity GREEN
decrypt-forward        GREEN    no-plaintext + tamper-rejected binary post-conditions GREEN
realmodel              SKIP     --no-realmodel flag
doctor                 SKIP     --no-doctor flag
prod-wire              GREEN    ListenerFactory selector + HELIXCHANNEL_ENABLED wired; selector tests pass

[release-gate] GREEN — release-ready
```

Exit code: 0

## Verifier — selector test detail

`go test -run 'SelectListenerFactory|PlainHTTPListener|HelixChannelEnabled' -count=1 ./internal/proxy/... .`:

```
ok  	github.com/nfsarch33/llm-cluster-router	0.041s
ok  	github.com/nfsarch33/llm-cluster-router/internal/proxy	0.036s
```

Selector unit tests cover:

- `TestSelectListenerFactory_HelixChannelReturnsAESMTLS`
- `TestSelectListenerFactory_LegacyReturnsPlainHTTP`
- `TestPlainHTTPListenerFactory_ListenRejectsEmptyAddr`
- `TestPlainHTTPListenerFactory_ListenBindsAndCancels`
- `TestHelixChannelEnabledFromEnv_DefaultIsTrue`
- `TestHelixChannelEnabledFromEnv_TruthyValues`
- `TestHelixChannelEnabledFromEnv_FalsyValues`
- `TestHelixChannelEnabledFromEnv_UnknownDefaultsTrue`

## ADR-085

`~/Code/cursor-global-kb/adrs/ADR-085-helixchannel-prod-wire.md` —
"HelixChannel prod-wire decision, supersedes ADR-084 wire-now stance".

Status: Accepted (v18712-2).

Key points:

- Default is HelixChannel (AES/mTLS); `HELIXCHANNEL_ENABLED=false` keeps the
  legacy plain HTTP listener for back-compat.
- Wire pattern taken from `cmd/dual-listener-demo/main.go`, restricted to
  a single AES/mTLS listener at production startup.
- Release-gate row 7 (`run_prod_wire`) covers the wire symbol assertions.

Machine-Id: win3-wsl3
Sprint: v18712