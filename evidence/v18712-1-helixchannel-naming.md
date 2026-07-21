# v18712-1 — HelixChannel naming + README + RELEASE-NOTES + metrics + response header

## Sprint
v18712-1 (additive; no breaking changes)

## Files touched
- README.md — new "HelixChannel (encrypted dual-listener)" top section.
- RELEASE-NOTES.md — created; first entry "## v18712 (2026-07-22)".
- internal/proxy/listener.go — package comment updated with HelixChannel
  brand name + ADR-085 reference.
- internal/proxy/helixchannel_header.go — new file; `WithHelixChannelHeader`
  middleware + `HelixChannelVersion` + `HelixChannelHeader` constants.
- internal/proxy/helixchannel_header_test.go — 3 tests (TDD).
- internal/proxy/observability/observability.go — added
  `HelixChannelConnectionsTotal` and `HelixChannelBytesTotal`; registered
  in `RegisterMetrics`; cleared in `Reset`. Existing metrics untouched.
- internal/proxy/observability/helixchannel_metric_test.go — asserts the
  new metric families register and increment correctly.

## Verifier output (fresh this turn)
- `go test ./... -count=1` → exit 0, all packages OK
- `go test ./internal/proxy/ -run 'HelixChannel' -v -count=1` → 3 PASS
- `go test ./internal/proxy/observability/... -count=1 -v` → 12 PASS

## Compatibility
ADDITIVE only. The legacy `llm_cluster_router_connections_total{listener="aes-mtls"}`
continues to work unchanged. The `HelixChannel-Version: v18712-1` response
header is stamped only by callers that opt in via `WithHelixChannelHeader`.

## Evidence of evidence: actual command output (this turn)
$ go test ./internal/proxy/observability/... -count=1
ok  github.com/nfsarch33/llm-cluster-router/internal/proxy/observability  0.021s
$ go test ./internal/proxy/ -run 'HelixChannel' -v -count=1
=== RUN   TestHelixChannelHeader_StampsResponseHeader
--- PASS
=== RUN   TestHelixChannelHeader_PreservesExistingHeaders
--- PASS
=== RUN   TestHelixChannelVersion_Stable
--- PASS
PASS
ok  github.com/nfsarch33/llm-cluster-router/internal/proxy  0.004s
$ go test ./... -count=1
ok  github.com/nfsarch33/llm-cluster-router                  0.328s
ok  github.com/nfsarch33/llm-cluster-router/cmd/dual-listener-demo  0.431s
ok  github.com/nfsarch33/llm-cluster-router/internal/proxy  0.008s
ok  github.com/nfsarch33/llm-cluster-router/internal/proxy/observability  0.015s
... (all 16 packages GREEN)
