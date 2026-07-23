# Testing

This document is the canonical reference for the `llm-cluster-router` test
suites. CI runs both on every push and PR (see `.github/workflows/ci.yml`).

## Two suites

```bash
# Unit tests (run on every push, fast, default lane)
go test -race ./...

# Integration tests (build-tagged so the default lane stays fast)
go test -tags=integration -timeout=2m -count=1 -race -v -run TestIT_ ./...
```

## Integration test catalogue

The integration suite (`it_test.go`, `//go:build integration`) starts the
router in-process with mock OpenAI-compatible upstream servers
(`net/http/httptest.NewServer`) and exercises:

- `TestIT_NoStarvationUnderConcurrentLoad` — burst load from multiple
  X-User producers; asserts every producer completes within ±20% of equal
  share (no header-based bias).
- `TestIT_StreamingSSEPassthrough` — Server-Sent Events from upstream reach
  the client unchanged with a `[DONE]` terminator.
- `TestIT_FailoverWhenUpstreamReturns502` — when the primary upstream
  starts returning HTTP 502, traffic continues to flow via the fallback
  upstream advertising the same model.
- `TestIT_ModelsAggregation` — `/v1/models` aggregates inventory from every
  healthy upstream.
- `TestIT_PrometheusExpositionFormat` — `/metrics` exposes
  `llm_router_requests_total`, `_request_duration_seconds`,
  `_queue_depth`, `_inflight_requests`, and `_node_healthy` with the
  expected types and labels.

## Grafana dashboard parity

A test in `dashboards/dashboard_test.go` enforces the dashboard references
every metric the router exports, so any future metric additions must
update both the router and the dashboard JSON in the same commit.

## HelixChannel tests

HelixChannel integration tests live under
`internal/proxy/helixchannel_*_test.go` and are gated by the `integration`
build tag. They exercise:

- AES-256-GCM round-trip (encrypt → decrypt → assert payload equality)
- Tamper detection (mutate ciphertext → assert `decrypt_failed_total++`)
- ListenerFactory contract (`Channel()`, `Listen(ctx, addr)`)
- Per-tenant channel preference (`prefer-aes-mtls`, `prefer-socks5`, etc.)

The fuzz harness (`internal/proxy/helixchannel_fuzz_test.go`,
`internal/proxy/socks5_handshake_fuzz_test.go`) runs `go test -fuzz` for
TLS/443 + SOCKS5 handshake hardening (v18720-5, v18728-1).