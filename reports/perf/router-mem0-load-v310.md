# v310 Router + Mem0 Synthetic Load Evidence

Recorded: 2026-05-07T23:56:00+10:00

## Scope

This report records the v310 synthetic-load evidence that is safe to run without
touching external Mem0 admin surfaces.

## Router Synthetic Load

Implemented focused in-process load proof in `synthetic_load_test.go`:

- 40 streaming `/v1/chat/completions` requests through the real router handler,
  throttled to 4 workers so the synthetic smoke stays below the configured
  queue-depth limit while still exercising concurrent traffic.
- `llm_router_request_duration_seconds` receives one observation per request.
- `llm_router_generation_tokens_per_second` receives one observation per request.
- Zero synthetic 5xx responses are accepted by the test.

Validation command:

```text
runx worktree run --repo router --branch test/v310-synthetic-load-smoke-2026-05-07 -- go test ./...
```

## Mem0 OSS Load

Live Mem0 OSS `/search` load was not run in this story. The active external
blockers remain Mem0 admin setup/quota and OCI compute capacity/subscription,
as recorded in the v309 KPI and v308 RED handoff. Git KB evidence remains the
source of truth until Mem0 dual-store and live load are unblocked.

## Acceptance Status

Router synthetic load: implemented and testable.

Mem0 OSS sustained hit-rate proof: deferred until Mem0 admin/quota state is
green.
