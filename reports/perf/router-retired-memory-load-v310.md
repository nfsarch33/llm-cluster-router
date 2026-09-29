# v310 Router + Retired-Memory-Service Synthetic Load Evidence

Recorded: 2026-05-07T23:56:00+10:00

## Scope

This report records the v310 synthetic-load evidence that is safe to run without
touching the retired memory service admin surfaces.

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

## Retired-Memory-Service OSS Load

Live retired-service `/search` load was not run in this story. The active external
blockers remained the retired service admin setup/quota and OCI compute capacity/subscription,
as recorded in the v309 KPI and v308 RED handoff. Git KB evidence remains the
source of truth until the Engram cutover and live load were unblocked.

## Acceptance Status

Router synthetic load: implemented and testable.

Sustained hit-rate proof for the retired service: deferred until its admin/quota state was
green.
