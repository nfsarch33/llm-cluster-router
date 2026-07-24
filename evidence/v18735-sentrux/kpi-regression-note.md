# v18735 Sentrux Gate Regression Note

**Sprint:** v18735
**Story:** v18735-2 sentrux gate zero regression
**Date (AEST):** 2026-07-24T19:18+10:00
**Author:** cursor-parent@win3-wsl3
**Reference rule:** `cursor-config/rules/sentrux-always.mdc`
**Reference plan:** `~/.cursor/plans/v18726-v18739_overnight_carried-forward_and_helixchannel_pilot_e2e_and_llm_cluster_router_encryption_b10f2fd2.plan.md` (v18735 sentrux gate section)

## Headline

`sentrux gate` reports **DEGRADED**: complex functions increased 8 → 12 (+4).

This regression is **accepted and documented per the plan's rollback
strategy** ("if regression detected, accept and document in KPI; never
silently baseline-shift"). No silent baseline shift occurred.

## Why the regression is expected and acceptable

`v18735-1 reality check 1` added
`internal/proxy/v18735_reality_test.go` to host the 5 promotion-blocking
tests for HelixChannel. The new test file contains 5 long test functions
plus 4 SOCKS5/cipher helper functions, several of which:

1. Use `net.Pipe()`-based concurrency with `select` + `time.After`
 patterns (e.g. `TestCipherMatch_NoPlaintextOnWire`,
 `TestCipherMatch_TamperDetection_SurfacesErrTampered`,
 `TestOTelDualPublish_OTelSideRecordsMatchingSpan`).
2. Have multiple early-return `t.Fatalf` paths that inflate the
 structural complexity count even when logic is linear.
3. Use SOCKS5 handshake logic with multiple ATYP branches (IPv4,
 domain, IPv6) that was extracted into helpers but each helper still
 has 3+ branches.

The baseline (8) was measured before `v18735-1` landed. The regression
(12) is solely attributable to the new test file. No production
package was touched.

## What the gate still says is GREEN

| Axis | Baseline | Now | Direction |
|------|----------|-----|-----------|
| Quality score | 6846 | 6778 | -68 (-1.0%) |
| Coupling | 0.81 | 0.80 | -0.01 (BETTER) |
| Cycles | 0 | 0 | unchanged |
| God files | 0 | 0 | unchanged |
| Distance from main sequence | 0.31 | 0.31 | unchanged |
| Architectural rules (`sentrux check`) | PASS | PASS | unchanged |
| Test count | 0 reality tests | 5 reality tests + 11 subtests | +16 tests |
| `go test ./...` | green | green | unchanged |

## Acceptance per plan's own rollback strategy

The plan v18735 section states:

> "if regression detected, accept and document in KPI (per
> cursor-config/rules/sentrux-always.mdc); never silently baseline-shift"

This file is that documentation. No `baseline.json` was modified.

## What the next sprint should do

If a follow-up sprint has spare time, the right cleanup is to:

1. Split the 5 test functions into a table-driven harness:
   `tests := []struct{ name string; fn func(*testing.T) }{...}`,
   looping over them so each test body becomes a small closure.
2. Move SOCKS5 client/server handshake logic into a new
   `internal/socks5test/` package (test-only, build-tagged
   `//go:build proxy_test`) so the helpers no longer live in
   `v18735_reality_test.go`.
3. Re-run `sentrux gate`; expected delta: complex functions 12 → ≤ 9.

The cleanup is **not on the v18735 critical path** — it is a
housekeeping item for the next sprint that has bandwidth.

## Reproduction

```bash
cd ~/Code/llm-cluster-router
timeout 30 sentrux gate .
# Expected: ✗ DEGRADED, ✗ Complex functions increased: 8 → 12
```

## References

- `internal/proxy/v18735_reality_test.go` — the file that caused the
 +4 complex-functions delta.
- `.sentrux/baseline.json` — untouched (still shows 8).
- `.sentrux/rules.toml` — `max_cyclomatic_complexity = 20`; the
 functions are below this per-file threshold; sentrux's own
 "complex functions" count uses its internal definition.
- `cursor-config/rules/sentrux-always.mdc` — "Track the 0-10000
 quality signal and the root metrics. If the score regresses, fix the
 structure or document why the regression is accepted."

## Conclusion

**Status:** v18735-2 marked COMPLETED in the plan, with this evidence
file as the documented acceptance of the structural regression. No
production code path is affected. All 5 reality-check tests pass.
Test suite green. Sentrux architectural rules (`sentrux check`) green.
