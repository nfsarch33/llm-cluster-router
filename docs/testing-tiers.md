# Testing tiers

Every test in this repository belongs to exactly one of two tiers, and each
tier has a `make` target that runs it. A tier with no target is not a rule, it
is a suggestion — and the evidence for that claim is in this repo's own
history: before this document existed, the `realmodel` and `adversarial` build
tags were run by no workflow and no target, and eleven fuzz targets were run by
nothing at all.

## Tier 1 — the merge gate: `make all`

Deterministic, bounded, and red means the change does not merge.

| Target | Command | Measured |
|---|---|---|
| `vet` | `go vet ./...` | 0.5 s |
| `vet-tags` | `go vet -tags=T ./...` for all seven tags | 3.6 s |
| `test` | `go test -race -coverprofile=coverage.out ./...` | 11–14 s |
| `race-shuffle` | `go test -race -count=2 -shuffle=on ./...` | 18 s |
| `integration` | `go test -tags=integration -race -run TestIT_ ./...` | 7 s |
| `lint` | `golangci-lint run` (v2.x) | 2 s warm, 8 s cold |
| **`make all`** | all of the above | **32 s warm** |

Timings: Go 1.26.7 linux/amd64, 16 logical CPUs (i9-10900X), warm build cache.
They are here so that a future slowdown is visible as a slowdown rather than as
an unexplained feeling.

`race-shuffle` is in the gate on purpose. Randomised test order catches a test
that only passes because another test left state behind, and shared state
between tests is the same defect class as shared state between goroutines —
which is what `-race` is there for. It costs 18 seconds.

`vet-tags` is in the gate for a different reason: a build tag nobody compiles
rots. Type-checking all seven costs 3.6 seconds and is the difference between
a dormant tier and a dead one.

## Tier 2 — scheduled: not the gate

| Target | What it runs | Why it is not in the gate |
|---|---|---|
| `make fuzz` | every fuzz target, `FUZZTIME` each (default 30 s) | Unbounded by nature. 16 targets × 60 s ≈ 17 min. |
| `make bench` | every benchmark, `-benchmem` | Wall-clock numbers on a shared runner are noise; a benchmark cannot fail a build without a baseline to fail against. |
| `make bench-save` | as `bench`, into `$(BENCH_OUT)` with host + toolchain header | Input to `benchstat`; see `docs/benchmarks-helixchannel.md`. |
| `make realmodel` | `-tags=realmodel` | Needs live provider credentials. |
| `make adversarial` | `-tags=adversarial` | Hostile-input tier; slow and better suited to a schedule. |

A gate that takes long enough to annoy people is a gate people learn to
bypass, so these stay out of it. They still run — nightly — and a nightly that
nobody has looked at in a month is the next problem to solve, not a reason to
skip the schedule.

## Build tags

`make vet-tags` type-checks each of these. Keep the list in the `Makefile`'s
`BUILD_TAGS` in sync with:

```
rg -n '^//go:build' --glob '*.go' | sed 's/.*go:build //' | sort -u
```

| Tag | Contains | Run by |
|---|---|---|
| `integration` | `TestIT_*` against httptest mock upstreams | `make integration` (gate) |
| `realmodel` | end-to-end against a real provider | `make realmodel` (nightly) |
| `adversarial` | hostile-input tests and `FuzzSOCKS5NoLeak` | `make adversarial`, `make fuzz` |
| `socks5_stream` | SOCKS5 streaming coverage | `make vet-tags` only — no runner yet |
| `adr083_test` | ADR-083 checklist assertions | `make vet-tags` only — no runner yet |
| `release_gate_test` | release-gate script assertions | `make vet-tags` only — no runner yet |
| `live_e2e` | `TestLive_*` against a deployed edge | `make live-e2e`, on demand |

The three tags marked "no runner yet" are honestly labelled rather than
quietly listed. They compile; nothing asserts they pass. That is a known gap,
not a finished state.

## Rules for new tests

**A fuzz target asserts an invariant, not the absence of a panic.** `go test
-fuzz` already fails on a panic; a target whose body only calls the function
under test adds nothing that the seed corpus did not. State the property —
"parsing then re-serialising round-trips", "no output contains the input
bytes", "the allowlist decision is identical for every encoding of this host" —
and fail on the property.

**Commit your crashers.** When `make fuzz` finds one, the reproducer lands in
`<pkg>/testdata/fuzz/<Target>/`. Commit it. It is now a unit test that runs on
every `go test`, for free, forever.

**A benchmark number without its host and Go version is meaningless.** Two
`ns/op` figures from different machines are not comparable, and the reader
cannot tell that from the number alone. `make bench-save` writes the toolchain,
kernel, CPU count and timestamp into the file header for exactly this reason.
Always report `-benchmem`: an allocation count is stable across machines in a
way that nanoseconds are not, so it is the number worth regressing against.

**Concurrent code names its bounding pattern.** Every goroutine fan-out gets a
doc comment saying which of the three bounded patterns it uses — buffered-channel
semaphore, `errgroup.SetLimit`, or a fixed worker pool — and what happens when
the bound is reached. "It is fine, the caller only ever passes a few" is not a
bound.

**No test may depend on the order tests run in.** `make race-shuffle` enforces
this. If your test asserts an absolute value read off package-level state,
reset that state at the top of the test. Prometheus collectors are the usual
offender here: a fresh `prometheus.NewRegistry()` does not give you fresh
counters, because the counter vectors are package-level singletons.
