# HelixChannel gateway — hot-path benchmark baseline

This is the reference set for `internal/channel`. Its purpose is comparison: a
number here is only useful because a later run can be put next to it, so the
machine, the toolchain and the exact command are recorded alongside every figure.
A benchmark result without its host is not a measurement.

> Not to be confused with [`benchmarks.md`](benchmarks.md), which measures the
> local Qwen serving host. This file measures the gateway process.

## Provenance

| | |
|---|---|
| Commit | `7424179` on `feat/v18770-rotation-integrated` |
| Date | 2026-08-25 |
| Toolchain | `go1.26.7 linux/amd64` |
| CPU | Intel Core i9-10900X @ 3.70 GHz |
| Logical CPUs / `GOMAXPROCS` | 16 / 16 (benchmark names carry the `-16` suffix) |
| OS | Ubuntu 24.04 under WSL2, kernel `6.18.x-microsoft-standard-WSL2` |
| Command | `go test -run='^$' -bench=. -benchmem -count=5 ./internal/channel/` |
| Statistic | **median of 5**, and every figure below was reproducible to within a few percent across those 5 |

Two properties of the host are worth naming before anything is compared against
it. It is a **virtualised** kernel, so syscall and loopback-networking costs are
higher than they would be on bare metal — which inflates the `http_upstream`
shapes specifically. And its 16 logical CPUs are what `conc=8` and `conc=64`
mean here; see [Concurrency](#a-note-on-what-conc-means) below, because those
labels do not survive a move to a machine with a different core count unchanged.

Benchmarks are **not** run under `-race`. Race instrumentation multiplies every
figure and would make this table meaningless. They are required to compile and
pass under it, which the ordinary gate covers.

## Reproducing

```sh
go test -run='^$' -bench=. -benchmem -count=5 ./internal/channel/
```

The whole set takes about 5½ minutes. For a quick correctness check that every
benchmark still runs — which is what CI wants, not the numbers:

```sh
go test -run='^$' -bench=. -benchtime=10x ./...
```

## The headline: what rotation costs per request

`Forward_SingleKey` is the pre-rotation path — one key, one `bearerInjector`, no
store, no lease, no usage extractor. `Forward_PooledKey` is the same request
against a three-key pool. Both drive the whole `Server.Handler`. The difference
between them is the rotation work and nothing else.

| Shape | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `Forward_SingleKey/gateway_only` | 17 173 | 40 142 | 39 |
| `Forward_PooledKey/gateway_only` | 20 583 | 42 950 | 47 |
| **Rotation delta** | **+3 410 (+19.9 %)** | **+2 808 (+7.0 %)** | **+8 (+20.5 %)** |
| `Forward_SingleKey/http_upstream` | 232 616 | 51 362 | 145 |
| `Forward_PooledKey/http_upstream` | 239 071 | 54 581 | 153 |
| Delta over a real socket | +6 455 (+2.8 %) — **inside the noise**, see below | +3 219 | +8 |

`gateway_only` substitutes an in-process `Forwarder`, so it contains the
gateway's own per-request work and nothing else. That is the shape to subtract
one row from the other with. `http_upstream` runs the real `httpForwarder`
against a loopback `httptest` server: realistic, but each of those rows had a
run-to-run spread of roughly ±10 µs, so a 6 µs delta across them is not a
measurement of anything. **Read the rotation cost off `gateway_only`.**

**Verdict: 3.4 µs per request, and it is not material.** Three ways of saying
the same thing:

- It is 1.5 % of a request served against a *loopback* mock. Against a real
  provider — tens to hundreds of milliseconds — it is under one part in ten
  thousand.
- In CPU terms it is 0.34 % of one core at 1 000 requests/second.
- It is *one third* of what the response-copy buffer costs on the same request
  (see [The streaming leg](#the-streaming-leg)), and that buffer is paid by the
  single-key path too.

The credential strip adds a further **288 ns** per request on top (below). The
whole of "rotation + strip" is therefore about **3.7 µs**.

### Where the 3.4 µs goes

Roughly, from the component benchmarks below: the rotation store's
acquire-and-settle round trip at three keys is 527 ns (sequential, which is what
these benchmarks are), and the usage extractor teed into the copy costs ~940 ns
on a 1 KiB body. The remainder is the
`KeyLease`, the per-request `leasedInjector` and `boundRoute`, and the two extra
audit fields. Nothing in the delta is a surprise, and nothing in it is a lock
held across I/O.

## Rotation store

One mutex serialises every key on a route, so this is where contention would
show up first. Measured at 1, 3 and 7 keys and at concurrency 1, 8 and 64.

### `AcquireSettle` — the round trip, and the number a capacity calculation wants

| keys | conc=1 | conc=8 | conc=64 | B/op | allocs/op |
|---:|---:|---:|---:|---:|---:|
| 1 | 373 ns | 466 ns | 487 ns | 168–192 | 2–3 |
| 3 | 527 ns | 689 ns | 695 ns | 360–383 | 2–3 |
| 7 | 819 ns | 1 110 ns | 1 154 ns | 776–800 | 2–3 |

**The store does not fall over.** Going from 1 to 8 goroutines costs 25–35 %;
going from 8 to *64* costs a further 0–4 %. That flat second step is the
finding: the lock is held for in-memory arithmetic only, so once it is saturated
the extra 56 goroutines queue without adding cost. There is no collapse to look
for at higher concurrency.

Cost grows with key count because `reserve` builds a `[]KeyState` of the
selectable keys on every call — the single allocation in the numbers above.

### `Next` — selection and reservation alone

| keys | conc=1 | conc=8 | conc=64 | B/op | allocs/op |
|---:|---:|---:|---:|---:|---:|
| 1 | 296 ns | 309 ns | 340 ns | ~230 | 1 |
| 3 | 424 ns | 474 ns | 495 ns | ~420 | 1 |
| 7 | 676 ns | 727 ns | 751 ns | ~835 | 1 |

Each iteration deliberately leaves its reservation outstanding, so the per-key
lease slice grows for the length of the run. The B/op figures therefore include
that slice's amortised growth and are an **upper** bound; the benchmark's own
doc comment says so. Use `AcquireSettle` for a per-request figure.

### `Settle` — releasing the slot and charging the window

| keys | conc=1 | conc=8 | conc=64 |
|---:|---:|---:|---:|
| 1 | 74.6 ns | 199 ns | 203 ns |
| 3 | 77.4 ns | 204 ns | 210 ns |
| 7 | 86.6 ns | 210 ns | 224 ns |

**Zero allocations at every shape.** Settlement is pure arithmetic under the
lock. The 2.6× step from conc=1 to conc=8 is the uncontended-to-contended mutex
transition and, again, it is flat from there to 64.

## The streaming leg

`copyResponseObserving`, at two body sizes across its three strategies.

| shape | 1 KiB | 1 MiB | B/op | allocs/op |
|---|---:|---:|---:|---:|
| `no_flusher` (plain `io.Copy`) | 11 065 ns | 42 015 ns | 33 304 | 10 |
| `flusher` (32 KiB loop) | 10 349 ns | 42 451 ns | 33 304 | 10 |
| `flusher_usage` (loop + usage tee) | 11 290 ns | 100 054 ns | 34 352 / 115 248 | 12 / 13 |

Three things an operator should take from this:

1. **The 32 KiB buffer is the single largest per-request cost in the gateway.**
   A 1 KiB response costs ~10.3 µs to copy, essentially all of it allocating and
   zeroing that buffer — about 60 % of the entire 17.2 µs single-key request.
   `io.Copy` allocates the same buffer, which is why `no_flusher` and `flusher`
   are indistinguishable. Anyone looking for gateway throughput should look here
   first, not at rotation. A `sync.Pool` for that buffer is the obvious lever,
   and it is unexplored.
2. **The usage extractor roughly doubles the copy on large bodies** — 42 µs to
   100 µs on 1 MiB, and 33 KB to 115 KB of allocation, as the rolling tail window
   grows past its 8 KiB steady state. It is cheap on the small bodies that
   dominate real traffic (+0.9 µs on 1 KiB), so this is a note for someone
   proxying megabyte responses through a pooled route, not a defect.
3. Throughput tops out around **24.7 GB/s**, i.e. memory bandwidth. Nothing in
   the copy path is doing anything but moving bytes.

## Route matching

`Server.match` is a linear longest-prefix scan. The benchmark matches the
*shortest* configured prefix, which the longest-first sort places last, so every
iteration walks the whole table — the worst case.

| routes | ns/op | B/op |
|---:|---:|---:|
| 1 | 4.6 | 0 |
| 10 | 39.0 | 0 |
| 50 | 75.3 | 0 |

Linear as designed, about 1.5 ns per route, zero allocations. At 50 routes it is
0.4 % of one request. **No reason to build a trie.**

## Audit serialisation

One NDJSON line per request, through one mutex and one `json.Marshal`.

| concurrency | ns/op | B/op | allocs/op |
|---:|---:|---:|---:|
| 1 | 1 250 | 648 | 3 |
| 8 | 1 447 | 649 | 3 |
| 64 | 1 444 | 649 | 3 |

Flat from 8 to 64, like the rotation store. `TS` is left empty exactly as
`handleProxy` hands it over, so the `time.Now().UTC().Format` is counted here
rather than hidden. At 1.25 µs the auditor is ~7 % of a request and is not worth
touching.

## Caller-credential strip

The deny-set scan, over one realistic request's ten inbound headers.

| shape | ns/op | B/op |
|---|---:|---:|
| no route `key_header` | 287.9 | 0 |
| route `key_header` set | 314.9 | 0 |

**288 ns and zero allocations for a whole request's headers** — about 29 ns per
header against an eight-entry table. A configured `key_header` adds ~9 %, because
every *miss* then pays an extra `TrimSpace` and `EqualFold`, and misses are the
common case.

This is the answer to whether the deny-set should become a map: **no.** A map
lookup needs a lowercased key, which allocates unless the header is already
canonical, and 29 ns per header is below the cost of getting there. The linear
scan is also what keeps the table readable as the extension seam
`callerCredentialHeaders` documents itself as being.

## Reading a future run against this one

- Compare `gateway_only` shapes, never `http_upstream` ones. The loopback socket
  has a ±10 µs spread that will swallow any change worth arguing about.
- Compare **allocs/op before ns/op**. An allocation regression shows up in
  production as GC pressure long before it shows up as a slower benchmark, and
  it is the more stable signal across machines.
- Re-record the whole [Provenance](#provenance) block. Half of these numbers are
  memory-bandwidth or mutex-transition figures and neither transfers between
  hosts.

### A note on what `conc` means

`testing.B.SetParallelism` takes a *multiplier* of `GOMAXPROCS`, not an absolute
goroutine count, so `runBench` divides the requested concurrency by `GOMAXPROCS`
and floors it at one. On this 16-CPU host, `conc=8` therefore ran at
parallelism 1 — **16 goroutines**, not 8 — and `conc=64` ran at parallelism 4,
i.e. 64. The `conc=1` rows are a plain sequential loop and are exact.

So `conc=8` here is honestly "saturated", and the useful comparison in every
table above is *conc=1 versus contended*, plus the flatness of contended-to-64.
On a host with a different core count the `conc=8` column will mean something
else, which is the whole reason `GOMAXPROCS` is in the provenance block.

## Known gap

`Forward_*/gateway_only` substitutes the `Forwarder`, so it never calls
`Authenticator.Apply` and never runs the credential strip — both live inside
`httpForwarder.Forward`. This was confirmed, not assumed: breaking
`bearerInjector.Apply` failed `http_upstream` and left `gateway_only` passing.

That is the intended trade — it is what makes the shape quiet enough to resolve a
3 µs delta — but it means `gateway_only` cannot be read as "the whole gateway".
The strip is priced separately above, and `http_upstream` is the shape that
exercises the credential path end to end.
