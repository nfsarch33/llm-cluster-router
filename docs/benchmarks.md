# Benchmarks & tuning — local Qwen3.8-27B serving

Measured on the primary GPU host (2× RTX 3090, no NVLink; RTX 2070 excluded from the
pool), llama-server CUDA build, `qwen-local.service`. All numbers from live
runs on 2026-08-20; the weekly [`local-eval`](../.github/workflows/local-eval.yml)
lane re-measures and uploads artifacts so drift is caught automatically.

## Locked serving configuration (and why)

The full rationale is embedded as comments in `qwen-local.service`. Summary:

| Flag | Value | Why |
|---|---|---|
| model | `Qwen3.8-27B-UD-Q4_K_M.gguf` (15.3 GB) | the ONLY quant reaching 200k ctx on 48 GiB: `head_dim=256` makes fp16 KV 256 KiB/token; 6-bit tops out ~164k, 8-bit ~114k |
| `--ctx-size` | 204800 | the 200k+ requirement |
| `--cache-type-k/v` | `q8_0` | halves KV to 128 KiB/token — the change that makes 200k fit |
| `--split-mode` | `layer` | no NVLink: row-split all-reduce over PCIe costs more than it gains at batch 1 |
| `--parallel` | 4 | measured sweet spot (below); **must** pair with `--kv-unified` |
| `--kv-unified` | on | without it, an explicit `--parallel` SPLITS the context to 51200/slot — caught live 2026-08-20; each slot must see the full 204800 |

## Measured performance (UD-Q4_K_M, 200k config)

| Metric | Value |
|---|---:|
| VRAM at 200k ctx | 26.5 GiB of 48 (12.5 + 13.9) |
| Decode, single stream | **36.9–37.9 tok/s** |
| Prompt processing | **1722 tok/s** (7060-token prompt in 4.1 s) |
| Decode at 7k-token prompt | 36.3 tok/s (no meaningful degradation) |
| Model load time | ~120 s |

### Concurrency sweep (through the router, 160-token completions)

| Concurrency | Wall | Aggregate tok/s | Per-stream |
|---:|---:|---:|---|
| 1 | 5.5 s | 28.8 | 28.9 |
| 4 | 8.5 s | **75.6** | 19.0 ×4 |
| 8 | 31.3 s | 41.0 | 5–10 (queueing) |

**4 slots is the locked sweet spot**: 2.6× aggregate over single-stream with
every slot still holding the full 200k context (unified KV, verified via
`/props`). Beyond 4, requests queue on the slot pool and per-stream rates
collapse. Raise `--parallel` only after re-running this sweep.

## Quality lane

`fleet-bench -mode matrix -corpus v300-baseline` runs the locked 50-prompt
corpus (code / reasoning / summarisation / translation / chat, each with a
pass predicate) against `qwen3.8-27b-local` through the router — directly
comparable to the Qwen3.6 baseline numbers recorded in fleet-bench. Latest
results live in the `local-eval` workflow artifacts; the first Qwen3.8 run's
summary is recorded in the v18755 handoff.

## Scaling option: 4× RTX 3090 (96 GiB)

Full analysis: KB `sop/qwen-2x3090-design.md` (§ 4×3090 addendum). The short
version:

- **Quality up, not speed up.** Layer-split decode is bandwidth-bound per
  token: BF16 becomes *possible* (~301k ctx with q8 KV) but projects
  **~12–16 tok/s** — below the ≥20 tok/s daily-driver bar. **UD-Q6_K**
  (~25–30 tok/s projected, 200k+ with huge headroom) is the recommended
  target if the eval lane shows Q4 quality gaps; Q8_0 if evals justify
  another ~5 tok/s.
- Concurrency doubles: 8 full-context slots become feasible (~150 tok/s
  aggregate projected at Q4).
- Costs the analysis flags: pulling the donor 3090s kills the tier-1 fleet
  nodes on win2/win4 (router config must change the same day); 4×3090 needs
  ≥1600 W PSU or ~275 W power limits; consumer-board PCIe lanes are fine for
  layer-split, hostile to row-split.
- **Decision gate:** run the quality matrix on Q4 vs Q6 vs Q8 *before*
  moving hardware — projections above must be confirmed by `local-eval`.

## How to re-benchmark (agents and operators)

```bash
# Perf (streaming TTFT, tok/s, p50/p95), direct and through the router:
go run . bench -url http://127.0.0.1:8010 -model qwen3.8-27b-local \
  -requests 8 -concurrency 4 -max-tokens 192 -output /tmp/bench.json

# Quality (50-prompt locked corpus, pass rates per category):
~/runs/fleet-bench -mode matrix -corpus v300-baseline \
  -endpoint http://127.0.0.1:8787/v1 -model qwen3.8-27b-local -out /tmp/matrix.json
```

Run perf sweeps only while the model is otherwise idle — a concurrent eval
pollutes TTFT and tok/s (observed: TTFT p50 inflated 3.8 s under contention).

### `bench` metric semantics

- **TTFT** = time to the **first SSE delta of any kind**, reasoning/thinking
  deltas included (`delta.reasoning_content` / `delta.reasoning` /
  `delta.content`). This is the standard queue + prefill definition and is
  comparable across thinking and non-thinking models. `bench` deliberately
  does **not** report time-to-first-*visible*-content: for reasoning models
  the whole think phase streams before the first visible delta, so that
  number tracks how long the model chose to think, not how responsive the
  serving stack is.
- **`avg_prompt_tokens_per_sec`** = prompt tokens / TTFT window (prefill
  rate, slightly understated by network + router hop).
- **`avg_generation_tokens_per_sec`** = completion tokens (thinking +
  visible) / decode window (latency − TTFT).

History: before the fix that introduced these semantics, `bench` anchored
TTFT at the first *visible* content delta, which for reasoning models made
TTFT ≈ full latency, inflated the generation rate several-fold (completion
tokens divided by only the visible tail) and deflated the prompt rate
(prompt tokens divided by full latency) — e.g. 1254 tok/s "generation"
against a server-side truth of ~36 tok/s. Numbers from `bench` builds
predating `TestRunBenchRequestReasoningStreamMetrics` are unreliable;
server-side `print_timing` journal lines remain the cross-check authority.
