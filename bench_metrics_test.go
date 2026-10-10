package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newReasoningSSEServer streams a chat completion the way llama-server
// streams a reasoning model: a silent prefill window, then think-phase
// deltas carrying only reasoning_content, then a short tail of visible
// content deltas, then the usage chunk requested via
// stream_options.include_usage. The timings are generous multiples of
// scheduler jitter so the assertions below can stay relational
// (fractions of measured latency) rather than absolute.
func newReasoningSSEServer(t *testing.T, prefill, thinking, content time.Duration, promptTokens, completionTokens int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer does not support flushing")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")

		time.Sleep(prefill)
		if thinking > 0 {
			const chunks = 9
			for i := 0; i < chunks; i++ {
				_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"think \"}}]}\n\n")
				flusher.Flush()
				time.Sleep(thinking / chunks)
			}
		}
		if content > 0 {
			const chunks = 3
			for i := 0; i < chunks; i++ {
				_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok \"}}]}\n\n")
				flusher.Flush()
				time.Sleep(content / chunks)
			}
		}
		_, _ = io.WriteString(w, fmt.Sprintf("data: {\"usage\":{\"prompt_tokens\":%d,\"completion_tokens\":%d}}\n\n", promptTokens, completionTokens))
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	t.Cleanup(server.Close)
	return server
}

// TestRunBenchRequestReasoningStreamMetrics pins the bench metric
// semantics against a reasoning-model stream with known token counts:
//
//   - TTFT anchors at the first streamed delta of ANY kind (the first
//     reasoning token), not the first visible content delta. The mock
//     spends ~20% of the request in prefill and ~80% generating, so
//     content-anchored TTFT would land at >70% of total latency.
//   - GenerationTokensSec spreads completion tokens over the full
//     decode window (latency - TTFT). Content-anchored TTFT squeezes
//     that window to the visible tail and inflates the rate several-fold
//     past completion/latency, which is the physical lower bound.
//   - PromptTokensSec measures prefill (prompt tokens over the TTFT
//     window), not prompt tokens over total latency — total latency is
//     dominated by decode and yields a nonsense prefill rate.
func TestRunBenchRequestReasoningStreamMetrics(t *testing.T) {
	t.Parallel()

	const (
		promptTokens     = 2048
		completionTokens = 64
	)
	server := newReasoningSSEServer(t, 150*time.Millisecond, 450*time.Millisecond, 150*time.Millisecond, promptTokens, completionTokens)

	result := runBenchRequest(server.Client(), server.URL, "qwen3.8-27b-local", "local", "hello", 10*time.Second, 64)
	if !result.OK {
		t.Fatalf("runBenchRequest returned error: %#v", result)
	}
	if result.PromptTokens != promptTokens || result.CompletionTokens != completionTokens {
		t.Fatalf("usage tokens = %d/%d, want %d/%d", result.PromptTokens, result.CompletionTokens, promptTokens, completionTokens)
	}
	if result.LatencyMillis <= 0 {
		t.Fatalf("latency = %vms, want > 0", result.LatencyMillis)
	}
	latencySec := result.LatencyMillis / 1000

	if result.TTFTMillis <= 0 {
		t.Errorf("ttft = %vms, want > 0 (first reasoning delta arrived after the prefill window)", result.TTFTMillis)
	}
	if result.TTFTMillis >= result.LatencyMillis/2 {
		t.Errorf("ttft = %vms of %vms total latency; TTFT must anchor at the first delta of any kind, not the first visible content delta", result.TTFTMillis, result.LatencyMillis)
	}

	genFloor := float64(completionTokens) / latencySec
	if result.GenerationTokensSec < genFloor {
		t.Errorf("generation rate = %.1f tok/s, below physical floor %.1f tok/s (completion tokens over total latency)", result.GenerationTokensSec, genFloor)
	}
	if maxPlausible := 2 * genFloor; result.GenerationTokensSec > maxPlausible {
		t.Errorf("generation rate = %.1f tok/s, want <= %.1f tok/s; rate must use the full decode window (latency - TTFT), not the visible-content tail", result.GenerationTokensSec, maxPlausible)
	}

	if promptFloor := 2 * float64(promptTokens) / latencySec; result.PromptTokensSec < promptFloor {
		t.Errorf("prompt rate = %.1f tok/s, want >= %.1f tok/s; prefill rate must divide by the TTFT window, not total request latency", result.PromptTokensSec, promptFloor)
	}
}

// TestRunBenchRequestThinkingOnlyStreamStillMeasuresTTFT covers the
// degenerate reasoning case: max_tokens exhausted inside the think
// phase, so the stream carries reasoning deltas and usage but zero
// visible content. TTFT must still anchor at the first reasoning delta
// instead of reporting 0 ("instant").
func TestRunBenchRequestThinkingOnlyStreamStillMeasuresTTFT(t *testing.T) {
	t.Parallel()

	server := newReasoningSSEServer(t, 100*time.Millisecond, 200*time.Millisecond, 0, 100, 32)

	result := runBenchRequest(server.Client(), server.URL, "qwen3.8-27b-local", "local", "hello", 10*time.Second, 32)
	if !result.OK {
		t.Fatalf("runBenchRequest returned error: %#v", result)
	}
	if result.TTFTMillis <= 0 {
		t.Errorf("ttft = %vms, want > 0: a thinking-only stream still has a first token", result.TTFTMillis)
	}
	if result.TTFTMillis >= result.LatencyMillis {
		t.Errorf("ttft = %vms, want < latency %vms", result.TTFTMillis, result.LatencyMillis)
	}
	if result.PromptTokensSec <= 0 {
		t.Errorf("prompt rate = %.1f tok/s, want > 0 when a TTFT window was observed", result.PromptTokensSec)
	}
}
