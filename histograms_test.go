package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestRequestDuration_LLMBuckets asserts the request_duration_seconds
// histogram uses LLM-tuned buckets (50ms..120s) instead of the
// Prometheus defaults (5ms..10s) which cap at 10s and lose all
// resolution for token-streaming workloads.
func TestRequestDuration_LLMBuckets(t *testing.T) {
	// Seed one observation so the default registry surfaces the
	// histogram with its declared buckets (Prometheus' Gather only
	// returns metrics with at least one sample).
	requestDuration.WithLabelValues("__bucket_probe__", "__bucket_probe__").Observe(0.1)

	got := capturedBuckets(t, "llm_router_request_duration_seconds")
	want := llmHistogramBuckets()
	if len(got) != len(want) {
		t.Fatalf("bucket count: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("bucket %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TestTTFTHistogramExposed asserts the new TTFT histogram is
// registered with the same node label and LLM-friendly buckets so
// we can chart "time-to-first-byte-from-upstream" alongside
// total request duration.
func TestTTFTHistogramExposed(t *testing.T) {
	requestTTFT.WithLabelValues("__bucket_probe__", "__bucket_probe__").Observe(0.1)
	got := capturedBuckets(t, "llm_router_request_ttft_seconds")
	want := llmHistogramBuckets()
	if len(got) != len(want) {
		t.Fatalf("ttft bucket count: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("ttft bucket %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TestHandleProxy_RecordsTTFT issues a real request through
// handleProxy, lets the upstream return immediately, and asserts
// llm_router_request_ttft_seconds picked up at least one
// observation for the node we routed to.
func TestHandleProxy_RecordsTTFT(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	t.Cleanup(upstream.Close)

	r := newTestRouter(t, upstream.URL, "alpha")
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{"model":"alpha","messages":[{"role":"user","content":"ping"}]}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.handleProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	count := histogramCountForLabels(t, "llm_router_request_ttft_seconds", map[string]string{
		"model": "alpha",
	})
	if count < 1 {
		t.Fatalf("expected at least one TTFT observation for model=alpha, got %d", count)
	}
}

// helpers
//

// llmHistogramBuckets is the canonical bucket set the production
// code is required to expose. LLM streaming workloads commonly run
// 200ms-90s end-to-end, so we want resolution across that whole
// range without burning labels on the 10ms-region that vLLM never
// hits.
func llmHistogramBuckets() []float64 {
	return []float64{
		0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120,
	}
}

// capturedBuckets gathers the upper bounds of a registered
// histogram by querying the default Prometheus registry and
// matching by metric name. Returns nil if not found.
func capturedBuckets(t *testing.T, name string) []float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			h := m.GetHistogram()
			if h == nil {
				continue
			}
			out := make([]float64, 0, len(h.Bucket))
			for _, b := range h.Bucket {
				out = append(out, b.GetUpperBound())
			}
			if len(out) > 0 {
				return out
			}
		}
		// Histogram registered but no observations yet; we still
		// need to expose the bucket spec, so synthesise one
		// observation by writing into the metric so it appears
		// in the gather.
		t.Fatalf("histogram %q registered but no buckets visible; "+
			"production code must observe at least once at boot OR "+
			"the test must trigger a request first", name)
	}
	t.Fatalf("histogram %q not registered", name)
	return nil
}

// histogramCountForLabels returns the sample count of a histogram
// matching the given label subset. Returns 0 if no match.
func histogramCountForLabels(t *testing.T, name string, want map[string]string) uint64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			matches := true
			for k, v := range want {
				if labels[k] != v {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
			h := m.GetHistogram()
			if h == nil {
				continue
			}
			return h.GetSampleCount()
		}
	}
	return 0
}

// newTestRouter builds a real *router from a tiny config that
// targets one httptest upstream. Used by handler-level tests.
func newTestRouter(t *testing.T, upstreamURL, model string) *router {
	t.Helper()
	cfg := config{
		Defaults: defaults{
			MaxQueueDepth:  4,
			MaxConcurrency: 2,
			RequestTimeout: durationValue{Duration: 5 * time.Second},
			MaxBodySize:    1 << 20,
		},
		HealthCheck: healthConfig{
			Interval:           durationValue{Duration: time.Hour},
			Timeout:            durationValue{Duration: time.Second},
			Path:               "/v1/models",
			HealthyThreshold:   1,
			UnhealthyThreshold: 1,
		},
		Nodes: []nodeConfig{{
			Name:    strings.ReplaceAll(model, ".", "-") + "-node",
			URL:     upstreamURL,
			Tier:    "fast",
			Enabled: "true",
			Weight:  1,
			Models:  []string{model},
		}},
	}
	r, err := newRouter(cfg)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	return r
}
