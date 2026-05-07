package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestSyntheticLoad_RouterMetricsStayHealthy(t *testing.T) {
	const (
		model    = "synthetic-v310"
		requests = 40
		workers  = 4
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":5}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	t.Cleanup(upstream.Close)

	r := newTestRouter(t, upstream.URL, model)
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	sem := make(chan struct{}, workers)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"ping"}]}`, model))))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.handleProxy(rec, req)
			if rec.Code != http.StatusOK {
				errs <- fmt.Errorf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	durationCount := histogramCountForLabels(t, "llm_router_request_duration_seconds", map[string]string{
		"model": model,
	})
	if durationCount < requests {
		t.Fatalf("duration observations = %d, want at least %d", durationCount, requests)
	}
	tokenCount := histogramCountForLabels(t, "llm_router_generation_tokens_per_second", map[string]string{
		"model": model,
	})
	if tokenCount < requests {
		t.Fatalf("generation token-rate observations = %d, want at least %d", tokenCount, requests)
	}
}
