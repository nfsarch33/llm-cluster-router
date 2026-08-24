package channel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func observeAll(ue UsageExtractor, chunks ...string) UsageSample {
	for _, c := range chunks {
		ue.Observe([]byte(c))
	}
	return ue.Result()
}

func TestUsageExtractor_PlainJSONUsageIsChargedExactly(t *testing.T) {
	t.Parallel()
	body := `{"id":"x","choices":[{"index":0}],"usage":{"prompt_tokens":21,"completion_tokens":4300,"total_tokens":4321}}`
	got := observeAll(NewUsageExtractor(), body)
	if got.Tokens != 4321 {
		t.Errorf("Tokens = %d, want 4321", got.Tokens)
	}
	if got.Estimated {
		t.Error("Estimated = true on a response that reported a real total")
	}
	if got.Outcome != OutcomeCompleted {
		t.Errorf("Outcome = %v, want OutcomeCompleted", got.Outcome)
	}
}

func TestUsageExtractor_SSEUsageIsChargedExactly(t *testing.T) {
	t.Parallel()
	got := observeAll(NewUsageExtractor(),
		"data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
		"data: {\"choices\":[],\"usage\":{\"total_tokens\": 4321}}\n\n",
		"data: [DONE]\n\n",
	)
	if got.Tokens != 4321 {
		t.Errorf("Tokens = %d, want 4321 from the final SSE usage frame", got.Tokens)
	}
	if got.Estimated {
		t.Error("Estimated = true on an SSE stream that did report usage")
	}
}

// TestUsageExtractor_SSEWithoutUsageIsAMarkedEstimate is the whole point of
// TokensUnknown being -1: charging 0 would let an all-streaming route spend a
// token budget that never advances.
func TestUsageExtractor_SSEWithoutUsageIsAMarkedEstimate(t *testing.T) {
	t.Parallel()
	got := observeAll(NewUsageExtractor(),
		"data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
		"data: [DONE]\n\n",
	)
	if got.Tokens != TokensUnknown {
		t.Errorf("Tokens = %d, want TokensUnknown (%d), never 0", got.Tokens, TokensUnknown)
	}
	if !got.Estimated {
		t.Error("Estimated = false on a stream that carried no usage object")
	}
}

// TestUsageExtractor_UsageBeyondTheTailIsAnEstimateNotAZero: the retained tail
// bounds memory, but falling off it must degrade to an estimate.
func TestUsageExtractor_UsageBeyondTheTailIsAnEstimateNotAZero(t *testing.T) {
	t.Parallel()
	filler := strings.Repeat("x", UsageTailBytes+2048)
	got := observeAll(NewUsageExtractor(),
		`{"usage":{"total_tokens":999},"padding":"`+filler+`"}`)
	if got.Tokens != TokensUnknown {
		t.Errorf("Tokens = %d, want TokensUnknown: a usage object outside the tail is unknown, not zero", got.Tokens)
	}
	if !got.Estimated {
		t.Error("Estimated = false when the usage object fell outside the retained tail")
	}
}

// TestUsageExtractor_TokenSplitAcrossChunks: the tail is rolling, so a value
// straddling two writes must still be read.
func TestUsageExtractor_TokenSplitAcrossChunks(t *testing.T) {
	t.Parallel()
	got := observeAll(NewUsageExtractor(), `{"usage":{"total_to`, `kens": 43`, `21}}`)
	if got.Tokens != 4321 {
		t.Errorf("Tokens = %d, want 4321 across chunk boundaries", got.Tokens)
	}
	if got.Estimated {
		t.Error("Estimated = true although the total was readable")
	}
}

// TestUsageExtractor_LastUsageWins: a body that mentions total_tokens more
// than once must be charged the final, authoritative figure.
func TestUsageExtractor_LastUsageWins(t *testing.T) {
	t.Parallel()
	got := observeAll(NewUsageExtractor(),
		`data: {"usage":{"total_tokens":10}}`+"\n\n",
		`data: {"usage":{"total_tokens":37}}`+"\n\n")
	if got.Tokens != 37 {
		t.Errorf("Tokens = %d, want 37 (the last usage frame)", got.Tokens)
	}
}

// TestCopyResponseObserving_NilExtractorIsTodaysBehaviour pins the refactor:
// copyResponse is now a wrapper, and it must still copy the same bytes,
// status and headers.
func TestCopyResponseObserving_NilExtractorIsTodaysBehaviour(t *testing.T) {
	t.Parallel()
	body := `{"object":"list","data":[]}`
	newResp := func() *http.Response {
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Header:     http.Header{"Content-Type": []string{"application/json"}, "Connection": []string{"close"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}
	}

	viaWrapper := httptest.NewRecorder()
	nWrapper, err := copyResponse(viaWrapper, newResp())
	if err != nil {
		t.Fatalf("copyResponse: %v", err)
	}
	viaObserving := httptest.NewRecorder()
	nObserving, err := copyResponseObserving(viaObserving, newResp(), nil)
	if err != nil {
		t.Fatalf("copyResponseObserving: %v", err)
	}

	if nWrapper != nObserving || nWrapper != int64(len(body)) {
		t.Errorf("bytes = %d and %d, want %d", nWrapper, nObserving, len(body))
	}
	if viaWrapper.Code != http.StatusTeapot || viaObserving.Code != http.StatusTeapot {
		t.Errorf("status = %d and %d, want %d", viaWrapper.Code, viaObserving.Code, http.StatusTeapot)
	}
	if viaWrapper.Body.String() != body || viaObserving.Body.String() != body {
		t.Errorf("body = %q / %q, want %q", viaWrapper.Body, viaObserving.Body, body)
	}
	if got := viaObserving.Header().Get("Connection"); got != "" {
		t.Errorf("hop-by-hop Connection header copied through as %q, want it dropped", got)
	}
	if viaWrapper.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want it preserved", viaWrapper.Header().Get("Content-Type"))
	}
}

func TestCopyResponseObserving_TeesTheBodyToTheExtractor(t *testing.T) {
	t.Parallel()
	body := `{"usage":{"total_tokens":77}}`
	rec := httptest.NewRecorder()
	ue := NewUsageExtractor()
	n, err := copyResponseObserving(rec, &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}, ue)
	if err != nil {
		t.Fatalf("copyResponseObserving: %v", err)
	}
	if n != int64(len(body)) || rec.Body.String() != body {
		t.Fatalf("client saw %d bytes %q, want the body untouched", n, rec.Body.String())
	}
	if got := ue.Result(); got.Tokens != 77 {
		t.Errorf("extracted tokens = %d, want 77 from the same buffer the client got", got.Tokens)
	}
}
