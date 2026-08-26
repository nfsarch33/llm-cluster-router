package channel

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A hermetic upstream
// ---------------------------------------------------------------------------

// upstreamNonceHeader carries, on the CALLER's request, the identity of the
// test whose gateway is supposed to forward it. The gateway copies caller
// headers onto its outbound request, so every request this gateway sends still
// carries it and nothing else does.
const upstreamNonceHeader = "X-Test-Upstream-Nonce"

// upstreamProbeSeq makes each probe within a process distinct; the pid makes
// each process distinct. Both halves are needed: `go test ./...` runs many test
// binaries at once, and a second copy of THIS package is one of the processes a
// stray request can arrive from.
var upstreamProbeSeq atomic.Int64

// upstreamProbe is an httptest upstream that counts only the requests the
// gateway under test actually sent it.
//
// WHY COUNTING ARRIVALS WAS WRONG. An httptest server binds a loopback TCP
// port, and every process on the machine can reach that port. Under
// `go test ./...` that is not hypothetical. The freePort helper in
// cmd/dual-listener-demo picks a port by binding 127.0.0.1:0, CLOSING the
// socket and re-using the number, so in the window between that close and the
// re-bind another package's httptest server can be handed the same port — and
// then receives the traffic addressed to the demo. Captured arriving at a
// rotation test's upstream from a different test binary on this tree:
// GET /probe, GET /v1/models, and POST /v1/chat/completions.
//
// Each of those was counted as a request this gateway had made. That is how
// TestRotation_RequestCapIsExactAcrossThePoolSizeAndCapSweep reported "21
// served against a cap of 20" about once in seventy race-shuffle runs while,
// in the very same failing run, the store had charged exactly 20, the gateway
// had called Forward exactly 20 times, and the transport had written exactly
// 20 requests. The cap was never exceeded. The instrument counted traffic that
// belonged to someone else, inside a test whose entire purpose is an exact
// count.
//
// The nonce travels on the CALLER's request and is checked at the upstream, so
// it proves ORIGIN rather than arrival. That is why this is not a way of making
// a red test green: a duplicate round trip the gateway really did make — a
// transport replay, a retry, a genuine over-admission — is a request the
// gateway forwarded, so it carries the nonce and is STILL counted. Only traffic
// that provably did not come through the gateway under test is excluded.
//
// A stray is answered 421 Misdirected Request and the wrapped handler does NOT
// run. Running it would be worse than miscounting: these upstreams call
// releaseGate.note, and a note raised by another process can release a burst
// before that burst has come to rest, which turns a foreign packet into a
// timing change inside the code under test.
type upstreamProbe struct {
	*httptest.Server
	nonce  string
	hits   atomic.Int64
	mu     sync.Mutex
	strays []string
}

// newUpstreamProbe starts an upstream that runs h for the gateway under test
// and refuses everything else. The server is closed by t.Cleanup, and stray
// traffic is reported there rather than silently dropped: a test that quietly
// tolerates another process writing to its socket has lost the ability to
// explain its own numbers.
func newUpstreamProbe(t *testing.T, h http.HandlerFunc) *upstreamProbe {
	t.Helper()
	p := &upstreamProbe{nonce: fmt.Sprintf("probe-%d-%d", os.Getpid(), upstreamProbeSeq.Add(1))}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(upstreamNonceHeader) != p.nonce {
			p.recordStray(r)
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		p.hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(func() {
		p.Close()
		if report := p.strayReport(); report != "" {
			t.Logf("upstream probe on %s ignored %s", p.URL, report)
		}
	})
	return p
}

// stamp marks a caller request as belonging to the gateway this probe serves.
func (p *upstreamProbe) stamp(req *http.Request) *http.Request {
	req.Header.Set(upstreamNonceHeader, p.nonce)
	return req
}

// header is stamp for the helpers that take an http.Header rather than a
// request. extra may be nil.
func (p *upstreamProbe) header(extra http.Header) http.Header {
	h := http.Header{}
	for k, vs := range extra {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	h.Set(upstreamNonceHeader, p.nonce)
	return h
}

// hitCount is how many requests the gateway under test sent this upstream.
func (p *upstreamProbe) hitCount() int64 { return p.hits.Load() }

func (p *upstreamProbe) recordStray(r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.strays = append(p.strays, fmt.Sprintf("%s %s from %s (User-Agent %q)",
		r.Method, r.URL.RequestURI(), r.RemoteAddr, r.Header.Get("User-Agent")))
}

// strayReport describes the traffic this probe refused, or the empty string
// when there was none.
func (p *upstreamProbe) strayReport() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.strays) == 0 {
		return ""
	}
	return fmt.Sprintf("%d request(s) that did not come through the gateway under test: %s",
		len(p.strays), strings.Join(p.strays, "; "))
}

// TestUpstreamProbe_CountsWhatTheGatewaySentNotWhatArrived is the test of the
// instrument itself, and it STAGES the contamination rather than waiting for
// it: one request through the gateway, one straight at the socket from
// something that is not the gateway.
//
// Both halves are load-bearing. Without the first, a probe that counted nothing
// would pass. Without the second, the plain arrival counter would pass and the
// one-in-seventy flake would still be there.
func TestUpstreamProbe_CountsWhatTheGatewaySentNotWhatArrived(t *testing.T) {
	t.Parallel()
	var handled atomic.Int64
	probe := newUpstreamProbe(t, func(w http.ResponseWriter, _ *http.Request) {
		handled.Add(1)
		_, _ = io.WriteString(w, `{"usage":{"total_tokens":1}}`)
	})
	srv := rotServer(t, rotatingConfig(t, "mm", probe.URL, []string{"k0-not-real"},
		&RotationConfig{Budget: Budget{Window: time.Hour, Requests: 5, SoftRatio: 1}}), nil, nil)

	if rec := serve(srv, http.MethodGet, "/mm/v1/chat", probe.header(nil)); rec.Code != http.StatusOK {
		t.Fatalf("gateway status = %d, want 200: the probe must not refuse the gateway it belongs to", rec.Code)
	}
	if got := probe.hitCount(); got != 1 {
		t.Fatalf("probe counted %d gateway requests, want 1", got)
	}

	// The measured shapes were GET /probe, GET /v1/models and
	// POST /v1/chat/completions, each from another test binary that had been
	// handed this port by a bind-close-reuse helper.
	resp, err := http.Get(probe.URL + "/probe")
	if err != nil {
		t.Fatalf("stray request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("stray answered %d, want %d: a request that reached the wrong process should be told so",
			resp.StatusCode, http.StatusMisdirectedRequest)
	}
	if got := probe.hitCount(); got != 1 {
		t.Errorf("probe counted %d requests after one stray, want 1: counting arrivals rather than what this gateway SENT is what reported a request-cap over-serve that never happened", got)
	}
	if got := handled.Load(); got != 1 {
		t.Errorf("the wrapped handler ran %d times, want 1: a stray must not reach it, or another process can release a burst gate before the burst is at rest", got)
	}
	if probe.strayReport() == "" {
		t.Error("the stray was not recorded: contamination must stay reportable, not merely excluded, or the next investigation starts from nothing again")
	}
}
