package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfgpkg "github.com/nfsarch33/llm-cluster-router/internal/config"
)

// H2: handleProxy buffered the whole request body BEFORE either admission
// gate, so MaxQueueDepth and MaxConcurrency bounded the upstream fan-out and
// bounded memory not at all.
//
// Every per-request piece is individually capped -- MaxBytesReader at
// max_body_size, the 2MiB limitedBuffer, the 64KiB io.LimitReader -- and the
// multiplier on all of them was the number of connections a caller chose to
// open, which nothing caps. The tests below are about the MULTIPLIER, which is
// why they are written in terms of a peak count of simultaneously held bodies
// rather than in terms of bytes.

// TestHandleProxy_BufferedBodiesAreBoundedByAdmissionNotByConnections is the
// defect itself.
//
// The fixture makes the body SLOW rather than large, and that is the whole
// design: the ceiling being tested is a count of concurrent buffers, so what
// has to be arranged is many callers sitting inside io.ReadAll at the same
// instant. Sixty clients each hold their request body open mid-upload. With
// admission after the read, all sixty are buffered at once and the peak is the
// client count. With admission before it, the ones over the queue ceiling are
// refused while they are still uploading and never allocate at all.
//
// EVERY OBSERVATION IS MADE SERVER-SIDE, through a wrapper around the handler,
// and that is deliberate rather than incidental. The natural version of this
// test counts 429s at the client, and it does not work: an http.Client that is
// still streaming a request body does not surface the early response, so the
// refusals are real, are already written, and are invisible to the caller that
// received them. Written that way the test measures the transport rather than
// the router and reports five seconds of nothing.
func TestHandleProxy_BufferedBodiesAreBoundedByAdmissionNotByConnections(t *testing.T) {
	const (
		clients  = 60
		maxQueue = 4
		maxConc  = 2
		wantPeak = maxQueue + maxConc
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","model":"m1","choices":[]}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouter(t, maxConc, maxQueue, 1<<20, upstream.URL)

	var arrived, refused atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		arrived.Add(1)
		r.handleProxy(&refusalSpy{ResponseWriter: w, refusals: &refused}, req)
	}))
	t.Cleanup(front.Close)

	// Closed once every caller has reached the handler; until then each one is
	// stuck partway through sending its body.
	hold := make(chan struct{})
	client := &http.Client{Timeout: 30 * time.Second}

	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pr, pw := io.Pipe()
			go func() {
				// Chunked, so the request carries no Content-Length and the
				// declared-size gate cannot be what refuses it. The gap is
				// where the caller sits while the router decides.
				_, _ = io.WriteString(pw, `{"model":"m1","messages":[`)
				<-hold
				_, _ = io.WriteString(pw, `{"role":"user","content":"hi"}]}`)
				_ = pw.Close()
			}()
			req, err := http.NewRequest(http.MethodPost, front.URL+"/v1/chat/completions", pr)
			if err != nil {
				t.Errorf("build request: %v", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			// The outcome of the CALL is not the subject here and is not
			// asserted: a caller refused mid-upload legitimately sees a
			// response, a closed connection or a write error depending on how
			// the two sides raced. What the router did is counted above.
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}

	// The bound is an upper limit on how long sixty connections take to reach
	// one handler, not synchronisation. It is generous because expiring early
	// would UNDER-count the peak, which would make the assertion pass for the
	// wrong reason -- so the arrival count is asserted too.
	waitFor(func() bool { return arrived.Load() >= clients }, 20*time.Second)
	peak := r.bufferingPeak.Load()
	got, hits := arrived.Load(), refused.Load()

	close(hold)
	wg.Wait()

	if got < clients {
		t.Fatalf("only %d of %d callers reached the handler within the wait: the peak below was measured against a load that never arrived", got, clients)
	}
	if peak > wantPeak {
		t.Errorf("peak simultaneously buffered bodies = %d, want <= %d (max_queue_depth %d + max_concurrency %d) with %d callers uploading at once: the body is allocated before admission decides, so the memory ceiling is the connection count and not the configuration",
			peak, wantPeak, maxQueue, maxConc, clients)
	}
	if hits == 0 {
		t.Errorf("no caller was refused out of %d against a queue ceiling of %d: the router was never saturated, so the bound above was not actually exercised", clients, maxQueue)
	}
	waitFor(func() bool { return r.buffering.Load() == 0 }, 10*time.Second)
	if live := r.buffering.Load(); live != 0 {
		t.Errorf("buffered bodies = %d after every request finished, want 0: the counter is not released on some path out of the handler", live)
	}
}

// TestHandleProxy_DeclaredOversizeBodyIsRefusedUnread is the cheap gate in
// front of the counted one.
//
// MaxBytesReader already truncates an oversize body, but it does so BY READING
// UP TO THE LIMIT: a caller who declares more than max_body_size has told the
// router, before a byte moves, that this request cannot be served. Reading it
// anyway is work done on behalf of a request that is going to be refused.
//
// The body here fails the test if it is read at all, which is the only way to
// assert "unread" rather than "read and then discarded".
func TestHandleProxy_DeclaredOversizeBodyIsRefusedUnread(t *testing.T) {
	const maxBody = 1 << 10

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouter(t, 2, 4, maxBody, upstream.URL)

	var reads atomic.Int64
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &countingReader{n: &reads})
	req.ContentLength = 64 << 20
	rec := httptest.NewRecorder()
	r.handleProxy(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d for a request declaring %d bytes against max_body_size %d", rec.Code, http.StatusRequestEntityTooLarge, req.ContentLength, maxBody)
	}
	if got := reads.Load(); got != 0 {
		t.Errorf("the body was read %d time(s) for a request that declared it was too large to serve", got)
	}
	if got := r.queueDepth.Load(); got != 0 {
		t.Errorf("queue depth = %d after a refusal that happens before admission, want 0", got)
	}

	// The same router still serves a request that declares nothing.
	rec = httptest.NewRecorder()
	ok := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m1","messages":[]}`))
	r.handleProxy(rec, ok)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d for an in-limit request, want 200: the declared-size gate refuses more than it was meant to", rec.Code)
	}
}

// TestHandleProxy_RefusalAfterAdmissionReturnsTheQueueSlot covers what moving
// admission earlier put at risk.
//
// Three refusals now happen while a queue slot is held that previously ran
// before any slot existed: a body that will not read, an agent the smartroute
// policy disallows, and no healthy upstream. A slot leaked on any of them is
// permanent -- queueDepth only ever climbs -- so the router would answer 429
// to everybody after MaxQueueDepth such requests, having been taken down by
// its own admission gate.
func TestHandleProxy_RefusalAfterAdmissionReturnsTheQueueSlot(t *testing.T) {
	const maxQueue = 4

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouter(t, 2, maxQueue, 1<<20, upstream.URL)
	for _, n := range r.nodes {
		n.healthy.Store(false)
	}

	for i := 1; i <= maxQueue*3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"m1","messages":[]}`))
		r.handleProxy(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d: status = %d, want %d: the router started refusing on its own queue instead of on the missing upstream, %d requests in", i, rec.Code, http.StatusServiceUnavailable, i)
		}
		if got := r.queueDepth.Load(); got != 0 {
			t.Fatalf("request %d: queue depth = %d after the handler returned, want 0", i, got)
		}
	}
}

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

// countingReader records that the request body was read and never yields data.
type countingReader struct{ n *atomic.Int64 }

func (c *countingReader) Read(_ []byte) (int, error) {
	c.n.Add(1)
	return 0, io.EOF
}

// refusalSpy counts 429s as the handler writes them.
//
// It exists because a refusal issued to a caller that is still uploading is
// invisible at that caller: the response is written and the client does not
// surface it. Counting at the point of writing is the only place the router
// decision can be observed without inventing production instrumentation for
// the test to read.
type refusalSpy struct {
	http.ResponseWriter
	refusals *atomic.Int64
}

func (s *refusalSpy) WriteHeader(code int) {
	if code == http.StatusTooManyRequests {
		s.refusals.Add(1)
	}
	s.ResponseWriter.WriteHeader(code)
}

// newAdmissionRouter builds a one-node router with the admission limits under
// test and marks the node healthy.
func newAdmissionRouter(t *testing.T, maxConc, maxQueue int, maxBody int64, upstreamURL string) *router {
	t.Helper()
	c := config{
		Defaults: cfgpkg.Defaults{
			MaxConcurrency: maxConc,
			MaxQueueDepth:  maxQueue,
			MaxBodySize:    maxBody,
			RequestTimeout: cfgpkg.DurationValue{Duration: 10 * time.Second},
		},
		Nodes: []cfgpkg.NodeConfig{{
			Name: "up", URL: upstreamURL, Tier: "0", Enabled: "true", Weight: 1, Models: []string{"m1"},
		}},
	}
	r, err := newRouter(c)
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}
	for _, n := range r.nodes {
		n.healthy.Store(true)
	}
	return r
}

// waitFor polls cond until it holds or the bound expires, reporting which.
//
// The poll is a BOUND on a condition that has no event to wait on -- "the
// router has finished refusing everyone it is going to refuse" is not
// signalled anywhere -- and both outcomes are legitimate for the caller, which
// is why it returns rather than failing.
func waitFor(cond func() bool, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}
