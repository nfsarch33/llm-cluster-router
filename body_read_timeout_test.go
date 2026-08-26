package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfgpkg "github.com/nfsarch33/llm-cluster-router/internal/config"
)

// af42cf0 moved admission ahead of allocation, bounding the bodies held in
// memory by MaxQueueDepth + MaxConcurrency instead of by the connection count.
// It did so by taking the queue slot BEFORE io.ReadAll and HOLDING IT ACROSS
// the read -- and nothing bounded that read.
//
// Its own commit body rejects moving the semaphore ahead of io.ReadAll on
// exactly this reasoning: "MaxConcurrency defaults to 2 and there is no read
// timeout on the body, so a few slow uploads would hold every upstream slot
// and starve traffic that was ready to serve: that trades memory exhaustion
// for availability exhaustion." The reasoning was right, and it was applied to
// one resource and not the other. A queue slot held across an unbounded read
// is the same trade reached through the other gate.
//
// These tests are about AVAILABILITY -- what a caller with a perfectly good
// request receives while somebody else's upload is stalled -- because a fix
// that bounds the read without restoring that is not a fix.

// TestHandleProxy_StalledUploadsDoNotRefuseReadyCallers is the measured
// regression.
//
// max_queue_depth callers stop sending mid-body. Each holds a queue slot for
// as long as its read lasts, so with an unbounded read the queue is full for
// as long as they care to stay and the router answers 429 to a caller whose
// request is complete and servable. The same four callers against the
// pre-af42cf0 ordering got 200, because no slot was taken until after the
// read.
//
// The 429 in phase one is ASSERTED rather than merely arranged: it is the
// hazard itself, and a run in which it does not appear is a run in which the
// 200 in phase two proves nothing.
func TestHandleProxy_StalledUploadsDoNotRefuseReadyCallers(t *testing.T) {
	const (
		maxQueue = 4
		maxConc  = 2
		// Long enough that phase one cannot race a reaping, short enough that
		// phase two is not a wait worth avoiding.
		bodyRead = 2 * time.Second
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x","model":"m1","choices":[]}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouterWithBodyRead(t, maxConc, maxQueue, 1<<20, bodyRead, upstream.URL)
	front := httptest.NewServer(http.HandlerFunc(r.handleProxy))
	t.Cleanup(front.Close)

	stalls := startStalledUploads(t, front.URL, maxQueue)

	// The stalls are established only when every one of them is inside the
	// handler holding a slot. Asserting the count is what makes the 429 below
	// mean "the queue is full of stalled uploads" rather than "something
	// answered 429".
	if !waitFor(func() bool { return r.queueDepth.Load() == maxQueue }, 20*time.Second) {
		t.Fatalf("queue depth reached %d of the %d stalled uploads within the wait: the saturation the rest of this test measures was never set up", r.queueDepth.Load(), maxQueue)
	}

	if code := postReady(t, front.URL); code != http.StatusTooManyRequests {
		t.Fatalf("a ready caller got %d while %d uploads were stalled, want %d: the fixture is not reproducing the regression, so the recovery asserted below is not being tested",
			code, maxQueue, http.StatusTooManyRequests)
	}

	// NOTHING RELEASES THE STALLED UPLOADS. They are still stalled here and
	// stay stalled until the test ends; the only thing that can give their
	// slots back is the read bound.
	if !waitFor(func() bool { return r.queueDepth.Load() == 0 }, bodyRead+20*time.Second) {
		t.Fatalf("queue depth = %d more than 20s past body_read_timeout %v: a stalled upload holds its queue slot for as long as the caller cares to hold it, so max_queue_depth of them take the router down for everyone else",
			r.queueDepth.Load(), bodyRead)
	}

	if code := postReady(t, front.URL); code != http.StatusOK {
		t.Fatalf("a ready caller got %d after every stalled upload passed its body_read_timeout, want %d: the slots were not returned, so the router is still refusing servable traffic on behalf of callers that stopped talking to it",
			code, http.StatusOK)
	}

	stalls.release()
}

// TestHandleProxy_StalledCallerIsToldWhatHappened is the caller's half of the
// same event.
//
// It speaks HTTP/1.1 over a raw socket instead of using http.Client because
// the point is what comes back on the wire: a client that is still streaming a
// request body does not reliably surface a response written to it early, so
// through a client this assertion is a coin toss about transport internals
// rather than a statement about the router.
//
// 408 and not 503 + Retry-After. 503 would claim the router cannot serve
// requests and Retry-After would name a time when it expects to be able to;
// both are false, because the slot this caller was holding has just been
// returned. The fault is in one caller's upload, and 408 is the status defined
// for a request message that did not arrive in the time the server was
// prepared to wait.
//
// The Connection: close assertion pins a property the caller depends on rather
// than the one line that states it: net/http declines to reuse a connection
// whose body was left undrained, so deleting the handler's explicit header
// does not move this assertion. It is checked because a caller invited to
// reuse this connection would meet an unread body and an expired read deadline
// on its next request, and that is true however the close comes about.
func TestHandleProxy_StalledCallerIsToldWhatHappened(t *testing.T) {
	const bodyRead = 250 * time.Millisecond

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouterWithBodyRead(t, 2, 4, 1<<20, bodyRead, upstream.URL)
	front := httptest.NewServer(http.HandlerFunc(r.handleProxy))
	t.Cleanup(front.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// A chunked body whose first chunk is the opening fragment of the JSON,
	// and then silence. Chunked so the request declares no length and the
	// declared-size gate cannot be what refuses it.
	const fragment = `{"model":"m1","messages":[`
	if _, err := io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\n"+
		"Host: router.test\r\n"+
		"Content-Type: application/json\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n"+
		"1a\r\n"+fragment+"\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if len(fragment) != 0x1a {
		t.Fatalf("chunk header says 0x1a bytes but the fragment is %d", len(fragment))
	}

	if err := conn.SetReadDeadline(time.Now().Add(bodyRead + 20*time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("a caller that stopped sending mid-body got no response at all within 20s of body_read_timeout %v: %v", bodyRead, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d: a caller whose upload was cut off for going silent is being told something other than that its request never arrived", resp.StatusCode, http.StatusRequestTimeout)
	}
	if !resp.Close {
		t.Error("the response did not carry Connection: close; the read deadline on this connection is deliberately left expired, so a caller invited to reuse it would fail the same way on its next request")
	}
}

// TestHandleProxy_ReapedUploadReturnsItsQueueSlot is the router's half.
//
// A slot leaked here is permanent: queueDepth only ever climbs, and the router
// would answer 429 to everybody after max_queue_depth stalls, taken down by
// its own admission gate rather than by any load. Running max_queue_depth*3
// stalls one after another is what turns "the counter looks right" into a
// property -- if any slot leaked, an iteration past the second would be
// refused 429 by the queue gate before its body was read at all, and the
// recorded status says which of the two happened.
//
// The status is observed AT THE HANDLER here, for the reason the neighbouring
// admission tests give; the wire-level assertion lives in the test above.
func TestHandleProxy_ReapedUploadReturnsItsQueueSlot(t *testing.T) {
	const (
		maxQueue = 2
		maxConc  = 2
		bodyRead = 250 * time.Millisecond
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouterWithBodyRead(t, maxConc, maxQueue, 1<<20, bodyRead, upstream.URL)

	codes := &statusLog{}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.handleProxy(&statusSpy{ResponseWriter: w, log: codes}, req)
	}))
	t.Cleanup(front.Close)

	for i := 1; i <= maxQueue*3; i++ {
		stalls := startStalledUploads(t, front.URL, 1)

		if !waitFor(func() bool { return codes.len() >= i }, bodyRead+20*time.Second) {
			t.Fatalf("stall %d: the handler never answered within 20s of body_read_timeout %v; an unbounded read waits for the caller, and this caller is never going to send again", i, bodyRead)
		}
		if got := codes.at(i - 1); got != http.StatusRequestTimeout {
			t.Fatalf("stall %d: status = %d, want %d: %d would mean the queue gate refused this request before reading it, so a slot from an earlier stall was never returned",
				i, got, http.StatusRequestTimeout, http.StatusTooManyRequests)
		}
		if got := r.queueDepth.Load(); got != 0 {
			t.Fatalf("stall %d: queue depth = %d after the handler returned, want 0", i, got)
		}
		if got := r.buffering.Load(); got != 0 {
			t.Fatalf("stall %d: buffered bodies = %d after the handler returned, want 0", i, got)
		}
		stalls.release()
	}
}

// TestHandleProxy_SlowButProgressingUploadIsNotReaped is the test that stops
// the fix from becoming a new availability bug of its own.
//
// The bound is on INACTIVITY, not on total duration, and this caller is the
// difference: a body that arrives in small pieces over well beyond
// body_read_timeout while never pausing for body_read_timeout at any point. A
// single deadline armed once before the read -- or http.Server.ReadTimeout,
// which is exactly that -- kills it. The upload is legitimate and the link is
// merely slow, so refusing it is the same availability failure the fix exists
// to remove, aimed at a different victim.
//
// The elapsed time is asserted for that reason. Without it the test would pass
// against a total cap simply by finishing before the cap was reached, and
// would be guarding nothing.
func TestHandleProxy_SlowButProgressingUploadIsNotReaped(t *testing.T) {
	const (
		bodyRead = 200 * time.Millisecond
		gap      = 50 * time.Millisecond
		fillers  = 18
	)

	var got atomic.Pointer[[]byte]
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got.Store(&b)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouterWithBodyRead(t, 2, 4, 1<<20, bodyRead, upstream.URL)
	front := httptest.NewServer(http.HandlerFunc(r.handleProxy))
	t.Cleanup(front.Close)

	// Whitespace between two JSON tokens: the body is valid JSON at the end
	// and carries no meaning in the middle, so the only thing the chunking
	// varies is THE SHAPE OF ITS ARRIVAL, which is the subject.
	chunks := [][]byte{[]byte(`{"model":"m1",`)}
	for i := 0; i < fillers; i++ {
		chunks = append(chunks, []byte("          "))
	}
	chunks = append(chunks, []byte(`"messages":[]}`))

	var want []byte
	for _, c := range chunks {
		want = append(want, c...)
	}

	body := &tricklingBody{chunks: chunks, gap: gap}
	t.Cleanup(body.stop)

	req, err := http.NewRequest(http.MethodPost, front.URL+"/v1/chat/completions", body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := newTestClient(t, 60*time.Second)
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("a body that trickled steadily for %v with no gap longer than %v was not served at all: %v", elapsed, gap, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d for an upload that made progress every %v, want %d: the bound is being applied to total duration instead of to inactivity, so a caller on a slow link is refused for being slow",
			resp.StatusCode, gap, http.StatusOK)
	}
	if elapsed <= 2*bodyRead {
		t.Fatalf("the upload finished in %v, inside body_read_timeout %v: this test cannot tell an inactivity bound from a total cap unless the upload outlives the bound", elapsed, bodyRead)
	}
	arrived := got.Load()
	if arrived == nil {
		t.Fatal("the upstream never saw the request: it was answered 200 without being forwarded")
	}
	if string(*arrived) != string(want) {
		t.Fatalf("the upstream received %d bytes, want %d: the body was truncated on its way through a bounded read", len(*arrived), len(want))
	}
}

// TestHandleProxy_ReapedUploadsStayWithinTheBufferingBound re-checks
// af42cf0's property on the path that now reaps.
//
// The fixture it inherits releases its sixty callers by hand, so it measures
// the ceiling while everybody is still holding. This one releases nobody:
// sixty callers stall and the read bound is the only thing that ends any of
// them. The peak must still be max_queue_depth + max_concurrency -- a reaper
// that admitted a replacement before releasing what it reaped would show up
// here and nowhere else -- and the counters must return to zero on their own,
// which nothing but the bound can do.
func TestHandleProxy_ReapedUploadsStayWithinTheBufferingBound(t *testing.T) {
	const (
		clients  = 60
		maxQueue = 4
		maxConc  = 2
		bodyRead = 300 * time.Millisecond
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouterWithBodyRead(t, maxConc, maxQueue, 1<<20, bodyRead, upstream.URL)

	var arrived atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		arrived.Add(1)
		r.handleProxy(w, req)
	}))
	t.Cleanup(front.Close)

	stalls := startStalledUploads(t, front.URL, clients)

	if !waitFor(func() bool { return arrived.Load() >= clients }, 30*time.Second) {
		t.Fatalf("only %d of %d callers reached the handler: the bound below was measured against a load that never arrived", arrived.Load(), clients)
	}
	if !waitFor(func() bool { return r.buffering.Load() == 0 && r.queueDepth.Load() == 0 }, bodyRead+30*time.Second) {
		t.Fatalf("buffered bodies = %d and queue depth = %d with nothing left that could release them: the bound is not reaping every stalled upload it admitted",
			r.buffering.Load(), r.queueDepth.Load())
	}
	if peak := r.bufferingPeak.Load(); peak > maxQueue+maxConc {
		t.Errorf("peak simultaneously buffered bodies = %d, want <= %d (max_queue_depth %d + max_concurrency %d) with %d callers stalled at once: the read bound is giving a slot back before the body it was holding is released",
			peak, maxQueue+maxConc, maxQueue, maxConc, clients)
	}

	stalls.release()
}

// TestBodyReadTimeout_ZeroConfigResolvesToTheDefault covers the Config values
// that never went through LoadConfig.
//
// LoadConfig turns an omitted or 0s key into the default, but a Config can
// reach the router without it -- tests build one by hand, and an embedded
// caller may too -- and the zero value of a time.Duration is the same zero an
// operator can type. Handing that zero to a deadline setter would arm a
// deadline that expired the instant it was set, so the key that exists to stop
// stalled uploads would refuse every upload instead. Zero has to mean the
// default in main.go as well, or it does not mean the default at all.
func TestBodyReadTimeout_ZeroConfigResolvesToTheDefault(t *testing.T) {
	if got := bodyReadTimeout(config{}); got != cfgpkg.DefaultBodyReadTimeout {
		t.Fatalf("bodyReadTimeout of a zero config = %v, want the default %v", got, cfgpkg.DefaultBodyReadTimeout)
	}
	explicit := config{Defaults: cfgpkg.Defaults{BodyReadTimeout: cfgpkg.DurationValue{Duration: 3 * time.Second}}}
	if got := bodyReadTimeout(explicit); got != 3*time.Second {
		t.Fatalf("bodyReadTimeout = %v for an explicit 3s, want 3s: the fallback is overwriting a configured value", got)
	}

	// And end to end, because the assertions above are about a number while
	// the failure is about a request: a zero reaching the deadline setter
	// arms a deadline already in the past, and the first read fails before
	// any caller could possibly be at fault.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(upstream.Close)

	r := newAdmissionRouterWithBodyRead(t, 2, 4, 1<<20, 0, upstream.URL)
	front := httptest.NewServer(http.HandlerFunc(r.handleProxy))
	t.Cleanup(front.Close)

	if code := postReady(t, front.URL); code != http.StatusOK {
		t.Fatalf("status = %d for a complete request against a router whose body_read_timeout is the zero value, want %d: zero is being used as the deadline instead of selecting the default",
			code, http.StatusOK)
	}
}

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

// stalledBody yields one prefix and then goes silent for good.
//
// It is a plain reader rather than an io.Pipe because the silence has to be
// the DEFAULT state: a pipe with no writer left is indistinguishable from a
// closed one, and what has to be modelled is a caller that is still connected,
// still owes a body, and is simply not sending it.
type stalledBody struct {
	prefix []byte
	sent   bool
	done   chan struct{}
}

func (s *stalledBody) Read(p []byte) (int, error) {
	if !s.sent {
		s.sent = true
		return copy(p, s.prefix), nil
	}
	<-s.done
	return 0, io.EOF
}

// stalledUploads is the handle for a set of callers that have stopped sending.
type stalledUploads struct {
	once sync.Once
	done chan struct{}
	wg   sync.WaitGroup
}

// release lets every stalled caller finish so the test's goroutines can exit.
// It is idempotent because it is called both explicitly at the end of a happy
// path and from t.Cleanup on every other one.
func (s *stalledUploads) release() {
	s.once.Do(func() { close(s.done) })
	s.wg.Wait()
}

// startStalledUploads opens n POSTs that send the opening fragment of a JSON
// body and then nothing.
//
// Each caller gets its own transport so a connection torn down by the read
// bound can never be handed to a later request in the same test: with pooling,
// the outcome would depend on which connection the pool happened to offer.
// The clients are built on the test goroutine and only used from the spawned
// ones, because t.Cleanup after a test returns is a panic.
func startStalledUploads(t *testing.T, frontURL string, n int) *stalledUploads {
	t.Helper()
	s := &stalledUploads{done: make(chan struct{})}
	t.Cleanup(s.release)
	for i := 0; i < n; i++ {
		client := newTestClient(t, 60*time.Second)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			body := &stalledBody{prefix: []byte(`{"model":"m1","messages":[`), done: s.done}
			// Chunked, because the reader's length is unknown: the request
			// carries no Content-Length, so the declared-size gate cannot be
			// what refuses it.
			req, err := http.NewRequest(http.MethodPost, frontURL+"/v1/chat/completions", body)
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			// The outcome AT THE CALLER is not the subject here and is not
			// asserted: a caller cut off mid-upload sees a response, a closed
			// connection or a write error depending on how the two sides
			// raced. What the router did is observed server-side.
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
	return s
}

// tricklingBody delivers one chunk per tick: a caller that is slow but never
// silent.
//
// The tick is the STIMULUS, not synchronisation -- the arrival rate is the
// thing under test, and there is no other goroutine whose progress it waits
// on.
type tricklingBody struct {
	chunks [][]byte
	gap    time.Duration
	i      int
	ticker *time.Ticker
}

func (t *tricklingBody) Read(p []byte) (int, error) {
	if t.i >= len(t.chunks) {
		return 0, io.EOF
	}
	if t.i > 0 {
		if t.ticker == nil {
			t.ticker = time.NewTicker(t.gap)
		}
		<-t.ticker.C
	}
	n := copy(p, t.chunks[t.i])
	t.i++
	return n, nil
}

func (t *tricklingBody) stop() {
	if t.ticker != nil {
		t.ticker.Stop()
	}
}

// statusLog records the statuses the handler wrote, in order.
type statusLog struct {
	mu    sync.Mutex
	codes []int
}

func (l *statusLog) add(code int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.codes = append(l.codes, code)
}

func (l *statusLog) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.codes)
}

func (l *statusLog) at(i int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.codes[i]
}

// statusSpy records what the handler answered.
//
// Unwrap is not decoration. http.ResponseController walks a wrapper chain
// looking for SetReadDeadline, and a wrapper that embeds the
// http.ResponseWriter INTERFACE promotes only that interface's three methods,
// never the concrete *http.response's deadline setters. Without Unwrap the
// controller reports ErrNotSupported, the handler falls back to an unbounded
// read, and a test of the bound would quietly be measuring its absence.
type statusSpy struct {
	http.ResponseWriter
	log *statusLog
}

func (s *statusSpy) WriteHeader(code int) {
	s.log.add(code)
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusSpy) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// newTestClient returns a client that never reuses a connection, so no test
// outcome depends on which pooled connection was offered.
func newTestClient(t *testing.T, timeout time.Duration) *http.Client {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: timeout}
}

// postReady sends a complete, servable request and reports the status.
func postReady(t *testing.T, frontURL string) int {
	t.Helper()
	resp, err := newTestClient(t, 30*time.Second).Post(
		frontURL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m1","messages":[]}`))
	if err != nil {
		t.Fatalf("ready caller: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
