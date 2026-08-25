package channel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// This file is the package's ONLY benchmark set, and it exists because the
// repository had none at all: five review rounds added a rotation store, a
// per-request credential strip, a usage extractor and a lease settlement to the
// path every proxied request travels, and nothing in the tree could say what any
// of it cost. A regression in throughput was, until now, unfalsifiable.
//
// What is measured is what an OPERATOR would regress on, so each benchmark is
// pinned to a decision someone might later make:
//
//   - Forward_SingleKey vs Forward_PooledKey — the whole point. The delta is the
//     price of rotation, and it is the number to quote when someone asks whether
//     the hardening cost throughput.
//   - RotationStore_Next / _Settle / _AcquireSettle — one mutex serialises every
//     key on a route, so if anything here is going to fall over under load it is
//     this. Measured at 1, 3 and 7 keys and at concurrency 1, 8 and 64.
//   - CopyResponse — the streaming leg, which the usage extractor moved off
//     io.Copy and onto a hand-rolled 32 KiB loop.
//   - Match — a linear longest-prefix scan, so its cost is O(routes) and worth
//     knowing before someone configures fifty of them.
//   - Audit_Log — one mutex and one json.Marshal on every request.
//   - CredentialHeaderStrip — the deny-set scan, which now runs against every
//     inbound header of every request on every injecting route.
//
// NONE of these touch a network other than loopback via httptest, none contact a
// provider, and none sleep. Every one reports allocations, because an allocation
// regression is the one that shows up as GC pressure in production rather than
// as a slower unit benchmark.
//
// Baseline numbers, with the host and toolchain they were taken on, are in
// docs/benchmarks-helixchannel.md. A benchmark figure without its machine is not
// a measurement.

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// benchRouteName is the single route name every benchmark configures. It is a
// constant rather than a literal so a store lookup miss shows up as a compile
// error rather than as a benchmark that silently measures the not-found path.
const benchRouteName = "bench"

// benchKeyCounts are the pool sizes measured. One key is the degenerate pool
// that still pays the full lease cost; seven is a realistically large one.
var benchKeyCounts = []int{1, 3, 7}

// benchConcurrency are the goroutine counts measured. Sixty-four is well past
// the point where a single mutex stops scaling, which is exactly why it is here.
var benchConcurrency = []int{1, 8, 64}

// benchNopObserver keeps retirement accounting off the global Prometheus
// registry. No benchmark here configures a budget, so nothing retires and this
// is never called — it is injected so that stays true even if one later does.
type benchNopObserver struct{}

func (benchNopObserver) KeyRetired(string, RetireReason) {}

// runBench executes body b.N times, sequentially when conc is 1 and spread
// across roughly conc goroutines otherwise.
//
// "Roughly" is not hedging. testing.B.SetParallelism takes a MULTIPLIER of
// GOMAXPROCS, not an absolute goroutine count, so an absolute target has to be
// divided by GOMAXPROCS and floored at one. On a host with more cores than the
// requested concurrency the floor wins and the achieved figure is GOMAXPROCS
// instead. That is why docs/benchmarks-helixchannel.md records GOMAXPROCS
// alongside every number: without it "conc=8" names a different experiment on a
// different machine.
//
// i is a PER-GOROUTINE counter, not a global one. A shared atomic would add a
// contended increment to every iteration and so would measure itself as much as
// the code under test; callers only use i to spread work across keys, for which
// each goroutine counting independently is equivalent.
func runBench(b *testing.B, conc int, body func(i int)) {
	b.Helper()
	if conc <= 1 {
		for i := 0; i < b.N; i++ {
			body(i)
		}
		return
	}
	p := conc / runtime.GOMAXPROCS(0)
	if p < 1 {
		p = 1
	}
	b.SetParallelism(p)
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			body(i)
			i++
		}
	})
}

// benchWriter is a minimal http.ResponseWriter that counts what it is given and
// keeps none of it.
//
// httptest.NewRecorder would buffer every response body, which on the 1 MiB
// CopyResponse shape would put the reported allocations at the mercy of the
// recorder rather than of the code under test — the benchmark would measure the
// harness.
//
// It deliberately does NOT implement http.Flusher: that is the whole point of
// the no_flusher shapes, which take copyResponseObserving's io.Copy fast path.
type benchWriter struct {
	hdr  http.Header
	code int
	n    int64
}

func (w *benchWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = make(http.Header, 8)
	}
	return w.hdr
}

func (w *benchWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

func (w *benchWriter) WriteHeader(code int) { w.code = code }

// benchFlushWriter is benchWriter that also flushes, which is what every real
// net/http response writer does.
//
// The handler benchmarks use THIS one and not benchWriter, because a
// non-flushing writer would send the single-key shape down io.Copy while the
// pooled shape stayed on the buffered loop — the two would then differ by a copy
// strategy as well as by rotation, and the delta this file exists to report
// would be measuring the wrong thing.
type benchFlushWriter struct{ benchWriter }

func (w *benchFlushWriter) Flush() {}

// benchPayload builds a response body of about size bytes shaped like an
// OpenAI-compatible completion, with a real usage object at the END so the
// tail-scanning UsageExtractor has genuine work to do rather than finding the
// marker in the first chunk.
func benchPayload(size int) []byte {
	const head = `{"id":"bench","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"`
	const tail = `"}}],"usage":{"prompt_tokens":11,"completion_tokens":22,"total_tokens":33}}`
	pad := size - len(head) - len(tail)
	if pad < 0 {
		pad = 0
	}
	buf := make([]byte, 0, len(head)+pad+len(tail))
	buf = append(buf, head...)
	buf = append(buf, bytes.Repeat([]byte("x"), pad)...)
	return append(buf, tail...)
}

// benchBody serves a []byte as an http.Response.Body.
//
// It implements Read and Close and DELIBERATELY NOTHING ELSE. bytes.Reader
// implements io.WriterTo, and io.NopCloser propagates that through, so a body
// built the obvious way sends io.Copy down its WriteTo shortcut: the entire body
// reaches the writer in one call, no copy buffer is ever allocated, and the
// first draft of BenchmarkCopyResponse reported a 1 MiB body copied in two
// microseconds at 444 GB/s. That is a measurement of the harness.
//
// A real upstream body is a network stream — net/http's *body type, which has no
// WriteTo — so reading through Read alone is both the fair comparison and the
// faithful one.
type benchBody struct {
	buf []byte
	off int
}

func (r *benchBody) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

func (r *benchBody) Close() error { return nil }

// benchRequestBody is the inbound body every handler benchmark posts. It is
// small on purpose: the request leg is not what this file measures, and a large
// one would bury the gateway's own per-request cost under memmove.
var benchRequestBody = []byte(`{"model":"bench","messages":[{"role":"user","content":"hello"}]}`)

// benchRequest builds one inbound request.
//
// A FRESH request per iteration is mandatory, not tidiness: handleProxy deletes
// the gateway token header from whatever it is handed, and Forward consumes the
// body. Both handler benchmarks pay this construction cost identically, so it
// cancels out of the single-key/pooled delta.
//
// Authorization and X-Api-Key are present because an injecting route must STRIP
// them, and a benchmark whose inbound headers contain nothing to strip would
// report the strip as free. The values are obvious placeholders.
func benchRequest(path string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(benchRequestBody))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Encoding", "gzip")
	r.Header.Set("User-Agent", "helixchannel-bench/1")
	r.Header.Set("X-Request-Id", "bench-request")
	r.Header.Set("Authorization", "Bearer placeholder-not-a-credential")
	r.Header.Set("X-Api-Key", "placeholder-not-a-credential")
	return r
}

// benchKeyFile writes one credential file under dir and returns its path.
//
// Files rather than environment variables, for the same reason the rotation
// tests use them: b.Setenv cannot be used from a parallel benchmark, and a
// process-global mutation is a poor foundation for a measurement. The contents
// are distinct per file because NewServer rejects a pool whose keys are
// duplicates, and they are not credentials.
func benchKeyFile(b *testing.B, dir, name string) string {
	b.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("BENCH-NOT-A-CREDENTIAL-"+name+"\n"), 0o600); err != nil {
		b.Fatalf("write key file %s: %v", p, err)
	}
	return p
}

// benchValidated runs the real Validate, so every benchmark measures a route
// carrying the same defaults a loaded config would (notably Route.Timeout, which
// stays zero otherwise and would make every forward's context expire on
// creation).
func benchValidated(b *testing.B, cfg *Config) *Config {
	b.Helper()
	if err := cfg.Validate(); err != nil {
		b.Fatalf("validate config: %v", err)
	}
	return cfg
}

// benchSingleKeyConfig is the pre-rotation shape: one key, one bearerInjector,
// no store, no lease, no usage extractor.
func benchSingleKeyConfig(b *testing.B, upstream string) *Config {
	b.Helper()
	dir := b.TempDir()
	return benchValidated(b, &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name:    benchRouteName,
		Prefix:  "/bench/",
		Auth:    AuthInject,
		KeyFile: benchKeyFile(b, dir, "single.key"),
		Enabled: true,

		Upstream: upstream,
	}}})
}

// benchPooledConfig is the shape this branch added: a key pool behind a
// rotatingInjector, which on every request takes a lease, builds a
// leasedInjector, streams the response through a UsageExtractor and settles.
//
// Round-robin and no budget on purpose. A budget would retire keys partway
// through a long run and turn the benchmark into a measurement of the refusal
// path, which is a different question and would make the number depend on b.N.
func benchPooledConfig(b *testing.B, upstream string, keys int) *Config {
	b.Helper()
	dir := b.TempDir()
	files := make([]string, 0, keys)
	for i := 0; i < keys; i++ {
		files = append(files, benchKeyFile(b, dir, "pool"+strconv.Itoa(i)+".key"))
	}
	return benchValidated(b, &Config{Listen: "127.0.0.1:0", Routes: []Route{{
		Name:     benchRouteName,
		Prefix:   "/bench/",
		Auth:     AuthInject,
		KeyFiles: files,
		Rotation: &RotationConfig{Policy: PolicyRoundRobin},
		Enabled:  true,

		Upstream: upstream,
	}}})
}

// benchServer builds a gateway. Audit output goes to io.Discard rather than
// being switched off, because ndjsonAuditor.Log's json.Marshal runs on every
// request in production and excluding it would flatter the result.
func benchServer(b *testing.B, cfg *Config, fwd Forwarder) *Server {
	b.Helper()
	srv, err := NewServer(cfg, fwd, NewAuditor(io.Discard))
	if err != nil {
		b.Fatalf("NewServer: %v", err)
	}
	return srv
}

// benchForwarder is an in-process stand-in for an upstream.
//
// It exists so the gateway_only shapes can measure what the GATEWAY costs per
// request without a loopback TCP round trip in the way. That round trip is tens
// of microseconds; the rotation work this file exists to price is around one.
// Measuring the two together would report the noise on the round trip and call
// it the answer.
//
// hdr and body are shared and read-only, so this is safe under -race from any
// number of goroutines.
type benchForwarder struct {
	hdr  http.Header
	body []byte
}

func (f *benchForwarder) Forward(_ context.Context, req *http.Request, _ *boundRoute) (*http.Response, error) {
	// A real transport reads the request body; not doing so would leave the
	// inbound body's cost out of the comparison.
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     f.hdr,
		Body:       &benchBody{buf: f.body},
		Request:    req,
	}, nil
}

// benchUpstream starts a loopback httptest server answering with body. It is
// the "mock upstream" for the http_upstream shapes, which run the REAL
// httpForwarder and therefore the real credential strip and the real transport.
func benchUpstream(b *testing.B, body []byte) *httptest.Server {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	b.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// 1. Per-request cost: single key versus pooled key
// ---------------------------------------------------------------------------

// BenchmarkForward_SingleKey is the CONTROL: the pre-rotation path, end to end
// through Server.Handler. Read it only against BenchmarkForward_PooledKey.
func BenchmarkForward_SingleKey(b *testing.B) {
	benchForwardShapes(b, func(bb *testing.B, upstream string) *Config {
		return benchSingleKeyConfig(bb, upstream)
	})
}

// BenchmarkForward_PooledKey is the same request against a three-key pool, so
// the difference from BenchmarkForward_SingleKey is exactly the rotation work:
// Store.reserve, the KeyLease, the leasedInjector, the UsageExtractor teed off
// the streaming copy, and the settlement.
func BenchmarkForward_PooledKey(b *testing.B) {
	benchForwardShapes(b, func(bb *testing.B, upstream string) *Config {
		return benchPooledConfig(bb, upstream, 3)
	})
}

// benchForwardShapes runs one route shape twice:
//
//	gateway_only  — an in-process Forwarder. This is the number to subtract one
//	                shape from the other with: it contains the gateway's own
//	                per-request work and nothing else.
//	http_upstream — the real httpForwarder against a loopback httptest server.
//	                It includes the credential strip and a real TCP round trip,
//	                so it is the realistic per-request figure but far too noisy
//	                to read a one-microsecond delta out of.
func benchForwardShapes(b *testing.B, build func(*testing.B, string) *Config) {
	payload := benchPayload(2048)
	up := benchUpstream(b, payload)

	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("X-Request-Id", "bench-upstream")

	b.Run("gateway_only", func(b *testing.B) {
		srv := benchServer(b, build(b, up.URL), &benchForwarder{hdr: hdr, body: payload})
		h := srv.Handler()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := &benchFlushWriter{}
			h.ServeHTTP(w, benchRequest("/bench/v1/chat/completions"))
			if w.code != http.StatusOK || w.n == 0 {
				b.Fatalf("gateway answered %d with %d body bytes, want 200 and a non-empty body; the benchmark is measuring an error path", w.code, w.n)
			}
		}
	})

	b.Run("http_upstream", func(b *testing.B) {
		srv := benchServer(b, build(b, up.URL), NewHTTPForwarder())
		h := srv.Handler()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := &benchFlushWriter{}
			h.ServeHTTP(w, benchRequest("/bench/v1/chat/completions"))
			if w.code != http.StatusOK || w.n == 0 {
				b.Fatalf("gateway answered %d with %d body bytes, want 200 and a non-empty body; the benchmark is measuring an error path", w.code, w.n)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 2. Rotation store: selection, settlement, and the round trip between them
// ---------------------------------------------------------------------------

// BenchmarkRotationStore_Next measures selection and reservation alone —
// Store.reserve's whole critical section, including the per-call KeyState slice
// and the policy's choice.
//
// Each iteration LEAVES ITS RESERVATION OUTSTANDING, because settling it would
// fold Store.settleLocked into the number and _Settle already measures that
// separately. The consequence is stated plainly rather than hidden: the per-key
// lease slice grows for the length of the run, so the reported allocations
// include its amortised growth, and a long run at high concurrency will hold
// tens of megabytes of lease timestamps. That growth is real behaviour — it is
// what a burst of genuinely in-flight requests does — but it means _Next is a
// LOWER bound on selection cost and an UPPER bound on its allocation, and that
// the honest per-request figure is _AcquireSettle below.
func BenchmarkRotationStore_Next(b *testing.B) {
	benchStoreShapes(b, func(b *testing.B, st *Store, keys, conc int) {
		runBench(b, conc, func(int) {
			if idx := st.Next(benchRouteName); idx < 0 {
				b.Errorf("Next refused a reservation on an unbudgeted %d-key route; the benchmark is measuring the refusal path", keys)
			}
		})
	})
}

// BenchmarkRotationStore_Settle measures the settlement half: releasing the
// in-flight slot, charging requests and tokens, and evaluating the caps.
//
// Settlements are spread across keys the way rotation spreads selections, so the
// figure is not one key's cache line answering every call.
func BenchmarkRotationStore_Settle(b *testing.B) {
	sample := UsageSample{Outcome: OutcomeCompleted, Tokens: 128}
	benchStoreShapes(b, func(b *testing.B, st *Store, keys, conc int) {
		runBench(b, conc, func(i int) {
			st.RecordSample(benchRouteName, i%keys, sample)
		})
	})
}

// BenchmarkRotationStore_AcquireSettle is the ROUND TRIP, and it is the number
// that belongs in a capacity calculation: exactly what one proxied request costs
// the store, with nothing left outstanding at the end of an iteration.
//
// It is also the shape whose memory is bounded, which is what makes it readable
// at conc=64 where _Next is not.
func BenchmarkRotationStore_AcquireSettle(b *testing.B) {
	sample := UsageSample{Outcome: OutcomeCompleted, Tokens: 128}
	benchStoreShapes(b, func(b *testing.B, st *Store, keys, conc int) {
		runBench(b, conc, func(int) {
			lease, ok := st.Acquire(benchRouteName)
			if !ok {
				b.Errorf("Acquire refused a lease on an unbudgeted %d-key route; the benchmark is measuring the refusal path", keys)
				return
			}
			lease.Settle(sample)
		})
	})
}

// benchStoreShapes runs body across every key count and concurrency, building a
// fresh unbudgeted Store for each combination.
//
// A FRESH store per sub-benchmark matters: testing runs a sub-benchmark several
// times with a growing b.N, and a store carried between those trials would enter
// the timed run with a different amount of accumulated state each time.
func benchStoreShapes(b *testing.B, body func(b *testing.B, st *Store, keys, conc int)) {
	b.Helper()
	for _, keys := range benchKeyCounts {
		for _, conc := range benchConcurrency {
			b.Run(fmt.Sprintf("keys=%d/conc=%d", keys, conc), func(b *testing.B) {
				st := NewStore(
					map[string]int{benchRouteName: keys},
					WithRetireObserver(benchNopObserver{}),
				)
				b.ReportAllocs()
				b.ResetTimer()
				body(b, st, keys, conc)
			})
		}
	}
}

// ---------------------------------------------------------------------------
// 3. The streaming leg
// ---------------------------------------------------------------------------

// BenchmarkCopyResponse prices the response copy at two body sizes across the
// three strategies copyResponseObserving can take.
//
// The shapes are not decoration. Without a Flusher AND without a usage
// extractor, the function delegates to io.Copy; add either one and it drops onto
// a hand-rolled 32 KiB loop that allocates that buffer on EVERY call, flushes
// after every chunk, and — with an extractor — tees each chunk into the tail
// window as well. flusher_usage is the pooled path; no_flusher is what a
// single-key route did before any of this existed.
//
// The bodies are benchBody, not bytes.Reader, for the reason documented there:
// with a WriteTo-capable body the no_flusher shape measures a pointer pass
// rather than a copy.
func BenchmarkCopyResponse(b *testing.B) {
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("X-Request-Id", "bench-upstream")
	// Hop-by-hop, so the header loop has something to skip as well as copy.
	hdr.Set("Connection", "keep-alive")

	sizes := []struct {
		name string
		size int
	}{
		{"small_1KiB", 1024},
		{"large_1MiB", 1 << 20},
	}
	shapes := []struct {
		name  string
		flush bool
		usage bool
	}{
		{"no_flusher", false, false},
		{"flusher", true, false},
		{"flusher_usage", true, true},
	}

	for _, s := range sizes {
		payload := benchPayload(s.size)
		for _, shape := range shapes {
			b.Run(s.name+"/"+shape.name, func(b *testing.B) {
				b.SetBytes(int64(len(payload)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var w http.ResponseWriter
					if shape.flush {
						w = &benchFlushWriter{}
					} else {
						w = &benchWriter{}
					}
					var ue UsageExtractor
					if shape.usage {
						ue = NewUsageExtractor()
					}
					resp := &http.Response{
						StatusCode: http.StatusOK,
						Header:     hdr,
						Body:       &benchBody{buf: payload},
					}
					n, err := copyResponseObserving(w, resp, ue)
					if err != nil {
						b.Fatalf("copyResponseObserving: %v", err)
					}
					if n != int64(len(payload)) {
						b.Fatalf("copied %d bytes, want %d", n, len(payload))
					}
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Route matching
// ---------------------------------------------------------------------------

// BenchmarkMatch prices the longest-prefix scan at 1, 10 and 50 routes.
//
// It measures the WORST case deliberately. Prefixes are built at ascending
// lengths and the benchmarked path matches the SHORTEST of them, which
// NewServer's longest-first sort places last — so every iteration walks the
// whole table before it hits. A benchmark that matched the first entry would
// report O(1) for a scan that is O(routes) and would notice nothing when someone
// configures fifty routes.
func BenchmarkMatch(b *testing.B) {
	for _, n := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			srv := benchMatchServer(b, n)
			// Matches "/r/" and no longer prefix, so the scan runs to the end.
			const path = "/r/v1/models"
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if rt := srv.match(path); rt == nil {
					b.Fatal("no route matched; the benchmark is measuring the miss path")
				}
			}
		})
	}
}

// benchMatchServer builds a gateway carrying n passthrough routes.
//
// Passthrough because it is the one mode that needs no credential, so the whole
// table costs no key resolution and the benchmark's setup stays independent of
// the filesystem. The upstream is never dialled: match does no I/O.
func benchMatchServer(b *testing.B, n int) *Server {
	b.Helper()
	routes := make([]Route, 0, n)
	for i := 0; i < n; i++ {
		routes = append(routes, Route{
			Name:     "bench" + strconv.Itoa(i),
			Prefix:   "/" + strings.Repeat("r", i+1) + "/",
			Upstream: "http://127.0.0.1:1",
			Auth:     AuthPassthrough,
			Enabled:  true,
		})
	}
	cfg := benchValidated(b, &Config{Listen: "127.0.0.1:0", Routes: routes})
	return benchServer(b, cfg, &benchForwarder{})
}

// ---------------------------------------------------------------------------
// 5. Audit serialisation
// ---------------------------------------------------------------------------

// BenchmarkAudit_Log prices one NDJSON line under 1, 8 and 64 concurrent
// writers. Every proxied request produces exactly one, through a single mutex,
// so this is the second serialisation point on the hot path after the rotation
// store.
//
// TS is deliberately left EMPTY, which is how handleProxy hands events over: the
// time.Now().Format that Log then performs is part of the per-request cost and
// pre-filling it would hide that.
func BenchmarkAudit_Log(b *testing.B) {
	idx := 2
	event := AuditEvent{
		Event:        "proxy_request",
		RequestID:    "00000000-0000-4000-8000-000000000000",
		Route:        benchRouteName,
		AuthMode:     string(AuthInject),
		Method:       http.MethodPost,
		Path:         "/bench/v1/chat/completions",
		Upstream:     "http://127.0.0.1:1",
		UpstreamHost: "127.0.0.1:1",
		Status:       http.StatusOK,
		LatencyMS:    42,
		BytesOut:     2048,
		ClientAddr:   "192.0.2.1:1234",
		KeyIndex:     &idx,
		Tokens:       33,
	}
	for _, conc := range benchConcurrency {
		b.Run(fmt.Sprintf("conc=%d", conc), func(b *testing.B) {
			auditor := NewAuditor(io.Discard)
			b.ReportAllocs()
			b.ResetTimer()
			runBench(b, conc, func(int) { auditor.Log(event) })
		})
	}
}

// ---------------------------------------------------------------------------
// 6. The caller-credential deny-set scan
// ---------------------------------------------------------------------------

// benchInboundHeaders is one realistic agent request's header set: eight
// ordinary names the scan must reject and two credentials it must catch.
//
// The count is what makes the benchmark meaningful. isCallerCredential is called
// once per inbound header, so the per-request cost is this whole slice, not one
// name — which is why the benchmark loops the set rather than timing a single
// call.
var benchInboundHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"Content-Type",
	"Content-Length",
	"User-Agent",
	"X-Request-Id",
	"X-Stainless-Lang",
	"Anthropic-Version",
	"Authorization",
	"X-Api-Key",
}

// BenchmarkCredentialHeaderStrip prices the deny-set scan for one request's
// worth of headers, with and without a route-configured key_header.
//
// The two shapes differ by more than one comparison. With no key_header the
// extra clause short-circuits on the empty string; with one, every MISS pays a
// strings.TrimSpace and a second EqualFold on top of the eight-entry table walk
// — and a miss is the common case, since most headers are not credentials.
func BenchmarkCredentialHeaderStrip(b *testing.B) {
	shapes := []struct {
		name   string
		header string
	}{
		{"no_key_header", ""},
		{"key_header", "X-Custom-Key"},
	}
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stripped := 0
				for _, name := range benchInboundHeaders {
					if isCallerCredential(name, shape.header) {
						stripped++
					}
				}
				if stripped != 2 {
					b.Fatalf("scan stripped %d of %d headers, want 2; the benchmark is measuring the wrong header set",
						stripped, len(benchInboundHeaders))
				}
			}
		})
	}
}
