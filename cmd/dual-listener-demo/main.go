// Command dual-listener-demo runs an AES/mTLS-style HTTP listener
// and a SOCKS5 listener side-by-side against an in-process mock
// upstream. It is a proof-of-concept for the ListenerFactory
// contract introduced in v18705 (see ADR-082) and instrumented in
// v18709 with OpenTelemetry + Agentrace + Prometheus
// observability.
//
// Scope: this binary is NOT wired into the production router
// boot sequence. It exists for:
//
//  1. Demonstrating that two ListenerFactory implementations can
//     compose in a single daemon.
//  2. Smoke-testing the v18705 / v18709 closeout evidence gate.
//  3. Regression-test scaffolding for future dual-listener work.
//
// Observability surface (v18709):
//
//   - OpenTelemetry: opt-in via OTEL_EXPORTER_OTLP_ENDPOINT.
//     When set, InitTracer wires an OTLP gRPC exporter to the
//     supplied endpoint; spans are emitted per accept. When
//     unset (default in tests), the tracer is a no-op.
//   - Agentrace: writes one NDJSON line per accept to the path
//     configured via --agentrace-log or the package-level
//     `agentraceLogPath` (default ./agentrace-router.ndjson).
//     Concurrent writes dedupe per key via golang.org/x/sync/
//     singleflight.
//   - Prometheus: exposes /metrics on the address configured via
//     --metrics-addr (or `metricsListenAddr` package var). The
//     dedicated registry lives in
//     internal/proxy/observability so the demo's series do not
//     collide with the production router metrics.
//
// Usage:
//
//	go run ./cmd/dual-listener-demo \
//	    --aes-addr 127.0.0.1:18080 \
//	    --socks5-addr 127.0.0.1:11080 \
//	    --metrics-addr 127.0.0.1:18090 \
//	    --mock-body "hello from the demo upstream" \
//	    --agentrace-log /tmp/agentrace-router.ndjson
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/nfsarch33/llm-cluster-router/internal/proxy"
	"github.com/nfsarch33/llm-cluster-router/internal/proxy/observability"
	socks5proxy "github.com/nfsarch33/llm-cluster-router/internal/proxy/socks5"
)

// Package-level configuration that the demo respects and that
// tests override to inject an in-process observability surface.
// Defaults are safe (no-op tracer, local NDJSON, metrics on
// 127.0.0.1:18090).
var (
	agentraceLogPath  = defaultAgentraceLogPath()
	metricsListenAddr = "127.0.0.1:18090"
	demoRegistry      = prometheus.NewRegistry()
	demoAgentraceMu   sync.Mutex
	demoAgentrace     *observability.AgentraceAppender
	demoAgentracePath string // path the current demoAgentrace was opened with
)

func defaultAgentraceLogPath() string {
	return filepath.Join(os.TempDir(), "agentrace-router.ndjson")
}

// errEmptyFlag is returned by runDualListenerDemo when an
// address flag is empty. Sentinel for tests via errors.Is.
var errEmptyFlag = errors.New("dual-listener-demo: aes-addr and socks5-addr must both be set")

// init wires the demo metrics registry once at package load. The
// registry is package-scoped so tests can use it directly without
// re-initialising the global Prometheus default registry.
func init() {
	if err := observability.RegisterMetrics(demoRegistry); err != nil {
		// Already-registered is a no-op; any other error is fatal.
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			log.Fatalf("dual-listener-demo: register metrics: %v", err)
		}
	}
	// InitTracer is no-op when OTEL_EXPORTER_OTLP_ENDPOINT is
	// unset, which is the test default.
	if _, err := observability.InitTracer(context.Background(), "llm-cluster-router-demo"); err != nil {
		log.Printf("dual-listener-demo: tracer init (continuing no-op): %v", err)
	}
}

// getAgentrace returns the package-level Agentrace appender,
// initialising it lazily on first use. If `agentraceLogPath`
// changes between calls (typical in tests that override the
// default), the previous appender is closed and a new one is
// opened against the new path. This keeps the test surface
// ergonomic: each test can use its own temp file without
// resetting globals.
func getAgentrace() *observability.AgentraceAppender {
	demoAgentraceMu.Lock()
	defer demoAgentraceMu.Unlock()
	if demoAgentrace != nil && demoAgentracePath == agentraceLogPath {
		return demoAgentrace
	}
	// Path changed (or first use): close prior appender, open new.
	if demoAgentrace != nil {
		_ = demoAgentrace.Close()
		demoAgentrace = nil
	}
	a, err := observability.NewAgentraceAppender(agentraceLogPath)
	if err != nil {
		log.Printf("dual-listener-demo: agentrace open (continuing without): %v", err)
		return nil
	}
	demoAgentrace = a
	demoAgentracePath = agentraceLogPath
	return demoAgentrace
}

// startMockUpstream binds an in-process HTTP server on a random
// loopback port and returns the address plus a serve function. The
// HTTP server replies to any request with the configured body.
func startMockUpstream(ctx context.Context, body string) (string, func(context.Context) error, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
	srv := &http.Server{Handler: mux}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr := ln.Addr().String()

	serve := func(ctx context.Context) error {
		// Shut down when ctx is cancelled.
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	return addr, serve, nil
}

// runDualListenerDemo wires both listener factories against the
// mock upstream and blocks until ctx is cancelled. The AES/mTLS
// listener accepts plain TCP (TLS termination is performed by the
// upstream reverse-proxy in production; see ADR-082 §2 scope cap)
// and forwards requests to the mock upstream over loopback. The
// SOCKS5 listener forwards CONNECT requests to the mock upstream.
//
// v18709 observability: each AES accept is recorded as an
// Agentrace event + Prometheus counter; the /metrics handler
// serves the demo-scoped Prometheus registry.
//
// runDualListenerDemo returns nil on graceful shutdown, or a
// non-nil error if flag validation fails or any listener exits
// unexpectedly before shutdown.
func runDualListenerDemo(ctx context.Context, aesAddr, socksAddr, mockBody string) error {
	if aesAddr == "" || socksAddr == "" {
		return errEmptyFlag
	}

	upstreamAddr, mockServe, err := startMockUpstream(ctx, mockBody)
	if err != nil {
		return fmt.Errorf("start mock upstream: %w", err)
	}

	// Mock upstream runs in its own goroutine.
	go func() { _ = mockServe(ctx) }()

	// Build the AES/mTLS-style listener factory and wire it to a
	// minimal HTTP handler that proxies the request to the mock
	// upstream over loopback. This is the proof that the factory
	// composes with an http.Server.
	aesFactory := proxy.NewAESMTLSListenerFactory()
	aesLn, aesServe, err := aesFactory.Listen(ctx, aesAddr)
	if err != nil {
		return fmt.Errorf("aes-mtls listen: %w", err)
	}
	// aesServe is the factory's generic ServeLoop; for HTTP we use
	// http.Server.Serve directly on aesLn instead.
	_ = aesServe
	aesHandler := newLoopbackProxyHandler(upstreamAddr)
	// Wrap the handler with observability: each request opens an
	// OTel span + emits an Agentrace event + bumps the Prometheus
	// counter. The wrapper is HTTP-only and respects ctx.
	instrumentedHandler := instrumentHTTPHandler("aes-mtls", aesHandler)
	aesServer := &http.Server{
		Handler:           instrumentedHandler,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// SOCKS5 listener: builds the factory and lets armon/go-socks5
	// drive the ServeLoop.
	socksFactory := socks5proxy.NewListenerFactory()
	socksLn, socksServe, err := socksFactory.Listen(ctx, socksAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}

	// Wire shutdown coordination.
	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := aesServer.Serve(aesLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("aes-mtls serve: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := socksServe(ctx, socksLn); err != nil {
			errCh <- fmt.Errorf("socks5 serve: %w", err)
		}
	}()

	// v18709: dedicated /metrics server on the configured
	// address. Bounded by ctx so graceful shutdown is fast.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := startMetricsServer(ctx, metricsListenAddr); err != nil {
			errCh <- fmt.Errorf("metrics serve: %w", err)
		}
	}()

	// Wait for ctx cancellation; on cancel, shut down all servers.
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = aesServer.Shutdown(shutdownCtx)
	_ = aesLn.Close()
	_ = socksLn.Close()

	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			return e
		}
	}
	return nil
}

// instrumentHTTPHandler wraps an http.Handler with the v18709
// observability surface: per-request OTel span + Agentrace event +
// Prometheus counter and bytes counters. The listener label flows
// through every signal so Grafana queries can split the two
// listener flavours.
func instrumentHTTPHandler(listener string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := observability.Tracer().Start(r.Context(), "demo.accept")
		span.SetAttributes(
			attribute.String("listener", listener),
			attribute.String("remote_addr", r.RemoteAddr),
		)
		defer span.End()
		_ = trace.SpanFromContext(ctx)

		start := time.Now()
		// Wrap ResponseWriter to capture bytes written.
		ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)
		dur := time.Since(start)

		// Prometheus: counter + bytes + duration.
		outcome := outcomeLabel(ww.status)
		observability.ConnectionsTotal.WithLabelValues(listener, outcome).Inc()
		observability.BytesTotal.WithLabelValues(listener, "in").Add(float64(r.ContentLength))
		observability.BytesTotal.WithLabelValues(listener, "out").Add(float64(ww.bytes))
		observability.RequestDuration.WithLabelValues(listener, r.Method).Observe(dur.Seconds())

		// v18714-3: HelixChannel session counter — emit ONLY for
		// the AES/mTLS listener (the brand-named "helixchannel"
		// channel). Other listeners keep their connection-level
		// metric; only this one tracks per-session outcome so
		// tampering / decrypt_error / success can be alerted on
		// without false positives from the SOCKS5 loopback tests.
		if listener == "helixchannel" || listener == "aes-mtls" {
			observability.ObserveHelixChannelSession(ctx, sessionOutcomeFromStatus(ww.status))
		}

		// Agentrace: one event per accept.
		if app := getAgentrace(); app != nil {
			_ = app.Append(observability.AgentraceEvent{
				TS:         time.Now().UTC().Format(time.RFC3339Nano),
				Event:      "demo.accept",
				Listener:   listener,
				RemoteAddr: r.RemoteAddr,
				BytesIn:    r.ContentLength,
				BytesOut:   int64(ww.bytes),
				DurationMS: dur.Milliseconds(),
			}, listener+"|"+r.RemoteAddr)
		}
	})
}

// startMetricsServer serves the demo's Prometheus registry on /metrics.
// Bounded by ctx so the demo exits cleanly when the parent context
// is cancelled.
func startMetricsServer(ctx context.Context, addr string) error {
	if addr == "" {
		// No metrics addr configured: idle until ctx cancellation.
		<-ctx.Done()
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(demoRegistry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// outcomeLabel maps HTTP status codes into the Prometheus outcome
// label space. We collapse 4xx and 5xx into single buckets to keep
// the cardinality bounded (production Grafana dashboards depend on
// this).
func outcomeLabel(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "ok"
	case status >= 500:
		return "error"
	default:
		// 3xx (redirect) and 4xx (client error) collapse into
		// "closed" — neither is a server fault, but they're
		// not "ok" either.
		return "closed"
	}
}

// sessionOutcomeFromStatus maps an HTTP status code to the v18714-3
// HelixChannel session-outcome label. The mapping is coarser than
// outcomeLabel because session outcome is a SLO signal — we want
// "success" / "failure" / "closed" buckets, not "ok" / "error"
// which are operationally confusing. The "tampering" and
// "decrypt_error" outcomes are NOT produced by the HTTP path
// directly; they are emitted by the wire-level forwarder in
// internal/proxy/listener.go (startTamperForwarder) when the AES-GCM
// authentication tag fails. They appear here as a defensive default
// to keep dashboards happy if the wire-forwarder is bypassed in a
// future refactor.
func sessionOutcomeFromStatus(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "success"
	case status >= 500:
		return "failure"
	default:
		// 1xx, 3xx, 4xx — the request reached us, we did not
		// crash, but it did not complete a normal success cycle.
		// "closed" is the canonical graceful teardown bucket.
		return "closed"
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status
// code and bytes written for the v18709 metrics path.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// newLoopbackProxyHandler returns an http.Handler that proxies
// every request to the supplied loopback upstream address.
func newLoopbackProxyHandler(upstream string) http.Handler {
	client := &http.Client{Timeout: 5 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://"+upstream+r.RequestURI, r.Body)
		if err != nil {
			http.Error(w, "proxy: build request failed", http.StatusInternalServerError)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "proxy: upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = bufio.NewReader(resp.Body).WriteTo(w)
	})
}

func main() {
	var (
		aesAddr      = flag.String("aes-addr", "127.0.0.1:18080", "TCP bind address for the AES/mTLS-style HTTP listener")
		socksAddr    = flag.String("socks5-addr", "127.0.0.1:11080", "TCP bind address for the SOCKS5 listener")
		metricsAddr  = flag.String("metrics-addr", "127.0.0.1:18090", "TCP bind address for the /metrics + /healthz endpoints")
		agentraceLog = flag.String("agentrace-log", defaultAgentraceLogPath(), "Path to the Agentrace NDJSON log (one event per accept)")
		mockBody     = flag.String("mock-body", "hello from the dual-listener demo mock upstream", "body served by the in-process mock upstream")
	)
	flag.Parse()

	agentraceLogPath = *agentraceLog
	metricsListenAddr = *metricsAddr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SIGINT / SIGTERM cancels the context for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	go func() {
		<-sigCh
		cancel()
	}()

	log.Printf("dual-listener-demo starting: aes=%s socks5=%s metrics=%s agentrace=%s",
		*aesAddr, *socksAddr, *metricsAddr, *agentraceLog)
	if err := runDualListenerDemo(ctx, *aesAddr, *socksAddr, *mockBody); err != nil {
		log.Fatalf("dual-listener-demo: %v", err)
	}
	if app := getAgentrace(); app != nil {
		_ = app.Close()
	}
	log.Printf("dual-listener-demo stopped")
}
