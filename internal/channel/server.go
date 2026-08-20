package channel

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AuditEvent is one NDJSON line describing a proxied request.
//
// It deliberately records no request or response body, no Authorization
// header and no credential material — only the metadata needed to answer
// "did this work, how fast, and through which route".
type AuditEvent struct {
	TS         string `json:"ts"`
	Event      string `json:"event"`
	RequestID  string `json:"request_id"`
	Route      string `json:"route,omitempty"`
	AuthMode   string `json:"auth_mode,omitempty"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
	Target     string `json:"target,omitempty"`
	Status     int    `json:"status,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
	BytesOut   int64  `json:"bytes_out,omitempty"`
	ClientAddr string `json:"client_addr,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Auditor writes audit events.
type Auditor interface {
	Log(AuditEvent)
}

// ndjsonAuditor serialises events to a writer, one JSON object per line.
type ndjsonAuditor struct {
	mu sync.Mutex
	w  io.Writer
}

// NewAuditor returns an Auditor writing NDJSON to w.
func NewAuditor(w io.Writer) Auditor { return &ndjsonAuditor{w: w} }

func (a *ndjsonAuditor) Log(e AuditEvent) {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = a.w.Write(append(b, '\n'))
}

// Server is the HelixChannel gateway: a path-prefix reverse proxy for
// API-key upstreams plus an optional CONNECT tunnel for clients that must
// keep their own end-to-end TLS session.
type Server struct {
	cfg       *Config
	routes    []*boundRoute
	forwarder Forwarder
	audit     Auditor
	connToken string
	allowed   map[string]bool
	httpSrv   *http.Server
}

// NewServer builds a gateway from validated configuration.
//
// All credentials are resolved here so that a misconfigured route fails at
// startup with a clear message instead of returning 502s later.
func NewServer(cfg *Config, fwd Forwarder, audit Auditor) (*Server, error) {
	if fwd == nil {
		fwd = NewHTTPForwarder()
	}
	s := &Server{cfg: cfg, forwarder: fwd, audit: audit, allowed: map[string]bool{}}

	for _, r := range cfg.EnabledRoutes() {
		auth, err := NewAuthenticator(r)
		if err != nil {
			return nil, err
		}
		s.routes = append(s.routes, &boundRoute{Route: r, Auth: auth})
	}
	// Longest prefix first, so "/openai/codex/" wins over "/openai/" when
	// both are configured.
	sort.Slice(s.routes, func(i, j int) bool {
		return len(s.routes[i].Route.Prefix) > len(s.routes[j].Route.Prefix)
	})

	if cfg.Connect.Enabled {
		tok, err := readSecret(cfg.Connect.TokenEnv, cfg.Connect.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
		s.connToken = tok
		for _, h := range cfg.Connect.AllowedHosts {
			s.allowed[strings.ToLower(h)] = true
		}
	}
	return s, nil
}

// RouteNames returns the enabled route names, longest-prefix first. Used by
// /healthz and by the CLI to show what the gateway is actually serving.
func (s *Server) RouteNames() []string {
	out := make([]string, 0, len(s.routes))
	for _, r := range s.routes {
		out = append(out, r.Route.Name)
	}
	return out
}

// Handler returns the gateway's http.Handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CONNECT is dispatched before path routing: its request target is
		// an authority ("api.anthropic.com:443"), not a path.
		if r.Method == http.MethodConnect {
			s.handleConnect(w, r)
			return
		}
		switch r.URL.Path {
		case "/healthz", "/health":
			s.handleHealth(w, r)
			return
		}
		s.handleProxy(w, r)
	})
}

// handleHealth reports liveness together with the routes actually enabled.
//
// Reporting the live route set is deliberate: a static health response that
// cannot distinguish "gateway up" from "upstreams configured" is precisely
// what masked a month-long outage on the pilot host, where a reverse proxy
// answered /healthz from a literal while the fan-out behind it was dead.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"service": "helixchannel-gateway",
		"routes":  s.RouteNames(),
		"connect": s.cfg.Connect.Enabled,
	})
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.NewString()

	rt := s.match(r.URL.Path)
	if rt == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  "not_found",
			"hint":   "prefix the path with an enabled route",
			"routes": s.RouteNames(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), rt.Route.Timeout)
	defer cancel()

	resp, err := s.forwarder.Forward(ctx, r, rt)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		s.audit.Log(AuditEvent{
			Event: "proxy_request", RequestID: requestID, Route: rt.Route.Name,
			AuthMode: string(rt.Auth.Mode()), Method: r.Method, Path: r.URL.Path,
			Upstream: rt.Route.Upstream, Status: http.StatusBadGateway,
			LatencyMS: time.Since(start).Milliseconds(), ClientAddr: r.RemoteAddr,
			Error: errorClass(err),
		})
		return
	}
	defer resp.Body.Close()

	n, _ := copyResponse(w, resp)
	s.audit.Log(AuditEvent{
		Event: "proxy_request", RequestID: requestID, Route: rt.Route.Name,
		AuthMode: string(rt.Auth.Mode()), Method: r.Method, Path: r.URL.Path,
		Upstream: rt.Route.Upstream, Status: resp.StatusCode,
		LatencyMS: time.Since(start).Milliseconds(), BytesOut: n,
		ClientAddr: r.RemoteAddr,
	})
}

// match resolves a path to an enabled route.
func (s *Server) match(path string) *boundRoute {
	for _, rt := range s.routes {
		if strings.HasPrefix(path, rt.Route.Prefix) {
			return rt
		}
	}
	return nil
}

// handleConnect serves the CONNECT tunnel leg.
//
// The gateway authenticates the client with a shared token, checks the target
// against an exact-match allowlist, then copies bytes in both directions. It
// never terminates the inner TLS session, so the client's own credential
// (for example an OAuth session token) is never visible to the gateway or to
// any intermediate hop — which is the entire point of routing an agent whose
// auth cannot be injected server-side.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.NewString()
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}

	deny := func(status int, reason string) {
		http.Error(w, http.StatusText(status), status)
		s.audit.Log(AuditEvent{
			Event: "connect_denied", RequestID: requestID, Target: target,
			Status: status, LatencyMS: time.Since(start).Milliseconds(),
			ClientAddr: r.RemoteAddr, Error: reason,
		})
	}

	if !s.cfg.Connect.Enabled {
		deny(http.StatusMethodNotAllowed, "connect_disabled")
		return
	}
	if !s.authorizeConnect(r.Header.Get("Proxy-Authorization")) {
		w.Header().Set("Proxy-Authenticate", `Bearer realm="helixchannel"`)
		deny(http.StatusProxyAuthRequired, "bad_token")
		return
	}
	if !s.allowed[strings.ToLower(target)] {
		deny(http.StatusForbidden, "host_not_allowlisted")
		return
	}

	upstream, err := net.DialTimeout("tcp", target, s.cfg.Connect.DialTimeout)
	if err != nil {
		deny(http.StatusBadGateway, "dial_failed")
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		deny(http.StatusInternalServerError, "hijack_unsupported")
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		deny(http.StatusInternalServerError, "hijack_failed")
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	s.audit.Log(AuditEvent{
		Event: "connect_established", RequestID: requestID, Target: target,
		Status: http.StatusOK, LatencyMS: time.Since(start).Milliseconds(),
		ClientAddr: r.RemoteAddr,
	})

	// Both directions are copied concurrently; the tunnel closes as soon as
	// either side does, so a half-closed peer cannot leak a goroutine.
	var wg sync.WaitGroup
	wg.Add(2)
	var bytesUp int64
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, client)
		bytesUp = n
		if c, ok := upstream.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if c, ok := client.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()

	s.audit.Log(AuditEvent{
		Event: "connect_closed", RequestID: requestID, Target: target,
		LatencyMS: time.Since(start).Milliseconds(), BytesOut: bytesUp,
		ClientAddr: r.RemoteAddr,
	})
}

// authorizeConnect compares the presented token in constant time.
func (s *Server) authorizeConnect(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.connToken)) == 1
}

// errorClass reduces an error to a stable label, so audit lines stay free of
// URLs, headers or anything else that could carry a credential.
func errorClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case strings.Contains(err.Error(), "connection refused"):
		return "refused"
	case strings.Contains(err.Error(), "no such host"):
		return "dns"
	case strings.Contains(err.Error(), "certificate"):
		return "tls"
	default:
		return "upstream_error"
	}
}

// ListenAndServe runs the gateway until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.httpSrv = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.cfg.TLS.Enabled() {
			err = s.httpSrv.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		} else {
			err = s.httpSrv.ListenAndServe()
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
