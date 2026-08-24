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
	"strconv"
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

	// KeyIndex is the pool slot that served the request. It appears only on
	// pooled routes, so legacy single-key and passthrough lines stay
	// byte-identical.
	//
	// *int, not int: with `omitempty` a plain int would DROP key_index==0 —
	// the most common slot, and the one a two-key route uses half the time —
	// and without omitempty every existing single-key and passthrough line
	// would gain a spurious "key_index":0. A nil pointer keeps today's lines
	// unchanged. The pointer must address a fresh local, never a shared field.
	KeyIndex *int `json:"key_index,omitempty"`
	// Tokens is set only when a real usage.total_tokens was observed.
	Tokens int64 `json:"tokens,omitempty"`
	// TokensEstimated marks a charge derived from Budget.EstimateTokens
	// because the response carried no usage object.
	TokensEstimated bool `json:"tokens_estimated,omitempty"`
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

// KeyInventory is the /healthz key surface for one route.
//
// It exists to separate "this route holds no credential BY DESIGN" from "this
// route holds no credential BY ACCIDENT", which a bare map[string]int could
// not: both rendered as 0. Every entry carries Mode, so a zero is never
// ambiguous.
//
// Invariants:
//
//	Keys == 0 && !Pooled  <=>  Mode == AuthPassthrough   (by design)
//	Keys == 0 &&  Pooled   =>  misconfiguration          (by accident)
//	Degraded == Pooled && Available == 0
//
// NewServer rejects an empty resolved pool, so the by-accident case is
// unreachable from configuration and Degraded means only "every key on this
// route is currently retired or drained" — page-worthy, but a different fact
// from "this route was never given a credential".
//
// Counts only: never a key, prefix, suffix, length or fingerprint. Any per-key
// hint on an unauthenticated endpoint is an oracle for correlating which
// account served which request.
type KeyInventory struct {
	Mode      AuthMode `json:"mode"`
	Pooled    bool     `json:"pooled"`
	Keys      int      `json:"keys"`
	Available int      `json:"available"`
	Degraded  bool     `json:"degraded"`
}

// Server is the HelixChannel gateway: a path-prefix reverse proxy for
// API-key upstreams plus an optional CONNECT tunnel for clients that must
// keep their own end-to-end TLS session.
//
// There is deliberately no map of rotation stores here. Each pooled route's
// Store is owned by its *rotatingInjector and reached through the keyLeaser
// capability; a second reference that only tests ever read is a field that
// drifts.
type Server struct {
	cfg       *Config
	routes    []*boundRoute
	forwarder Forwarder
	audit     Auditor
	connToken string
	allowed   map[string]bool
	httpSrv   *http.Server
}

// serverOptions are the injectable construction dependencies.
type serverOptions struct {
	secrets  SecretProvider
	now      func() time.Time
	observer RetireObserver
}

// ServerOption customises Server construction. Variadic options keep every
// existing three-argument NewServer call compiling unchanged.
type ServerOption func(*serverOptions)

// WithSecretProvider overrides the SecretProvider used to resolve every route
// credential and the CONNECT token. It defaults to NewDefaultSecretProvider().
func WithSecretProvider(sp SecretProvider) ServerOption {
	return func(o *serverOptions) { o.secrets = sp }
}

// WithRotationClock injects the clock every rotation Store reads, so a test can
// advance a window instead of sleeping. Named apart from the StoreOption
// WithClock because Go has one package namespace for both.
func WithRotationClock(now func() time.Time) ServerOption {
	return func(o *serverOptions) { o.now = now }
}

// WithRotationRetireObserver replaces the retirement metric sink on every
// rotation Store, so a test can assert reasons without touching a global
// registry.
func WithRotationRetireObserver(o RetireObserver) ServerOption {
	return func(so *serverOptions) { so.observer = o }
}

// NewServer builds a gateway from validated configuration.
//
// Every credential is resolved HERE, eagerly, before Handler() is reachable —
// so a misconfigured route fails at startup with a clear message instead of
// returning 502s later, and Server.connToken is written exactly once and only
// read thereafter. ONE SecretProvider is shared across every route and the
// CONNECT token, so a vault item named twice is fetched once.
//
// Only ENABLED routes are resolved: a switched-off route with a broken
// credential must not be able to take the gateway down.
func NewServer(cfg *Config, fwd Forwarder, audit Auditor, opts ...ServerOption) (*Server, error) {
	if fwd == nil {
		fwd = NewHTTPForwarder()
	}
	var o serverOptions
	for _, opt := range opts {
		opt(&o)
	}
	sp := o.secrets
	if sp == nil {
		sp = NewDefaultSecretProvider()
	}
	s := &Server{cfg: cfg, forwarder: fwd, audit: audit, allowed: map[string]bool{}}

	for _, r := range cfg.EnabledRoutes() {
		// The Store is sized from configuration alone: resolveKeyPool yields
		// exactly one key per declared slot, so the pool can be accounted for
		// before any credential is held.
		var st *Store
		if hasPluralKeys(r) {
			st = newRotationStore(r, declaredKeyCount(r), o)
		}
		auth, err := newAuthenticatorFor(r, sp, st)
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
		tok, err := resolveFirst(sp, secretRefs(cfg.Connect.TokenRef, cfg.Connect.TokenEnv, cfg.Connect.TokenFile))
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
		// Belt and braces: connToken can never be "" on a running server,
		// because an empty token would make ConstantTimeCompare authorise an
		// empty bearer. authorizeConnect guards the same fact independently.
		if tok = strings.TrimSpace(tok); tok == "" {
			return nil, fmt.Errorf("connect: %w", ErrSecretEmpty)
		}
		s.connToken = tok
		for _, h := range cfg.Connect.AllowedHosts {
			s.allowed[strings.ToLower(h)] = true
		}
	}
	return s, nil
}

// newRotationStore builds one accounting Store per pooled route. Budgets and
// policies are per-route configuration, so a shared store would have to pick
// one route's budget for all of them.
func newRotationStore(r Route, keys int, o serverOptions) *Store {
	rot := r.Rotation
	if rot == nil {
		rot = &RotationConfig{}
	}
	policy, err := NewPolicy(rot.Policy)
	if err != nil {
		// Validate rejects an unknown policy at startup; falling back here
		// keeps a programmatically built Config serving rather than panicking.
		policy = NewRoundRobinPolicy()
	}
	opts := []StoreOption{
		WithPolicy(policy),
		WithBudget(rot.Budget),
		WithMaxRetryAfter(rot.MaxRetryAfter),
	}
	if o.now != nil {
		opts = append(opts, WithClock(o.now))
	}
	if o.observer != nil {
		opts = append(opts, WithRetireObserver(o.observer))
	}
	return NewStore(map[string]int{r.Name: keys}, opts...)
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

// KeyInventory reports, per enabled route, how many server-held credentials
// back it and how many are selectable right now. See the KeyInventory type for
// the by-design / by-accident distinction it exists to preserve.
func (s *Server) KeyInventory() map[string]KeyInventory {
	out := make(map[string]KeyInventory, len(s.routes))
	for _, rt := range s.routes {
		if kl, ok := rt.Auth.(keyLeaser); ok {
			out[rt.Route.Name] = kl.inventory()
			continue
		}
		mode := rt.Auth.Mode()
		if mode == AuthPassthrough {
			// No credential BY DESIGN: the caller holds it.
			out[rt.Route.Name] = KeyInventory{Mode: mode}
			continue
		}
		out[rt.Route.Name] = KeyInventory{Mode: mode, Keys: 1, Available: 1}
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
// answered /healthz from a literal while the fan-out behind it was dead. The
// key inventory extends the same argument to credentials: a route with every
// key drained is serving 503s, and a health endpoint that cannot say so is
// answering from a literal again.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"service": "helixchannel-gateway",
		"routes":  s.RouteNames(),
		"keys":    s.KeyInventory(),
		"connect": s.cfg.Connect.Enabled,
	})
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.NewString()

	rt := s.match(r.URL.Path)
	if rt == nil {
		s.writeNotFound(w)
		return
	}

	// The rotation branch is entered only through a type assertion that
	// bearerInjector, leasedInjector and passthrough deliberately fail, so the
	// single-key path runs through code this change does not touch.
	fwdRoute, lease := rt, (*KeyLease)(nil)
	if kl, ok := rt.Auth.(keyLeaser); ok {
		auth, l, live := kl.leaseFor()
		if !live {
			s.denyDrained(w, rt, r, requestID, start, kl.retryAfter())
			return
		}
		fwdRoute, lease = &boundRoute{Route: rt.Route, Auth: auth}, l
		// Settle is sync.Once-guarded, so this deferred failure settlement is
		// a no-op once the success path has settled. Between them, exactly one
		// settlement happens on every exit path including a panic.
		defer lease.Settle(UsageSample{Outcome: OutcomeFailed})
	}

	ctx, cancel := context.WithTimeout(r.Context(), rt.Route.Timeout)
	defer cancel()

	resp, err := s.forwarder.Forward(ctx, r, fwdRoute)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		event := AuditEvent{
			Event: "proxy_request", RequestID: requestID, Route: rt.Route.Name,
			AuthMode: string(rt.Auth.Mode()), Method: r.Method, Path: r.URL.Path,
			Upstream: rt.Route.Upstream, Status: http.StatusBadGateway,
			LatencyMS: time.Since(start).Milliseconds(), ClientAddr: r.RemoteAddr,
			Error: errorClass(err),
		}
		// The 502 line carries the key index too: during a per-key outage,
		// which account failed is exactly what an operator needs.
		if lease != nil {
			idx := lease.Index()
			event.KeyIndex = &idx
		}
		s.audit.Log(event)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var usage UsageExtractor
	if lease != nil {
		usage = NewUsageExtractor()
	}
	n, _ := copyResponseObserving(w, resp, usage)

	event := AuditEvent{
		Event: "proxy_request", RequestID: requestID, Route: rt.Route.Name,
		AuthMode: string(rt.Auth.Mode()), Method: r.Method, Path: r.URL.Path,
		Upstream: rt.Route.Upstream, Status: resp.StatusCode,
		LatencyMS: time.Since(start).Milliseconds(), BytesOut: n,
		ClientAddr: r.RemoteAddr,
	}
	if lease != nil {
		s.settleLease(rt, lease, resp.StatusCode, usage, &event)
	}
	s.audit.Log(event)
}

// writeNotFound is the unchanged 404 body, extracted so handleProxy stays
// readable.
func (s *Server) writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":  "not_found",
		"hint":   "prefix the path with an enabled route",
		"routes": s.RouteNames(),
	})
}

// settleLease charges the request against its key and annotates the audit
// event. An upstream quota signal retires the key BEFORE the lease is settled,
// so the next selection already skips it.
func (s *Server) settleLease(rt *boundRoute, lease *KeyLease, status int, usage UsageExtractor, event *AuditEvent) {
	sample := usage.Result()
	if isQuotaStatus(status) {
		if kl, ok := rt.Auth.(keyLeaser); ok {
			kl.retire(lease.Index(), ReasonQuota)
		}
	}
	lease.Settle(sample)

	// A fresh local, addressed once: sharing a field here would let a later
	// request mutate a value this line has not yet marshalled.
	idx := lease.Index()
	event.KeyIndex = &idx
	if sample.Tokens != TokensUnknown {
		event.Tokens = sample.Tokens
	}
	event.TokensEstimated = sample.Estimated
}

// isQuotaStatus reports whether an upstream status means "this key's plan is
// spent" rather than "this upstream is broken".
//
// 402 is included alongside 429 because header-auth providers (the Exa/Tavily
// class) commonly signal an exhausted plan with Payment Required. Treating that
// as a generic upstream error would keep re-selecting the dead key until the
// window rolled.
func isQuotaStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusPaymentRequired
}

// denyDrained answers a request that arrived with every plan spent.
func (s *Server) denyDrained(w http.ResponseWriter, rt *boundRoute, r *http.Request, requestID string, start time.Time, retryAfter time.Duration) {
	s.writeDrained(w, rt.Route.Name, retryAfter)
	s.audit.Log(AuditEvent{
		Event: "proxy_request", RequestID: requestID, Route: rt.Route.Name,
		AuthMode: string(rt.Auth.Mode()), Method: r.Method, Path: r.URL.Path,
		Upstream: rt.Route.Upstream, Status: http.StatusServiceUnavailable,
		LatencyMS: time.Since(start).Milliseconds(), ClientAddr: r.RemoteAddr,
		Error: "keys_exhausted",
	})
}

// writeDrained writes the all-keys-spent answer: 503 with Retry-After, NOT 502.
//
// An operator paging on 502 is hunting a broken upstream; a route whose plans
// are all spent is a billing question. Collapsing the two is how a quota
// outage gets triaged as an outage. The body names the route and the wait and
// carries no credential material.
func (s *Server) writeDrained(w http.ResponseWriter, route string, retryAfter time.Duration) {
	secs := int64(retryAfter / time.Second)
	if retryAfter%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":               "keys_exhausted",
		"hint":                "every upstream key on this route is retired or drained; retry after the advertised wait",
		"route":               route,
		"retry_after_seconds": secs,
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
	defer func() { _ = upstream.Close() }()

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
	defer func() { _ = client.Close() }()

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
//
// subtle.ConstantTimeCompare([]byte(""), []byte("")) returns 1, so a server
// holding an empty token would AUTHORISE the header "Bearer " and become an
// allowlisted open relay. The credential layer already makes an empty token
// unreachable from configuration — envProvider trims before testing, and
// NewServer refuses a blank one — and the guards below make it unreachable from
// anywhere, so the property still holds if a future credential path regresses.
//
// The two emptiness checks are MUTUALLY REDUNDANT, not two independent
// properties, and the comment says so because a mutation run proved it: with
// one empty side ConstantTimeCompare already returns 0, so each check only ever
// fires when BOTH sides are empty — the case the other one also catches.
// Deleting either alone changes no behaviour; deleting both reopens the bypass.
// They are both kept because the failure is an unauthenticated open relay and
// the cost is two string comparisons, but do not read them as belt and braces
// for different risks.
func (s *Server) authorizeConnect(header string) bool {
	const prefix = "Bearer "
	if s.connToken == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if got == "" {
		return false
	}
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
