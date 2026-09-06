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
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nfsarch33/llm-cluster-router/internal/crypto"
)

// AuditEvent is one NDJSON line describing a proxied request.
//
// It deliberately records no request or response body, no Authorization
// header and no credential material — only the metadata needed to answer
// "did this work, how fast, and through which route".
type AuditEvent struct {
	TS        string `json:"ts"`
	Event     string `json:"event"`
	RequestID string `json:"request_id"`
	Route     string `json:"route,omitempty"`
	AuthMode  string `json:"auth_mode,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Upstream  string `json:"upstream,omitempty"`
	// UpstreamHost is the host:port the gateway ACTUALLY contacted, read back
	// from the request net/http sent, as opposed to Upstream, which is the
	// route's CONFIGURED base URL. They are different SHAPES and so never
	// compare equal -- "http://host:port" against "host:port" -- and with
	// refuseRedirect in force nothing can move a forward off its configured
	// host, so a real divergence is unreachable too. Neither field is an
	// alerting input; recording both makes the log STATE where the gateway went
	// rather than restate configuration.
	//
	// It exists because the pair was previously one field carrying the
	// configured value, which made the audit stream — the record these docs
	// present as the forensic one — incapable of recording an SSRF it had just
	// performed. omitempty, and populated only from a real response, so a line
	// with no response to read (a 502 from a dial failure) is unchanged.
	UpstreamHost string `json:"upstream_host,omitempty"`
	Target       string `json:"target,omitempty"`
	Status       int    `json:"status,omitempty"`
	LatencyMS    int64  `json:"latency_ms"`
	BytesOut     int64  `json:"bytes_out,omitempty"`
	ClientAddr   string `json:"client_addr,omitempty"`
	Error        string `json:"error,omitempty"`

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
	// Tokens is the amount the rotation store was ACTUALLY charged for this
	// request — the upstream's own usage.total_tokens when it reported one,
	// and Budget.EstimateTokens when it did not. Summing this field across the
	// NDJSON stream therefore reconciles to the store's accounting.
	//
	// It once carried the real total only, leaving the estimate path at 0 for
	// omitempty to drop: the stream then under-reported consumption by the
	// whole of every streaming request, which is every request on a header-auth
	// route. A zero really is zero (a failed request, or no estimate
	// configured), so omitempty stays correct.
	Tokens int64 `json:"tokens,omitempty"`
	// TokensEstimated marks a charge derived from Budget.EstimateTokens
	// because the response carried no usage object. It is PROVENANCE for
	// Tokens, not a substitute for it.
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

	// scope is how far the socket this gateway is serving actually reaches,
	// and it is the AUTHORITY for every loopback relaxation on this server.
	// Serve writes it exactly once, from the address the kernel assigned,
	// before a listener is handed to net/http; handlers only read it. It is
	// atomic because Handler may already be mounted elsewhere when Serve runs.
	//
	// Zero value scopeUnknown means no socket was adopted -- Handler was
	// mounted on someone else's server -- and servingScope says what happens
	// then. It never means "loopback".
	scope atomic.Uint32

	// proxyAuth and proxyToken gate the REVERSE-PROXY leg. They are a
	// different credential from connToken above, which gates the CONNECT leg
	// and nothing else; both are written exactly once, by NewServer, and only
	// read thereafter.
	proxyAuth  ProxyAuthMode
	proxyToken string

	// trustForwardedForAudit mirrors Config.TrustForwardedForAudit, copied
	// once by NewServer. Consulted ONLY by auditClientAddr. No admission
	// decision reads this field -- see the config-level doc for why.
	trustForwardedForAudit bool

	// connectLinger is the CONNECT tunnel half-close backstop, written exactly
	// once by NewServer and only read thereafter. See the comment on
	// defaultConnectHalfCloseLinger for what it bounds and why.
	connectLinger time.Duration

	// tunnels is the CONNECT admission semaphore: its capacity is the ceiling
	// on tunnels alive at once, and holding a slot IS the permission to carry
	// one. NewServer sizes it from Connect.MaxConcurrent whenever the leg is
	// enabled; tunnelsOnce covers the one remaining way it can be nil, which
	// is a Server built as a bare struct literal instead of by NewServer.
	//
	// A nil channel is deliberately NOT read as "unbounded": a non-blocking
	// send on nil falls straight through to the refusal branch, so that
	// accident would be a gateway refusing every tunnel, and the accident it
	// replaced was a gateway accepting every tunnel. Neither is a decision, so
	// tunnelSem makes one -- it defaults the semaphore instead.
	tunnels     chan struct{}
	tunnelsOnce sync.Once
}

// serverOptions are the injectable construction dependencies.
type serverOptions struct {
	secrets       SecretProvider
	now           func() time.Time
	observer      RetireObserver
	connectLinger time.Duration
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

// WithConnectHalfCloseLinger overrides how long the surviving direction of a
// CONNECT tunnel may keep copying once the first direction has finished.
//
// It exists so a leak test can assert the bound in milliseconds instead of
// waiting out defaultConnectHalfCloseLinger, and it is deliberately NOT a
// config key: an operator has no reason to tune a backstop whose only job is to
// stop an unresponsive peer parking a goroutine. Values <= 0 keep the default.
func WithConnectHalfCloseLinger(d time.Duration) ServerOption {
	return func(o *serverOptions) { o.connectLinger = d }
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
	linger := o.connectLinger
	if linger <= 0 {
		linger = defaultConnectHalfCloseLinger
	}
	s := &Server{cfg: cfg, forwarder: fwd, audit: audit, allowed: map[string]bool{}, connectLinger: linger}

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
		// A BACKSTOP, not a layer: resolveFirst returns either an error or a
		// value that is already trimmed and non-empty, so no SecretProvider —
		// including a third-party one supplied through WithSecretProvider —
		// can put a blank in front of this line. It cannot be killed by a test
		// on its own; its precondition is pinned by
		// TestResolveFirst_NeverHandsBackAValueThatStillNeedsTrimming, which
		// fails the moment that stops being true.
		//
		// It stays because connToken can never be "" on a running server:
		// an empty token would make ConstantTimeCompare authorise an empty
		// bearer, turning the gateway into an allowlisted open relay.
		// authorizeConnect guards the same fact independently, and that guard
		// IS reachable and IS tested.
		if tok = strings.TrimSpace(tok); tok == "" {
			return nil, fmt.Errorf("connect: %w", ErrSecretEmpty)
		}
		s.connToken = tok
		for _, h := range cfg.Connect.AllowedHosts {
			s.allowed[strings.ToLower(h)] = true
		}
		// Sized HERE, once, from validated configuration -- the same place
		// and the same moment as the credential that gates the leg. A
		// semaphore allocated lazily on the request path would be a second
		// answer to "how many tunnels may this gateway carry", arrived at by
		// whichever request got there first.
		s.tunnels = make(chan struct{}, connectMaxConcurrent(cfg))
	}

	// The gateway token resolves through the SAME SecretProvider as every route
	// credential and the CONNECT token, so an operator names it the same way
	// and a vault item shared with a route is fetched once. Eagerly, like the
	// rest: a gateway that cannot read its own admission credential must fail
	// at startup rather than answer 401 to every caller once traffic arrives.
	s.proxyAuth = cfg.GatewayAuth.Mode()
	if cfg.GatewayAuth.hasToken() {
		tok, err := resolveFirst(sp, secretRefs(cfg.GatewayAuth.TokenRef, cfg.GatewayAuth.TokenEnv, cfg.GatewayAuth.TokenFile))
		if err != nil {
			return nil, fmt.Errorf("gateway_auth: %w", err)
		}
		// Unconditional, and stated plainly because the whitespace-credential
		// class has now cost this codebase twice: a token mode whose token is
		// blank would reach ConstantTimeCompare("", "") == 1 and authorise an
		// empty header. resolveFirst already refuses a blank, so this is a
		// second refusal of the same fact rather than an independent property —
		// but the failure it prevents is an unauthenticated funded relay, and
		// the cost is one comparison.
		if tok = strings.TrimSpace(tok); tok == "" {
			return nil, fmt.Errorf("gateway_auth: %w", ErrSecretEmpty)
		}
		// The two tokens must be DIFFERENT secrets. Pointing both at one source
		// is the exact overload the split exists to prevent: it would silently
		// grant every holder of a tunnel credential the ability to spend every
		// key on every route, and vice versa. Refusing at startup is the only
		// moment anyone would notice.
		if s.connToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.connToken)) == 1 {
			return nil, fmt.Errorf("gateway_auth: the gateway token and the connect token resolve to the same secret; they gate different powers (spending every route key vs opening an allowlisted tunnel) and must be distinct")
		}
		s.proxyToken = tok
	}
	s.trustForwardedForAudit = cfg.TrustForwardedForAudit
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

// ProxyAuthMode reports the caller-authentication posture of the reverse-proxy
// leg, so the startup banner and /healthz state the same fact the request path
// enforces instead of each restating the configuration for itself.
func (s *Server) ProxyAuthMode() ProxyAuthMode { return s.proxyAuth }

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
// The inventory half is gated by EXACTLY the decision that gates the proxy leg
// itself, not by a second rule of its own. A caller that may spend every key on
// the route learns nothing new from being told how many there are; a caller that
// may not should not be handed the route table, the auth mode of each route and
// a live per-route count of how many plans are still selectable, which together
// are a reconnaissance surface and an oracle for correlating which account
// served which request.
//
// Liveness stays anonymous and stays 200 in every mode. A probe that answers 401
// is a probe an orchestrator reads as "down", which would turn this change into
// an outage on every deployment with a health check in front of it — and the
// status field is the one part of this response that was never sensitive.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"status":     "ok",
		"service":    "helixchannel-gateway",
		"proxy_auth": string(s.proxyAuth),
	}
	if s.authorizeProxy(r) == proxyAuthOK {
		body["routes"] = s.RouteNames()
		body["keys"] = s.KeyInventory()
		body["connect"] = s.cfg.Connect.Enabled
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.NewString()

	// Caller authentication is the FIRST thing that happens: before the route
	// match, before any lease, before any upstream contact. Until this existed,
	// an anonymous POST to an enabled prefix reached the provider with the
	// server-held key injected, and the only thing standing between a listening
	// socket and a funded relay was where that socket was bound.
	//
	// It also runs before s.match because writeNotFound's 404 body lists every
	// enabled route name: matching first would disclose the route table to a
	// caller not allowed to use any of it.
	if refusal := s.authorizeProxy(r); refusal != proxyAuthOK {
		s.denyUnauthenticated(w, r, requestID, start, refusal)
		return
	}
	// The gateway token authenticates THIS hop and has no meaning upstream, so
	// it is removed on every mode — including passthrough, which is exempt from
	// the forwarder's caller-credential strip by design and would otherwise
	// hand the gateway's own admission credential to the provider.
	r.Header.Del(GatewayTokenHeader)

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
		auth, l, refusal := kl.leaseFor()
		if refusal != refusalNone {
			s.denyUnavailable(w, rt, r, requestID, start, refusal, kl)
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
			LatencyMS: time.Since(start).Milliseconds(), ClientAddr: s.auditClientAddr(r),
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
		Upstream: rt.Route.Upstream, UpstreamHost: contactedHost(resp),
		Status:    resp.StatusCode,
		LatencyMS: time.Since(start).Milliseconds(), BytesOut: n,
		ClientAddr: s.auditClientAddr(r),
	}
	// A redirect the gateway declined to follow is a distinct outcome, not a
	// plain 3xx relay: the upstream asked for a credential to be replayed
	// somewhere and was refused. Naming it here is what makes the refusal
	// countable in the NDJSON instead of merely absent from it.
	if redirectNotFollowed(resp) {
		event.Error = "redirect_not_followed"
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
	sample := chargeableSample(status, usage.Result())
	if kl, ok := rt.Auth.(keyLeaser); ok {
		// The vendor's own code is MORE SPECIFIC than the HTTP status and wins
		// where both are present. MiniMax-family upstreams report the real
		// reason in the body, often alongside HTTP 200, and the three failures
		// that arrive as one 429 need opposite handling: a burst limit clears
		// in seconds, a plan cap holds for the window, and a balance signal
		// needs a human. A vendor code that says the KEY is healthy (auth or
		// malformed-request) suppresses the status-based retire entirely,
		// because retiring there would drain a funded pool over a caller bug.
		if sig, found := vendorSignalFrom(usage); found {
			if sig.Retires() {
				// Deliberately NOT kl.retire() for a quota signal. That path
				// parks until the end of the route's ACCOUNTING window, which
				// is this gateway's own spend bound (5m on the public edge) and
				// has nothing to do with the provider's plan window. A 2056
				// parked for 5 minutes returns, draws 2056 again, and walks the
				// pool -- the exact under-punishment this classifier removes.
				// vendorRetireUntil answers on the PROVIDER's clock: its own
				// reset time when it named one, else the documented window.
				kl.retireUntil(lease.Index(),
					vendorRetireUntil(sig, time.Now(), time.Time{}), sig.Reason())
			}
		} else if isQuotaStatus(status) {
			kl.retire(lease.Index(), ReasonQuota)
		}
	}
	lease.Settle(sample)

	// A fresh local, addressed once: sharing a field here would let a later
	// request mutate a value this line has not yet marshalled.
	idx := lease.Index()
	event.KeyIndex = &idx
	event.Tokens = chargedTokensFor(rt.Route, sample)
	event.TokensEstimated = sample.Estimated
}

// chargeableSample decides what an upstream response may be charged for, from
// its status. The extracted usage alone cannot answer that: "no usage object"
// looks identical on a completed stream and on an upstream that fell over.
//
// The policy, stated explicitly because the two halves differ ON PURPOSE:
//
//	5xx  the upstream did NOT serve the request. OutcomeFailed: the lease is
//	     released, Errors is incremented, and NOTHING is charged. Charging the
//	     streaming estimate here is how a transient upstream outage became a
//	     self-inflicted multi-hour quota outage — four 500s carrying zero real
//	     tokens drained two whole plans and the route then answered 503 with a
//	     one-hour Retry-After, labelled reason=cap, having spent nothing.
//	4xx  the upstream DID serve the request and refused it. That consumed
//	     upstream work and counts against a request plan, so it settles as a
//	     completed request — but a refusal generates no completion, so it is
//	     charged only the tokens the upstream actually reported, never the
//	     streaming estimate. (429 and 402 additionally retire the key; see
//	     isQuotaStatus.)
//	3xx  no completion was generated either. Same treatment as 4xx.
//	2xx  unchanged: the real total when the response reported one, and
//	     Budget.EstimateTokens when it did not, which is the whole reason
//	     TokensUnknown is not zero.
//
// A 5xx that somehow DID report usage is still treated as a failure: a response
// this gateway could not deliver as a success is not evidence of spend.
func chargeableSample(status int, sample UsageSample) UsageSample {
	switch {
	case status >= 500:
		return UsageSample{Outcome: OutcomeFailed}
	case status >= 300 && sample.Tokens == TokensUnknown:
		// A real, trustworthy zero — NOT TokensUnknown, which would be charged
		// the estimate downstream.
		return UsageSample{Outcome: OutcomeCompleted, Tokens: 0}
	default:
		return sample
	}
}

// chargedTokensFor is the figure the store ACTUALLY charged for this sample, so
// the audit stream reconciles to the accounting rather than merely hinting at
// it.
//
// The estimate path used to leave Tokens at 0, which omitempty then dropped
// entirely: only tokens_estimated:true survived, and anyone summing the NDJSON
// under-reported consumption by the whole of every streaming request.
// tokens_estimated says HOW the figure was arrived at; it is not a substitute
// for the figure.
//
// The estimate is read back from the route's own configuration because that is
// exactly what its Store was built with (newRotationStore passes
// Rotation.Budget straight through), and Settle deliberately returns nothing —
// a lease that reported its charge back would be a second, drifting copy of
// state the store already owns.
func chargedTokensFor(r Route, sample UsageSample) int64 {
	switch {
	case sample.Outcome == OutcomeFailed:
		return 0
	case sample.Tokens != TokensUnknown:
		return sample.Tokens
	case r.Rotation == nil:
		return 0
	default:
		return r.Rotation.Budget.EstimateTokens
	}
}

// isQuotaStatus reports whether an upstream status means "this key's plan is
// spent" rather than "this upstream is broken".
//
// 402 is included alongside 429 because header-auth providers (the Exa/Tavily
// class) commonly signal an exhausted plan with Payment Required. Treating that
// as a generic upstream error would keep re-selecting the dead key until the
// window rolled.
// vendorSignalFrom asks an extractor for a vendor error code, when it can
// answer. A nil or non-signalling extractor yields no signal, which leaves the
// previous HTTP-status-only behaviour untouched.
func vendorSignalFrom(ue UsageExtractor) (VendorSignal, bool) {
	vs, ok := ue.(VendorSignaler)
	if !ok || vs == nil {
		return VendorSignal{}, false
	}
	return vs.VendorSignal()
}

func isQuotaStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusPaymentRequired
}

// denyUnavailable answers a request refused BEFORE any upstream call. It is the
// only place the reasons for that are turned into a response, so the body, the
// Retry-After, the audit line and the metric cannot drift apart.
func (s *Server) denyUnavailable(w http.ResponseWriter, rt *boundRoute, r *http.Request, requestID string, start time.Time, refusal admissionRefusal, kl keyLeaser) {
	code, hint, wait := refusalAnswerFor(refusal, kl)
	AdmissionRefusedTotal.WithLabelValues(rt.Route.Name, code).Inc()
	s.writeUnavailable(w, rt.Route.Name, code, hint, wait)
	s.audit.Log(AuditEvent{
		Event: "proxy_request", RequestID: requestID, Route: rt.Route.Name,
		AuthMode: string(rt.Auth.Mode()), Method: r.Method, Path: r.URL.Path,
		Upstream: rt.Route.Upstream, Status: http.StatusServiceUnavailable,
		LatencyMS: time.Since(start).Milliseconds(), ClientAddr: s.auditClientAddr(r),
		Error: code,
	})
}

// refusalAnswerFor maps a refusal to the error code, hint and wait a caller
// receives. The three move together on purpose: a code without a matching wait
// is how a client learns to ignore Retry-After.
//
// The two answers are DIFFERENT FACTS and the split is the whole of this fix:
//
//	keys_exhausted    no key is selectable. Every plan is spent or every key is
//	                  in an upstream cooldown. The wait is a time this store can
//	                  name — until a window rolls or a retirement expires — so
//	                  Retry-After is that wait. Page on it: it is a billing
//	                  question and the traffic is not being served.
//	admission_limited at least one key is healthy and selectable; every one of
//	                  them is at its hard cap only once the leases already in
//	                  flight are counted. Nothing is retired, nothing is drained,
//	                  and /healthz correctly reports the route undegraded. It
//	                  clears when an outstanding lease settles, which is not a
//	                  time anything here can name, so Retry-After is the floor:
//	                  come back immediately, not after the window. Do not page:
//	                  it means the route is being offered more concurrency than
//	                  its per-window plan allows.
//
// Reporting the second as the first is what sent an operator hunting a billing
// problem that did not exist, against a route reporting {keys: 2, available: 2,
// degraded: false} with every key Selectable and none Drained.
//
// kl is consulted ONLY on the drained path. An admission refusal deliberately
// does not ask the store for a wait: Store.RetryAfter answers "no wait" whenever
// any key is selectable, which is always true here, so the floor would be
// arrived at by accident rather than by decision.
func refusalAnswerFor(refusal admissionRefusal, kl keyLeaser) (code, hint string, wait time.Duration) {
	if refusal == refusalAdmission {
		return "admission_limited",
			"every upstream key on this route is at its per-window cap once the requests already in flight are counted; none has been retired and none is drained, so retry immediately rather than after a window",
			MinRetryAfter
	}
	return "keys_exhausted",
		"every upstream key on this route is retired or drained; retry after the advertised wait",
		kl.retryAfter()
}

// writeUnavailable writes a pre-dispatch refusal: 503 with Retry-After, NOT 502.
//
// An operator paging on 502 is hunting a broken upstream; a route that refused
// before dispatch has no broken upstream to find — it may have no upstream
// contact at all. Collapsing the two is how a quota outage gets triaged as an
// outage. The body names the route, the reason and the wait, and carries no
// credential material.
//
// The reason is a parameter rather than a constant for the same argument one
// level down: "refused before dispatch" is not one fact, and a single body that
// asserted "every upstream key on this route is retired or drained" for both of
// them was wrong for one of them on every request it answered.
func (s *Server) writeUnavailable(w http.ResponseWriter, route, code, hint string, retryAfter time.Duration) {
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
		"error":               code,
		"hint":                hint,
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

// defaultConnectHalfCloseLinger bounds how long the surviving direction of a
// CONNECT tunnel may keep copying after the FIRST direction has finished. It is
// the backstop for a peer that is sent a FIN and then neither writes nor closes.
const defaultConnectHalfCloseLinger = 30 * time.Second

// connectCopyBufferSize is the per-direction copy buffer, and it is the same
// 32KiB io.Copy used to allocate here, so the per-tunnel memory an operator
// budgets is unchanged. What changed is the multiplier: the number of tunnels
// is now Connect.MaxConcurrent rather than whatever the network offers.
const connectCopyBufferSize = 32 << 10

// connectRouteLabel is the route name the CONNECT leg reports in a 503 body, in
// its audit line and on AdmissionRefusedTotal. The leg has no configured route
// to name, and the alternative -- naming the TARGET -- would put a caller
// controlled string into a metric label and mint a new series per host.
const connectRouteLabel = "connect"

// connectMaxConcurrent is the tunnel ceiling for cfg, defaulted.
//
// validateConnect has normally applied the default already, so this repeats it
// only for a Config that never went through Validate -- a test fixture, or an
// embedder that built one in code. Keeping the fallback in ONE place is what
// stops the semaphore and the config key disagreeing about what "unset" means.
func connectMaxConcurrent(cfg *Config) int {
	if n := cfg.Connect.MaxConcurrent; n > 0 {
		return n
	}
	return DefaultConnectMaxConcurrent
}

// tunnelSem returns the CONNECT admission semaphore, defaulting it for a Server
// that was built as a bare struct literal. See Server.tunnels for why nil is
// not allowed to mean either bound.
func (s *Server) tunnelSem() chan struct{} {
	s.tunnelsOnce.Do(func() {
		if s.tunnels == nil {
			s.tunnels = make(chan struct{}, connectMaxConcurrent(s.cfg))
		}
	})
	return s.tunnels
}

// acquireTunnel takes a tunnel slot WITHOUT waiting and reports whether it got
// one. releaseTunnel gives the slot back.
//
// The non-blocking form is the decision, not an optimisation: a blocking
// acquire would convert an over-capacity gateway into an unbounded queue of
// parked handler goroutines, which is one of the three resources this bound
// exists to cap, reached by a different route.
func (s *Server) acquireTunnel() bool {
	select {
	case s.tunnelSem() <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseTunnel() { <-s.tunnelSem() }

// closeWriter is the half-close capability of a connection, stated as a
// BEHAVIOUR so that no concrete conn type has to be enumerated.
//
// The CONNECT tunnel used to assert client.(*net.TCPConn), and that assertion
// is FALSE on the deployment that matters. When tls.cert_file/key_file are set,
// Serve hands the listener to http.Server.ServeTLS, so the conn returned by
// Hijack is a *tls.Conn: ok came back false, CloseWrite was never called, the
// client was never sent a FIN after the upstream half-closed, and the opposite
// io.Copy blocked forever on an idle client -- taking wg.Wait, the handler
// goroutine and both deferred Closes down with it. The upstream side of the
// same pair worked only by luck, because net.DialTimeout really does hand back
// a *net.TCPConn.
//
// *net.TCPConn, *tls.Conn and *net.UnixConn all implement CloseWrite, so asking
// for the method covers every posture this gateway can serve in today and does
// not silently regress the next time a conn arrives wrapped in something else.
type closeWriter interface{ CloseWrite() error }

// tunnelDeadlines is the SINGLE writer of both conns deadlines for one CONNECT
// tunnel. It is a type rather than two closures because the two bounds it
// applies are armed from different goroutines and would otherwise fight.
//
// The two bounds:
//
//   - IDLE. Before every Read, the reading direction re-arms that conn read
//     deadline to now+idle. A tunnel that is established and then goes silent
//     -- the cheapest way there is to hold a socket, two goroutines and 64KiB
//     of this gateway indefinitely -- unblocks and unwinds instead.
//     ReadHeaderTimeout stops applying the instant the conn is hijacked, so
//     before this there was no deadline of any kind on an established tunnel.
//
//   - LINGER. Once the FIRST direction finishes, arm puts a hard deadline on
//     BOTH conns. That is the half-close backstop, and it is a DEADLINE rather
//     than a Close because closing both the moment one direction ends
//     truncates the ordinary half-close -- client done sending, upstream still
//     streaming -- turning a goroutine leak into silent data loss.
//
// EITHER ONE MAY ONLY EVER TIGHTEN THE OTHER, and both directions of that rule
// had to be written down because both are reachable and each was wrong once:
//
//   - A refresh landing just after arm would push the read deadline back out
//     past the linger bound, and the surviving direction would then sit for a
//     whole idle period on a peer that has already been told to go away. Every
//     refresh is therefore CLAMPED to the linger deadline once armed.
//   - arm setting the linger deadline unconditionally EXTENDS a conn whose
//     idle deadline is already sooner, which is what happens on any gateway
//     configured with idle < linger. The direction that times out first arms,
//     and its arming hands the other direction a fresh linger-long lease on
//     the very deadline that was about to reap it. arm therefore keeps
//     whichever of the two is EARLIER, per conn.
//
// Both operations run under one mutex, so no refresh can interleave with an
// arm. The mutex is held across two setsockopt-class calls and never across a
// Read.
type tunnelDeadlines struct {
	mu       sync.Mutex
	client   net.Conn
	upstream net.Conn
	idle     time.Duration
	linger   time.Duration
	armed    bool
	lingerAt time.Time

	// clientIdleAt and upstreamIdleAt are the idle deadlines currently in
	// force, remembered so arm can tighten to them rather than over them.
	clientIdleAt   time.Time
	upstreamIdleAt time.Time
}

// refreshIdle re-arms src read deadline, clamped to the linger deadline.
func (d *tunnelDeadlines) refreshIdle(src net.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	at := time.Now().Add(d.idle)
	if d.armed && d.lingerAt.Before(at) {
		at = d.lingerAt
	}
	// Dispatched on conn identity because each direction refreshes only the
	// conn it READS, and arm needs to know which recorded deadline belongs to
	// which conn. The two are distinct sockets, so the comparison is exact.
	if src == d.client {
		d.clientIdleAt = at
	} else {
		d.upstreamIdleAt = at
	}
	_ = src.SetReadDeadline(at)
}

// arm applies the half-close linger bound to both conns, once.
//
// SetDeadline reaches a Read that is ALREADY blocked, and that is the whole
// mechanism: the surviving direction is parked in Read at this moment, and
// this is what will eventually return it.
func (d *tunnelDeadlines) arm() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.armed {
		return
	}
	d.armed = true
	d.lingerAt = time.Now().Add(d.linger)
	d.tightenLocked(d.client, d.clientIdleAt)
	d.tightenLocked(d.upstream, d.upstreamIdleAt)
}

// tightenLocked sets c deadline to the EARLIER of the linger bound and the idle
// deadline already in force on it, so arming can only ever shorten a tunnel.
func (d *tunnelDeadlines) tightenLocked(c net.Conn, idleAt time.Time) {
	at := d.lingerAt
	if !idleAt.IsZero() && idleAt.Before(at) {
		at = idleAt
	}
	_ = c.SetDeadline(at)
}

// copyTunnelHalf copies src into dst until src stops producing, refreshing the
// idle deadline before every Read, and returns the number of bytes written.
//
// It is a hand-rolled loop and not io.Copy because io.Copy offers no point at
// which to re-arm a deadline: the read that has to be bounded happens inside
// it. The cost is io.Copy ReadFrom/splice fast path -- which this leg never
// had on the posture that matters anyway, since a TLS-terminating gateway
// hands one end of every pair to crypto/tls and splice needs both ends to be
// kernel sockets.
//
// Errors are dropped for the same reason the io.Copy calls dropped them: every
// outcome here -- clean EOF, reset peer, idle deadline, linger deadline --
// ends this direction, and the audit line already records the tunnel closing.
func copyTunnelHalf(dst io.Writer, src net.Conn, d *tunnelDeadlines) int64 {
	buf := make([]byte, connectCopyBufferSize)
	var total int64
	for {
		d.refreshIdle(src)
		n, rerr := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total
			}
		}
		if rerr != nil {
			return total
		}
	}
}

// handleConnect serves the CONNECT tunnel leg.
//
// The gateway authenticates the client with a shared token, checks the target
// against an exact-match allowlist, then copies bytes in both directions. It
// never terminates the inner TLS session, so the client own credential
// (for example an OAuth session token) is never visible to the gateway or to
// any intermediate hop — which is the entire point of routing an agent whose
// auth cannot be injected server-side.
//
// ADMISSION IS THE BUFFERED-CHANNEL SEMAPHORE, PATTERN (a), ACQUIRED
// NON-BLOCKINGLY. Stated here because the alternatives are all reachable from
// this spot and each is wrong in its own specific way:
//
//   - A BLOCKING acquire (same channel, no default branch) turns the overflow
//     into a queue of parked handler goroutines. Goroutines are one of the
//     three resources being bounded, so that would cap the sockets and the
//     buffers by uncapping the thing they are counted alongside.
//   - A WaitGroup or errgroup limit is a different shape entirely: those join
//     work the SERVER started, and this is work an untrusted CALLER starts.
//     There is nothing to wait for here and no result to collect.
//   - A rate limiter (tokens per second) bounds ARRIVALS. The resource here is
//     held for the whole life of the tunnel, so arrivals are not what runs the
//     gateway out of file descriptors; concurrency is.
//
// The acquire sits immediately after the allowlist check and BEFORE the dial,
// so a full gateway stops dialling outbound rather than dialling and then
// discovering it has nowhere to put the result. That ordering is what keeps a
// saturated gateway from being an amplifier. The release is a defer, so it
// covers every path out of the handler including the ones that return before
// wg.Wait -- a failed hijack, a peer that hangs up on the 200.
//
// The refusal is 503 + Retry-After, matching the reverse-proxy leg pre-dispatch
// refusals rather than a 429: nothing about the caller RATE is being judged,
// the gateway is simply full. It is emitted before a single outbound packet, so
// a client retrying into a full gateway costs it one HTTP response.
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
			ClientAddr: s.auditClientAddr(r), Error: reason,
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

	if !s.acquireTunnel() {
		AdmissionRefusedTotal.WithLabelValues(connectRouteLabel, "tunnels_at_capacity").Inc()
		s.writeUnavailable(w, connectRouteLabel, "tunnels_at_capacity",
			"the gateway is already carrying connect.max_concurrent tunnels; no upstream was dialled, and a slot frees the moment any tunnel finishes, so retry shortly rather than after a quota window",
			MinRetryAfter)
		s.audit.Log(AuditEvent{
			Event: "connect_denied", RequestID: requestID, Target: target,
			Status: http.StatusServiceUnavailable, LatencyMS: time.Since(start).Milliseconds(),
			ClientAddr: s.auditClientAddr(r), Error: "tunnels_at_capacity",
		})
		return
	}
	defer s.releaseTunnel()

	upstream, err := net.DialTimeout("tcp", target, s.cfg.Connect.DialTimeout)
	if err != nil {
		deny(http.StatusBadGateway, "dial_failed")
		return
	}
	defer func() { _ = upstream.Close() }()

	// SECOND layer, after the dial and before a single byte moves: refuse a
	// target that turned out to be this machine. Config validation refuses the
	// spellings it can decide without a resolver; this refuses what only the
	// opened socket can show — an allowlisted NAME whose address is loopback,
	// or an answer that changed after startup. Without it the gateway can be
	// made to dial itself, and the tunnelled request arrives as a LOCAL caller
	// holding the gateway_auth loopback exemption.
	// The scope comes from a SOCKET, never from s.cfg.Listen. A config string
	// has to be predicted, and three rounds of this defect were three strings
	// this package predicted one way and net.Listen resolved another.
	if reason := connectDialRefusal(s.servingScope(r), upstream.LocalAddr(), upstream.RemoteAddr()); reason != "" {
		deny(http.StatusForbidden, reason)
		return
	}

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
		ClientAddr: s.auditClientAddr(r),
	})

	// Both directions are copied concurrently, and BOTH are bounded three ways.
	//
	// FIRST bound -- the FIN actually reaches the peer. When a direction runs
	// out of bytes the other side is told so with CloseWrite, asked for as a
	// BEHAVIOUR (closeWriter) rather than as *net.TCPConn. See closeWriter for
	// the defect that replaces: the concrete-type assertion was false on a
	// TLS-terminating gateway, which is the only posture a reachable gateway
	// may run in, so the half-close was silently skipped exactly where it
	// mattered and every affected tunnel parked this handler forever.
	//
	// SECOND bound -- a peer that ignores the FIN still cannot park us. The
	// moment the FIRST direction finishes, a linger deadline is armed on BOTH
	// conns; the surviving copy then unblocks instead of waiting on a socket
	// nobody will ever write to or close again. CloseWrite asks a peer to stop
	// and nothing makes a peer listen, so the half-close fix alone is a
	// courtesy, not a bound.
	//
	// THIRD bound -- a tunnel that never half-closes at all. Neither of the
	// above fires while both peers simply hold the socket open and say nothing,
	// which is the cheapest possible way to occupy this gateway, and it is what
	// made an established tunnel an unbounded hold. The idle deadline refreshed
	// before every Read is what reaps that one.
	//
	// See tunnelDeadlines for how the second and third are kept from fighting,
	// and for why the linger is a deadline rather than a Close.
	linger := s.connectLinger
	if linger <= 0 {
		// A Server built as a bare struct literal (some tests do that) never
		// ran the defaulting in NewServer, and a zero here would mean a
		// deadline in the past: it would kill the tunnel on the spot rather
		// than bound it.
		linger = defaultConnectHalfCloseLinger
	}
	idle := s.cfg.Connect.IdleTimeout
	if idle <= 0 {
		idle = DefaultConnectIdleTimeout
	}
	dl := &tunnelDeadlines{client: client, upstream: upstream, idle: idle, linger: linger}

	var wg sync.WaitGroup
	wg.Add(2)
	var bytesUp int64
	go func() {
		defer wg.Done()
		bytesUp = copyTunnelHalf(upstream, client, dl)
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		dl.arm()
	}()
	go func() {
		defer wg.Done()
		_ = copyTunnelHalf(client, upstream, dl)
		if cw, ok := client.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		dl.arm()
	}()
	wg.Wait()

	s.audit.Log(AuditEvent{
		Event: "connect_closed", RequestID: requestID, Target: target,
		LatencyMS: time.Since(start).Milliseconds(), BytesOut: bytesUp,
		ClientAddr: s.auditClientAddr(r),
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

// servingScope is how far the socket carrying r reaches, and it is the single
// authority every loopback relaxation on the request path reads.
//
// Both branches answer from a kernel-assigned address. Neither parses
// Config.Listen, and that is deliberate rather than incidental: predicting what
// net.Listen will do with a config string is what produced this defect three
// times running, once per new spelling nobody had enumerated.
//
//   - Serve adopted a listener, so the whole server's reach is known and is
//     the answer for every request on it.
//   - Nothing was adopted -- Handler was mounted on someone else's
//     http.Server (httptest, an embedder, a socket-activation wrapper) -- so
//     the fallback is the address THIS connection was accepted on, which
//     net/http carries in the request context. It is a real socket address
//     too, just a narrower one, and it is sound for the question being asked:
//     a connection accepted ON 127.0.0.1 has a peer that is necessarily on
//     this machine, so there is no remote caller to launder whatever the
//     listener's own address happens to be.
//   - Neither available: scopeReachable. Undecidable is not loopback.
func (s *Server) servingScope(r *http.Request) listenScope {
	if sc := listenScope(s.scope.Load()); sc != scopeUnknown {
		return sc
	}
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return boundListenScope(addr)
	}
	return scopeReachable
}

// bindRefusal reports why this server must NOT serve on the socket it just
// opened, or "" when it may.
//
// It is the post-bind half of two rules Config.Validate also states, and it is
// the half that decides. Validate ran before a socket existed, so all it could
// do was predict what net.Listen would make of Config.Listen; here the kernel
// has already answered. Where the two disagree, this one wins, because a
// relaxation granted on a prediction is a relaxation granted on whatever the
// platform resolver felt like saying.
//
// The two rules, both of which are relaxations that loopback-ness would grant:
//
//   - A tokenless posture (proxy_auth loopback_only: no gateway token, no
//     written-down allow_unauthenticated) authenticates NOBODY, so it is
//     permissible only while the socket cannot be reached from another host.
//   - connect.allowed_hosts entries that name this machine are permitted only
//     on a loopback-only socket, where every CONNECT client is already a local
//     process and a tunnel to a local service grants it nothing.
//
// The third relaxation, the dial-time CONNECT guard, needs no refusal here: it
// simply stays ARMED, because servingScope reads the same scope.
func (s *Server) bindRefusal(addr net.Addr, scope listenScope) string {
	if scope == scopeLoopbackOnly {
		return ""
	}
	bound := addr.String()
	if s.proxyAuth == ProxyAuthLoopbackOnly {
		return fmt.Sprintf("gateway_auth: this gateway bound %s, which is reachable from other hosts, and no gateway token is configured; the reverse-proxy leg would authenticate nobody while reachable, so anyone able to open a TCP connection could spend every key on every enabled route. The bind address is decided here from the socket the kernel actually opened, not from listen %q, because that string is only a prediction of what net.Listen will do with it. Set gateway_auth.token_env/token_file/token_ref, bind a loopback address, or -- only behind an authenticating terminator -- set gateway_auth.allow_unauthenticated: true", bound, s.cfg.Listen)
	}
	if !s.cfg.Connect.Enabled {
		return ""
	}
	for _, h := range s.cfg.Connect.AllowedHosts {
		host, port, err := net.SplitHostPort(h)
		if err != nil {
			// Validate already refuses a malformed entry, and a Config built
			// in memory that skipped it has no allowlist worth checking.
			continue
		}
		if why := connectSelfReference(host, port, bound, false); why != "" {
			return fmt.Sprintf("connect: allowed_hosts entry %q %s. This gateway bound %s, which is reachable from other hosts, whatever listen %q predicted. Remove the entry, or run the service it names on a different host", h, why, bound, s.cfg.Listen)
		}
	}
	return ""
}

// ListenAndServe binds Config.Listen and runs the gateway until ctx is
// cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// ServeWrapped runs the AES-256-GCM leg on an already-bound listener: it wraps
// ln so every accepted connection is AES-decrypted before net/http sees it, and
// serves the SAME handler — routes and gateway_auth — as the reverse-proxy leg.
// The caller supplies ln already carrying the outer transport; in production
// that is a tls.Listener, so the on-wire stack is TCP → TLS → AES → HTTP, with
// AES nested inside TLS.
//
// The AES leg is not a second trust boundary. gateway_auth is enforced by the
// shared handler exactly as on the reverse-proxy leg, and this method applies
// the SAME tokenless-relay bind refusal as Serve — judged from the socket ln
// actually bound, not from a config string — so a public AES bind with no token
// configured is refused rather than served as an open relay. ln is closed on
// refusal, mirroring Serve.
func (s *Server) ServeWrapped(ctx context.Context, ln net.Listener, key [32]byte) error {
	scope := boundListenScope(ln.Addr())
	if why := s.bindRefusal(ln.Addr(), scope); why != "" {
		_ = ln.Close()
		return errors.New(why)
	}
	wrapped := crypto.WrapListener(ln, key)
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(wrapped)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		return shutdownHTTPServer(srv, errCh)
	case err := <-errCh:
		return err
	}
}

// Serve runs the gateway on an already-bound listener until ctx is cancelled,
// and takes ownership of ln: it is closed on refusal and by Shutdown otherwise.
//
// The ORDER here is the security property, not an implementation detail. ln is
// already bound, so ln.Addr() is the address the kernel actually gave us --
// spelling-independent and resolver-independent. That address is adopted as
// this server's authoritative scope, the tokenless posture is judged against
// it, and only if it survives does a listener reach net/http. A refusal closes
// ln without ever calling Accept, so a connection already sitting in the
// backlog is reset rather than answered: not one request is served in the
// window between binding and refusing.
//
// Doing it the other way round -- serve, then check -- would have been the same
// defect in a new place. The point of deciding from the socket is lost if the
// socket is serving by the time the decision is made.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	scope := boundListenScope(ln.Addr())
	s.scope.Store(uint32(scope))
	if why := s.bindRefusal(ln.Addr(), scope); why != "" {
		_ = ln.Close()
		return errors.New(why)
	}
	s.httpSrv = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.cfg.TLS.Enabled() {
			err = s.httpSrv.ServeTLS(ln, s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		} else {
			err = s.httpSrv.Serve(ln)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		return shutdownHTTPServer(s.httpSrv, errCh)
	case err := <-errCh:
		return err
	}
}
