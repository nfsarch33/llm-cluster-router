package channel

import (
	"fmt"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// RetireReason labels why a key stopped being selectable. It is the "reason"
// label on llm_cluster_router_helixchannel_key_retired_total.
type RetireReason string

const (
	// ReasonCap is a planned retirement from this gateway's own accounting:
	// the soft cap (80% of budget by default) or the hard cap (100%).
	ReasonCap RetireReason = "cap"
	// ReasonQuota is an upstream quota signal — an HTTP 429 or a provider
	// quota-exhausted body. It is the reason recorded by RotationStore.Retire.
	ReasonQuota RetireReason = "quota"
	// ReasonError is repeated upstream failure that is not a quota signal.
	ReasonError RetireReason = "error"
)

// TokensUnknown is the RecordUsage token value meaning "the upstream reported
// no token count".
//
// It is deliberately NOT zero: zero is a real, trustworthy count of zero
// tokens, and conflating the two is exactly how an all-streaming route would
// under-charge its budget forever and never rotate.
const TokensUnknown int64 = -1

// SampleOutcome distinguishes a request that reached the upstream from one
// that failed before producing any usage.
type SampleOutcome uint8

const (
	// OutcomeCompleted is a request that received a response.
	OutcomeCompleted SampleOutcome = iota
	// OutcomeFailed is a request that produced no usage (dial error, timeout,
	// client disconnect). It releases the lease and increments Errors but
	// charges no requests and no tokens, so a dead upstream cannot make a
	// healthy key look like the most-used one.
	OutcomeFailed
)

// UsageSample is one settled request's contribution to a key's window.
type UsageSample struct {
	// Outcome is how the request ended.
	Outcome SampleOutcome
	// Tokens is the upstream-reported total, or TokensUnknown when the
	// response carried no usage object.
	Tokens int64
	// Estimated is set during normalisation when Tokens is TokensUnknown. It
	// is a field rather than a derived value so a test can assert the
	// normalisation directly.
	Estimated bool
}

// RotationStore selects and accounts for keys on a route.
//
// This is the narrow seam a replacement implementation must satisfy. The
// concrete Store also implements RetryAfterReporter, ReasonedRetirer and
// SampleRecorder; callers type-assert for those and degrade to documented
// defaults when absent, so new capability arrives as a new optional interface
// rather than a breaking change to this one (OCP).
type RotationStore interface {
	// Next reserves and returns the index of the key to use for the next
	// request on route, or -1 when every key is retired or drained.
	//
	// A non-negative result RESERVES an in-flight slot. The caller MUST settle
	// it with exactly one RecordUsage (or RecordSample) call, or the key looks
	// permanently busy to leastUsedPolicy. Prefer Store.Acquire, whose lease
	// makes both double-settlement and non-settlement impossible.
	Next(route string) (idx int)

	// RecordUsage settles a reservation as a completed request: it releases
	// the in-flight slot, increments the request counter and charges tokens.
	// Pass TokensUnknown when the upstream reported none. Unknown routes and
	// out-of-range indices are no-ops.
	RecordUsage(route string, idx int, tokens int64)

	// Retire makes a key unselectable until the given time, recording reason
	// ReasonQuota. A time at or before now is a no-op and never an
	// un-retirement.
	Retire(route string, idx int, until time.Time)
}

// RetryAfterReporter answers "how long until this route can serve again", so
// a gateway can put a truthful Retry-After on its 503.
type RetryAfterReporter interface {
	// RetryAfter returns the wait until the earliest key becomes selectable.
	// ok is false when a key is selectable right now.
	RetryAfter(route string) (d time.Duration, ok bool)
}

// ReasonedRetirer retires a key with an explicit metric reason.
type ReasonedRetirer interface {
	RetireWithReason(route string, idx int, until time.Time, reason RetireReason)
}

// SampleRecorder settles a reservation with the full sample, including the
// failure outcome that RecordUsage's bare token count cannot express.
type SampleRecorder interface {
	RecordSample(route string, idx int, s UsageSample)
}

// RetireObserver receives one call per key retirement.
type RetireObserver interface {
	KeyRetired(route string, reason RetireReason)
}

var (
	_ RotationStore      = (*Store)(nil)
	_ RetryAfterReporter = (*Store)(nil)
	_ ReasonedRetirer    = (*Store)(nil)
	_ SampleRecorder     = (*Store)(nil)
)

// Budget is one route's per-KEY allowance for one window.
//
// The window is TUMBLING, not sliding: it starts at the store's epoch and
// rolls over lazily on the first call after it expires. Tumbling matches how
// provider plans actually reset, needs no ring buffer, and — because rollover
// is evaluated from the injectable clock on every call — is testable by
// advancing a fake clock rather than by sleeping.
type Budget struct {
	// Window is the accounting period. Zero disables all caps.
	Window time.Duration `yaml:"window"`
	// Tokens is the hard per-key token cap for the window. Zero = uncapped.
	Tokens int64 `yaml:"tokens"`
	// Requests is the hard per-key request cap for the window. Zero = uncapped.
	Requests int64 `yaml:"requests"`
	// SoftRatio is the fraction of a cap at which a key is retired for the
	// rest of the window rather than allowed to run into an upstream error.
	// Zero means DefaultSoftRatio. Must be in (0, 1].
	SoftRatio float64 `yaml:"soft_ratio"`
	// EstimateTokens is charged for a request whose response reported no token
	// count — the streaming case. REQUIRED when Tokens > 0: leaving it zero
	// would let an all-streaming route spend a token budget that never
	// advances. Config.Validate rejects that combination at startup.
	EstimateTokens int64 `yaml:"estimate_tokens"`
}

// RotationConfig is the per-route rotation block.
type RotationConfig struct {
	// Policy names the selection strategy. Empty means PolicyRoundRobin.
	Policy PolicyName `yaml:"policy"`
	// Budget is the per-key window allowance.
	Budget Budget `yaml:"budget"`
	// MaxRetryAfter clamps the Retry-After advertised on a 503. Zero means
	// DefaultMaxRetryAfter. The advertised value is min(trueWait, clamp): a
	// client that retries early simply receives another 503 with a fresh
	// value, whereas several agents treat an hours-long Retry-After as fatal.
	MaxRetryAfter time.Duration `yaml:"max_retry_after"`
}

// UnmarshalYAML accepts BOTH shipped spellings of the rotation key:
//
//	rotation: round_robin                          -> {Policy: "round_robin"}
//	rotation: {policy:, budget:, max_retry_after:}  -> decoded normally
//
// The scalar shorthand is not sugar: it is the spelling in the example config
// this gateway already ships, and dropping it would turn a deployed file into a
// parse error on upgrade. Anything else — a sequence, an alias — is rejected
// rather than coerced, so a mis-indented budget block fails at load instead of
// silently configuring no budget at all.
func (rc *RotationConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Tag == "!!null" {
			// "rotation:" with nothing after it. The zero config means
			// round-robin with no budget once defaults are applied.
			*rc = RotationConfig{}
			return nil
		}
		var name string
		if err := value.Decode(&name); err != nil {
			return rotationShapeError(value)
		}
		*rc = RotationConfig{Policy: PolicyName(name)}
		return nil
	case yaml.MappingNode:
		// The alias type sheds the custom unmarshaller, so Decode does the
		// ordinary field-by-field work instead of recursing into this method.
		type plain RotationConfig
		var p plain
		if err := value.Decode(&p); err != nil {
			return err
		}
		*rc = RotationConfig(p)
		return nil
	default:
		return rotationShapeError(value)
	}
}

func rotationShapeError(value *yaml.Node) error {
	return fmt.Errorf("rotation must be a policy name or a mapping of policy/budget/max_retry_after (got %s)", yamlKindName(value.Kind))
}

// yamlKindName names a node kind for an operator-facing error. yaml.Kind is a
// bitmask constant with no String method.
func yamlKindName(k yaml.Kind) string {
	switch k {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "unknown"
	}
}

const (
	// DefaultSoftRatio retires a key at 80% of its window budget.
	DefaultSoftRatio = 0.8
	// DefaultMaxRetryAfter clamps advertised Retry-After to one hour.
	DefaultMaxRetryAfter = time.Hour
	// MinRetryAfter is the floor for an advertised Retry-After. "Retry-After:
	// 0" tells a client nothing useful.
	MinRetryAfter = time.Second
	// DefaultQuotaCooldown parks a key that reported an upstream quota error
	// when the route has no accounting window to fall back on.
	DefaultQuotaCooldown = 5 * time.Minute
)

// Store is the default RotationStore: per-route, per-key accounting over a
// tumbling window, with soft/hard caps and an injectable clock.
//
// It guards state with a mutex rather than the atomics internal/keypool uses.
// keypool only needs round-robin, which requires no cross-key consistency;
// leastUsed and leastTokens must compare every key against every other at one
// instant, and rollover must zero every key at once. The lock is held for
// in-memory arithmetic only — never across a network call and never across a
// metric increment: retirement events are collected under the lock and
// emitted after it is released.
//
// Store starts no goroutines. Rollover is lazy, so there is no timer to leak
// and no need for goleak.
type Store struct {
	mu            sync.Mutex
	routes        map[string]*routeState
	policy        RotationPolicy
	fallback      RotationPolicy
	budget        Budget
	maxRetryAfter time.Duration
	observer      RetireObserver
	now           func() time.Time
}

// routeState is one route's key accounting. Unexported; reachable only under
// Store.mu.
type routeState struct {
	keys        []keyState
	windowStart time.Time
}

// keyState is the mutable per-key record behind a KeyState snapshot.
type keyState struct {
	requests     int64
	tokens       int64
	inFlight     int64
	errors       int64
	estimated    bool
	drained      bool
	softRetired  bool
	retiredUntil time.Time
	retireReason RetireReason
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithClock injects the clock.
//
// The supplied function is called from many goroutines. A test clock MUST
// serialise its own state; a bare captured time.Time mutated by the test body
// is a data race that -race will, and should, fail on.
func WithClock(now func() time.Time) StoreOption { return func(s *Store) { s.now = now } }

// WithPolicy sets the selection policy. Default: NewRoundRobinPolicy().
func WithPolicy(p RotationPolicy) StoreOption { return func(s *Store) { s.policy = p } }

// WithBudget sets the per-key window allowance. The zero Budget disables caps.
func WithBudget(b Budget) StoreOption { return func(s *Store) { s.budget = b } }

// WithMaxRetryAfter clamps the advertised Retry-After.
func WithMaxRetryAfter(d time.Duration) StoreOption { return func(s *Store) { s.maxRetryAfter = d } }

// WithRetireObserver replaces the metric sink. Tests inject a counting fake so
// they can assert retirement reasons without touching a global registry.
func WithRetireObserver(o RetireObserver) StoreOption { return func(s *Store) { s.observer = o } }

// NewStore builds a Store. keys maps route name to that route's key count.
func NewStore(keys map[string]int, opts ...StoreOption) *Store {
	s := &Store{
		routes:        make(map[string]*routeState, len(keys)),
		policy:        NewRoundRobinPolicy(),
		fallback:      NewRoundRobinPolicy(),
		maxRetryAfter: DefaultMaxRetryAfter,
		observer:      promRetireObserver{},
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.policy == nil {
		s.policy = NewRoundRobinPolicy()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.maxRetryAfter <= 0 {
		s.maxRetryAfter = DefaultMaxRetryAfter
	}
	if s.budget.SoftRatio <= 0 || s.budget.SoftRatio > 1 {
		s.budget.SoftRatio = DefaultSoftRatio
	}
	start := s.now()
	for name, n := range keys {
		if n <= 0 {
			continue
		}
		s.routes[name] = &routeState{keys: make([]keyState, n), windowStart: start}
	}
	return s
}

// Next implements RotationStore.
func (s *Store) Next(route string) int {
	idx, _ := s.reserve(route)
	return idx
}

// admissionRefusal is WHY a reservation was declined. The two reasons are
// operationally different questions and must not be collapsed into one boolean.
//
// The R1 admission-control fix created a second way for a reservation to fail
// and left it wearing the first one's label. A route refusing on refusalAdmission
// reported {available: 2, degraded: false} on /healthz, with every key
// Selectable and none Drained, while answering callers "every upstream key on
// this route is retired or drained" — so an operator paged by that answer went
// hunting a billing problem that did not exist, and the one signal that could
// have told them otherwise agreed with them.
type admissionRefusal uint8

const (
	// refusalNone is a granted lease.
	refusalNone admissionRefusal = iota
	// refusalDrained: no key is selectable at all. Every one is retired (an
	// upstream quota signal) or capped out for the window. The plans are spent;
	// the wait is until a window rolls or a cooldown expires; it is a BILLING
	// question and a legitimate page.
	refusalDrained
	// refusalAdmission: at least one key is selectable and healthy, but every
	// selectable key is already at its hard cap once the leases in flight are
	// counted. Nothing is retired, nothing is drained, and the plan may be
	// barely touched. It is a CONCURRENCY question, it clears as soon as an
	// outstanding lease settles, and paging on it is a false alarm.
	refusalAdmission
)

// Acquire reserves a key and returns a lease whose Settle is idempotent. It is
// the only reservation path a gateway should use: a deferred lease.Settle can
// neither leak an in-flight slot nor release one twice. ok is false when no key
// could be reserved, for either reason; acquire reports which.
func (s *Store) Acquire(route string) (*KeyLease, bool) {
	lease, refusal := s.acquire(route)
	return lease, refusal == refusalNone
}

// acquire is Acquire with the refusal reason preserved. It is unexported
// because the reason is a gateway-response concern, not part of the store's
// published contract, and Acquire's boolean is what every existing caller and
// test is written against.
func (s *Store) acquire(route string) (*KeyLease, admissionRefusal) {
	idx, refusal := s.reserve(route)
	if refusal != refusalNone {
		return nil, refusal
	}
	return &KeyLease{route: route, index: idx, store: s}, refusalNone
}

// reserve filters, selects and reserves in ONE critical section. Snapshotting
// candidates, releasing the lock and then reserving would let a key retired in
// between be leased anyway, which is why RotationPolicy.Select is documented
// as non-blocking and forbidden from calling back into the store.
//
// The filter is admissibleLocked, NOT selectableAt: a cap that is only ever
// evaluated at settlement is overspendable by the concurrency factor, because
// every request in a simultaneous burst sees the same not-yet-charged key and
// is dispatched before any of them settles.
func (s *Store) reserve(route string) (int, admissionRefusal) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, ok := s.routes[route]
	if !ok {
		return -1, refusalDrained
	}
	now := s.now()
	s.rollLocked(rs, now)

	// selectable is counted separately from admissible so a refusal can say
	// which of the two filters emptied the candidate set. It is read from the
	// same critical section and the same `now` as the selection itself: asking
	// afterwards would be a second reading of state that may already have
	// moved, which is how a refusal ends up labelled by a window it was not
	// decided in.
	selectable := 0
	states := make([]KeyState, 0, len(rs.keys))
	for i := range rs.keys {
		if !selectableAt(&rs.keys[i], now) {
			continue
		}
		selectable++
		if s.admissibleLocked(&rs.keys[i], now) {
			states = append(states, s.keyStateLocked(rs, i, now))
		}
	}
	if len(states) == 0 {
		if selectable > 0 {
			return -1, refusalAdmission
		}
		return -1, refusalDrained
	}
	pos := s.policy.Select(states)
	if pos < 0 || pos >= len(states) {
		pos = s.fallback.Select(states)
	}
	if pos < 0 || pos >= len(states) {
		pos = 0
	}
	idx := states[pos].Index
	rs.keys[idx].inFlight++
	return idx, refusalNone
}

// admissibleLocked reports whether a key may accept ANOTHER reservation right
// now: it is selectableAt plus admission control against the HARD cap, counting
// the leases already in flight.
//
// Why admission control has to exist at all: applyCapsLocked runs at
// SETTLEMENT, and a settlement that has not happened yet cannot stop a request
// from being dispatched. Under sequential traffic that is invisible, because
// every request settles before the next one is selected. Under the concurrency
// production actually has, a burst of N requests all see the same uncharged key
// and are all sent upstream, so a per-window plan is overspendable by N — which
// is precisely the outcome the budget exists to prevent.
//
// It enforces the HARD cap only, deliberately. The soft cap is a PLANNED early
// exit that trips at settlement well before the hard cap; enforcing it here too
// would move the sequential boundary and change behaviour no finding asked to
// change. Admission is a floor under the existing rule, not a replacement.
//
// Exactness, honestly stated:
//
//   - Requests is EXACT. requests+inFlight is invariant across a settlement and
//     rises only on reservation, so the count admitted per window can never
//     exceed the cap.
//   - Tokens is a BOUND on the estimate, not a guarantee. Before a response
//     exists, Budget.EstimateTokens is the only figure available to project an
//     in-flight lease by; a response that reports MORE than the estimate can
//     still overshoot at settlement, and the hard cap then catches it there as
//     it always did. A route that sets Tokens without EstimateTokens gets no
//     token admission control at all — Config.Validate rejects that pairing.
func (s *Store) admissibleLocked(k *keyState, now time.Time) bool {
	if !selectableAt(k, now) {
		return false
	}
	b := s.budget
	if b.Window <= 0 {
		return true
	}
	if b.Requests > 0 && k.requests+k.inFlight >= b.Requests {
		return false
	}
	if b.Tokens > 0 && k.tokens+k.inFlight*b.EstimateTokens >= b.Tokens {
		return false
	}
	return true
}

// RecordUsage implements RotationStore. It is exactly equivalent to
// RecordSample(route, idx, UsageSample{Outcome: OutcomeCompleted, Tokens: tokens}).
func (s *Store) RecordUsage(route string, idx int, tokens int64) {
	s.RecordSample(route, idx, UsageSample{Outcome: OutcomeCompleted, Tokens: tokens})
}

// RecordSample implements SampleRecorder. Any negative Tokens is normalised to
// TokensUnknown and sets Estimated.
func (s *Store) RecordSample(route string, idx int, sample UsageSample) {
	if sample.Tokens < 0 {
		sample.Tokens = TokensUnknown
		sample.Estimated = true
	}
	var events []RetireReason

	s.mu.Lock()
	if rs, ok := s.routes[route]; ok && idx >= 0 && idx < len(rs.keys) {
		now := s.now()
		s.rollLocked(rs, now)
		events = s.settleLocked(&rs.keys[idx], sample)
	}
	s.mu.Unlock()

	s.emit(route, events)
}

// settleLocked applies one sample to one key and reports any retirement it
// caused. The caller emits those events after releasing the lock.
func (s *Store) settleLocked(k *keyState, sample UsageSample) []RetireReason {
	if k.inFlight > 0 {
		k.inFlight--
	}
	if sample.Outcome == OutcomeFailed {
		k.errors++
		return nil
	}
	k.requests++
	charge := sample.Tokens
	if charge == TokensUnknown {
		charge = s.budget.EstimateTokens
		k.estimated = true
	}
	k.tokens += charge
	return s.applyCapsLocked(k)
}

// applyCapsLocked trips the soft and hard caps. A key that is already out of
// rotation does not emit a second event, so a late settlement of an in-flight
// lease cannot inflate the retirement counter.
func (s *Store) applyCapsLocked(k *keyState) []RetireReason {
	b := s.budget
	if b.Window <= 0 || (b.Requests <= 0 && b.Tokens <= 0) {
		return nil
	}
	wasRetired := k.drained || k.softRetired
	switch {
	case atRatio(k.requests, b.Requests, 1) || atRatio(k.tokens, b.Tokens, 1):
		k.drained, k.softRetired = true, true
	case atRatio(k.requests, b.Requests, b.SoftRatio) || atRatio(k.tokens, b.Tokens, b.SoftRatio):
		k.softRetired = true
	}
	if (k.drained || k.softRetired) && !wasRetired {
		return []RetireReason{ReasonCap}
	}
	return nil
}

// atRatio reports whether used has reached the given fraction of limit. A
// non-positive limit is uncapped.
func atRatio(used, limit int64, ratio float64) bool {
	return limit > 0 && float64(used) >= ratio*float64(limit)
}

// Retire implements RotationStore (reason ReasonQuota).
func (s *Store) Retire(route string, idx int, until time.Time) {
	s.RetireWithReason(route, idx, until, ReasonQuota)
}

// RetireWithReason implements ReasonedRetirer. A deadline that is not later
// than both now and the key's existing deadline is a no-op: retirement only
// ever extends, so a stale call can never un-retire a cooling key.
func (s *Store) RetireWithReason(route string, idx int, until time.Time, reason RetireReason) {
	if reason == "" {
		reason = ReasonQuota
	}
	var events []RetireReason

	s.mu.Lock()
	if rs, ok := s.routes[route]; ok && idx >= 0 && idx < len(rs.keys) {
		now := s.now()
		s.rollLocked(rs, now)
		events = retireLocked(&rs.keys[idx], now, until, reason)
	}
	s.mu.Unlock()

	s.emit(route, events)
}

// retireLocked applies one retirement to one key and reports whether it was a
// RETIREMENT rather than an extension of one already in force.
//
// The distinction is the whole contract of the metric: KeyRetiredTotal counts
// keys LEAVING rotation, so a key that is already parked and is pushed further
// out has not left it a second time. Without that guard a burst of concurrent
// quota answers — all of them settling against a key retired by the first one —
// increments the counter once per response, and the alerting surface reads a
// two-key outage as sixty.
func retireLocked(k *keyState, now, until time.Time, reason RetireReason) []RetireReason {
	if !until.After(now) {
		return nil
	}
	alreadyOut := k.retiredUntil.After(now)
	if until.After(k.retiredUntil) {
		k.retiredUntil, k.retireReason = until, reason
	}
	if alreadyOut {
		return nil
	}
	return []RetireReason{reason}
}

// retireForWindow parks a key for the remainder of the accounting window,
// which is the natural cooldown for an upstream quota signal: the plan resets
// when the window does.
//
// The deadline is computed AND applied under ONE critical section. Splitting
// them let a rollover land in between: the second reading rolled the window
// past the deadline the first reading had just derived from it, `until` was no
// longer in the future, and the retirement silently became a no-op — a key that
// had just reported a spent plan stayed in rotation, with no event to say so.
func (s *Store) retireForWindow(route string, idx int, reason RetireReason) {
	if reason == "" {
		reason = ReasonQuota
	}
	var events []RetireReason

	s.mu.Lock()
	if rs, ok := s.routes[route]; ok && idx >= 0 && idx < len(rs.keys) {
		now := s.now()
		s.rollLocked(rs, now)
		until := now.Add(DefaultQuotaCooldown)
		if s.budget.Window > 0 {
			until = rs.windowStart.Add(s.budget.Window)
		}
		events = retireLocked(&rs.keys[idx], now, until, reason)
	}
	s.mu.Unlock()

	s.emit(route, events)
}

// RetryAfter implements RetryAfterReporter. The result is clamped into
// [MinRetryAfter, s.maxRetryAfter].
func (s *Store) RetryAfter(route string) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, ok := s.routes[route]
	if !ok || len(rs.keys) == 0 {
		return 0, false
	}
	now := s.now()
	s.rollLocked(rs, now)

	best := time.Duration(-1)
	for i := range rs.keys {
		k := &rs.keys[i]
		if selectableAt(k, now) {
			return 0, false
		}
		if w := s.waitForLocked(rs, k, now); best < 0 || w < best {
			best = w
		}
	}
	if best < 0 {
		return 0, false
	}
	if best > s.maxRetryAfter {
		best = s.maxRetryAfter
	}
	if best < MinRetryAfter {
		best = MinRetryAfter
	}
	return best, true
}

// waitForLocked is how long one unselectable key stays that way. A key that is
// both capped and explicitly retired must clear BOTH conditions, so the wait
// is the later of the two.
func (s *Store) waitForLocked(rs *routeState, k *keyState, now time.Time) time.Duration {
	var w time.Duration
	if k.retiredUntil.After(now) {
		w = k.retiredUntil.Sub(now)
	}
	if k.drained || k.softRetired {
		switch {
		case s.budget.Window > 0:
			if d := rs.windowStart.Add(s.budget.Window).Sub(now); d > w {
				w = d
			}
		case w == 0:
			w = s.maxRetryAfter
		}
	}
	return w
}

// Snapshot returns the route's current KeyState set, rolling the window over
// first if it has expired. It takes no reservation. Exported for tests and for
// the /healthz surface.
func (s *Store) Snapshot(route string) []KeyState {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, ok := s.routes[route]
	if !ok {
		return nil
	}
	now := s.now()
	s.rollLocked(rs, now)
	out := make([]KeyState, len(rs.keys))
	for i := range rs.keys {
		out[i] = s.keyStateLocked(rs, i, now)
	}
	return out
}

// rollLocked advances a tumbling window that has expired, zeroing the window
// counters.
//
// In-flight counts are deliberately carried across the boundary: a live lease
// must still find its slot when it settles. An explicit retirement whose
// deadline outlives the boundary is carried too — a one-hour provider cooldown
// is not a five-minute accounting artefact.
func (s *Store) rollLocked(rs *routeState, now time.Time) {
	w := s.budget.Window
	if w <= 0 {
		return
	}
	elapsed := now.Sub(rs.windowStart)
	if elapsed < w {
		return
	}
	rs.windowStart = rs.windowStart.Add((elapsed / w) * w)
	for i := range rs.keys {
		k := &rs.keys[i]
		k.requests, k.tokens, k.errors = 0, 0, 0
		k.estimated, k.drained, k.softRetired = false, false, false
		if !k.retiredUntil.After(now) {
			k.retiredUntil, k.retireReason = time.Time{}, ""
		}
	}
}

func (s *Store) keyStateLocked(rs *routeState, i int, now time.Time) KeyState {
	k := &rs.keys[i]
	return KeyState{
		Index:        i,
		Requests:     k.requests,
		Tokens:       k.tokens,
		InFlight:     k.inFlight,
		Errors:       k.errors,
		Estimated:    k.estimated,
		Selectable:   selectableAt(k, now),
		SoftRetired:  k.softRetired,
		Drained:      k.drained,
		RetiredUntil: k.retiredUntil,
		Reason:       reasonAt(k, now),
	}
}

// emit reports retirements to the observer. It is called with the lock
// RELEASED, so the hot path is never coupled to a metric backend's latency.
func (s *Store) emit(route string, events []RetireReason) {
	if s.observer == nil {
		return
	}
	for _, r := range events {
		s.observer.KeyRetired(route, r)
	}
}

func selectableAt(k *keyState, now time.Time) bool {
	return !k.drained && !k.softRetired && !k.retiredUntil.After(now)
}

func reasonAt(k *keyState, now time.Time) RetireReason {
	switch {
	case k.drained || k.softRetired:
		return ReasonCap
	case k.retiredUntil.After(now):
		if k.retireReason == "" {
			return ReasonQuota
		}
		return k.retireReason
	default:
		return ""
	}
}

// KeyLease is a single reserved use of one key.
type KeyLease struct {
	route string
	index int
	store *Store
	once  sync.Once
}

// Index is the reserved key's position in the route's key slice.
func (l *KeyLease) Index() int { return l.index }

// Settle releases the reservation exactly once. Later calls are no-ops, so a
// handler may both defer Settle and call it explicitly on the success path.
func (l *KeyLease) Settle(s UsageSample) {
	l.once.Do(func() { l.store.RecordSample(l.route, l.index, s) })
}
