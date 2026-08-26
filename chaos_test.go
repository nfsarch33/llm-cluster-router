package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// chaosClock is a deterministic, mutex-guarded clock shared between the test
// and an upstream/breaker. It lets recovery scenarios advance "time" without
// real sleeps, keeping the chaos suite fast and race-clean.
type chaosClock struct {
	mu  sync.Mutex
	now time.Time
}

func newChaosClock() *chaosClock { return &chaosClock{now: time.Unix(0, 0)} }

func (c *chaosClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *chaosClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestChaos_AutomaticFailoverDownChain injects a different fault on each tier
// (502 on M3-key1, 429 on M3-key2) and asserts the request walks the ordered
// chain all the way to the healthy fallback tier.
func TestChaos_AutomaticFailoverDownChain(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	key1 := newProgrammableUpstream(t, "m3-key1", model, always(upstreamBehavior{status: 502, body: `{"error":"502"}`}))
	key2 := newProgrammableUpstream(t, "m3-key2", model, always(upstreamBehavior{status: 429, body: `{"error":"429"}`, retryAfter: "1"}))
	fb := newProgrammableUpstream(t, "fallback", model, always(upstreamBehavior{}))

	n1 := newTestNode(t, "m3-key1", key1.URL, "reasoning", 0, 1, []string{model}, 8, time.Minute, nil)
	n2 := newTestNode(t, "m3-key2", key2.URL, "reasoning", 0, 1, []string{model}, 8, time.Minute, nil)
	nf := newTestNode(t, "fallback", fb.URL, "reasoning", 10, 1, []string{model}, 8, time.Minute, nil)
	r := newFailoverRouter([]*upstreamNode{n1, n2, nf}, 5*time.Second)

	code, body := doChat(r, model)
	if code != 200 {
		t.Fatalf("expected 200 from fallback tier after walking the chain, got %d body=%s", code, body)
	}
	if key1.hits.Load() != 1 || key2.hits.Load() != 1 || fb.hits.Load() != 1 {
		t.Fatalf("expected each tier tried once (key1=1 key2=1 fallback=1), got key1=%d key2=%d fallback=%d",
			key1.hits.Load(), key2.hits.Load(), fb.hits.Load())
	}
}

// TestChaos_SelfRecoveryAfterUpstreamHealthy is the end-to-end self-heal proof:
// an upstream 502s until its breaker trips (node ejected from rotation), then
// — after the upstream recovers AND the fake cooldown elapses — the breaker
// half-opens, the request succeeds, and the breaker closes. No real sleeps.
func TestChaos_SelfRecoveryAfterUpstreamHealthy(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	var down atomic.Bool
	down.Store(true)
	up := newProgrammableUpstream(t, "flaky", model, func(int64) upstreamBehavior {
		if down.Load() {
			return upstreamBehavior{status: 502, body: `{"error":"saturated"}`}
		}
		return upstreamBehavior{}
	})

	clk := newChaosClock()
	node := newTestNode(t, "m3", up.URL, "reasoning", 0, 1, []string{model}, 3, 30*time.Second, clk.Now)
	r := newFailoverRouter([]*upstreamNode{node}, 2*time.Second)

	// Three 502s trip the breaker (threshold 3). Each is relayed as a real 502.
	for i := 0; i < 3; i++ {
		if code, _ := doChat(r, model); code != 502 {
			t.Fatalf("request %d: expected relayed 502, got %d", i, code)
		}
	}
	if node.breaker.GetState() != circuitOpen {
		t.Fatalf("breaker should be open after 3 consecutive 502s, got %s", node.breaker.GetState())
	}

	// Breaker open + only node => fast 503 "no healthy upstream" (no hang,
	// no request lost). The upstream is not even contacted.
	hitsBefore := up.hits.Load()
	if code, _ := doChat(r, model); code != 503 {
		t.Fatalf("expected 503 while breaker open, got %d", code)
	}
	if up.hits.Load() != hitsBefore {
		t.Fatalf("upstream must NOT be hit while breaker is open")
	}

	// Upstream recovers; advance the fake clock past the cooldown.
	down.Store(false)
	clk.Advance(31 * time.Second)

	code, body := doChat(r, model)
	if code != 200 {
		t.Fatalf("expected self-recovery to 200 after cooldown + upstream healthy, got %d body=%s", code, body)
	}
	if node.breaker.GetState() != circuitClosed {
		t.Fatalf("breaker should close after a successful half-open probe, got %s", node.breaker.GetState())
	}
}

// TestChaos_DisabledNodeSelfHealsViaBreaker proves the "never recovers" fix
// for a no-probe upstream (e.g. the live MiniMax bridge that 404s on /health,
// so health_check_disabled must be true). Because the health loop can never
// restore such a node, the proxy must NOT permanently mark it unhealthy on a
// transport error — the circuit breaker becomes the sole liveness signal and
// self-recovers via a half-open re-probe after its cooldown.
func TestChaos_DisabledNodeSelfHealsViaBreaker(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	clk := newChaosClock()
	// Dead URL => every attempt is a transport error. Breaker threshold 2,
	// 30s cooldown, fake clock.
	node := newTestNode(t, "m3-bridge", "http://127.0.0.1:1", "coding-agent", 0, 1, []string{model}, 2, 30*time.Second, clk.Now)
	node.cfg.HealthCheckDisabled = true
	r := newFailoverRouter([]*upstreamNode{node}, 200*time.Millisecond)

	// Two transport errors trip the breaker. The node must stay healthy=true
	// (no probe loop to ever flip it back) — the breaker does the ejecting.
	for i := 0; i < 2; i++ {
		if code, _ := doChat(r, model); code != 502 {
			t.Fatalf("request %d: expected 502 transport failure, got %d", i, code)
		}
		if !node.healthy.Load() {
			t.Fatalf("a health_check_disabled node must NEVER be stored unhealthy (would strand it forever)")
		}
	}
	if node.breaker.GetState() != circuitOpen {
		t.Fatalf("breaker should be open after 2 transport errors, got %s", node.breaker.GetState())
	}

	// Breaker open => node ejected from rotation => 503 (no upstream contacted).
	if code, _ := doChat(r, model); code != 503 {
		t.Fatalf("expected 503 while breaker open, got %d", code)
	}

	// After the cooldown the breaker half-opens and the node is RE-PROBED
	// (self-heal): selection admits it again. With the URL still dead it
	// re-trips, but the key property is that recovery is attempted at all.
	clk.Advance(31 * time.Second)
	if code, _ := doChat(r, model); code != 502 {
		t.Fatalf("expected the breaker to re-probe (and re-trip on still-dead URL) after cooldown, got %d", code)
	}
	if node.healthy.Load() != true {
		t.Fatalf("node healthy flag must remain true throughout (breaker is the liveness signal)")
	}
}

// TestChaos_FairSpreadAcrossTwoM3Keys proves quota-aware spreading: two
// healthy, same-priority M3 keys should each absorb ~half the traffic via
// weighted round-robin (this is Tier B's two-key spread).
func TestChaos_FairSpreadAcrossTwoM3Keys(t *testing.T) {
	t.Parallel()
	const (
		model = "minimax-m3"
		total = 200
		slop  = 0.20
	)
	key1 := newProgrammableUpstream(t, "m3-key1", model, always(upstreamBehavior{}))
	key2 := newProgrammableUpstream(t, "m3-key2", model, always(upstreamBehavior{}))
	n1 := newTestNode(t, "m3-key1", key1.URL, "reasoning", 0, 1, []string{model}, 8, time.Minute, nil)
	n2 := newTestNode(t, "m3-key2", key2.URL, "reasoning", 0, 1, []string{model}, 8, time.Minute, nil)
	r := newFailoverRouter([]*upstreamNode{n1, n2}, 5*time.Second)

	for i := 0; i < total; i++ {
		if code, _ := doChat(r, model); code != 200 {
			t.Fatalf("request %d unexpectedly failed with %d", i, code)
		}
	}
	want := float64(total) / 2
	tol := want * slop
	for name, got := range map[string]int64{"key1": key1.hits.Load(), "key2": key2.hits.Load()} {
		if float64(got) < want-tol || float64(got) > want+tol {
			t.Errorf("%s served %d of %d, want within ±%.0f of %.0f (fair spread)", name, got, total, tol, want)
		}
	}
	if key1.hits.Load()+key2.hits.Load() != total {
		t.Fatalf("no request lost: expected %d total hits, got %d", total, key1.hits.Load()+key2.hits.Load())
	}
}

// TestChaos_LatencyTimeoutTriggersFailover injects latency that exceeds the
// router's request timeout on the primary, forcing a transport-timeout that
// must fail over to the fast fallback.
func TestChaos_LatencyTimeoutTriggersFailover(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	slow := newProgrammableUpstream(t, "slow", model, always(upstreamBehavior{delay: 1500 * time.Millisecond}))
	fast := newProgrammableUpstream(t, "fast", model, always(upstreamBehavior{}))
	sNode := newTestNode(t, "m3-slow", slow.URL, "reasoning", 0, 1, []string{model}, 8, time.Minute, nil)
	fNode := newTestNode(t, "m3-fast", fast.URL, "reasoning", 10, 1, []string{model}, 8, time.Minute, nil)
	// Router timeout (200ms) << injected latency (1500ms) => deterministic timeout
	// on the primary. The 7.5x ratio is what makes the primary's timeout certain;
	// the ABSOLUTE value is what makes the FALLBACK's success certain, and only
	// the ratio was being reasoned about before.
	//
	// This used to be 40ms/300ms. Same ratio, but 40ms is not a safe budget for
	// "an instant local round trip": under -race with the whole repo running in
	// parallel, an httptest server can take longer than that just to be
	// scheduled, and then the FALLBACK leg times out too and the test reports
	// 502 "context deadline exceeded" -- a failure that looks like broken
	// failover and is really a loaded machine. Observed roughly one run in six
	// at load average ~5 on 16 cores; zero failures in 8 isolated runs.
	//
	// Scaled 5x rather than loosened: every assertion below is unchanged, and
	// the property under test (primary timeout MUST fail over to the fallback)
	// is asserted exactly as strictly as before.
	r := newFailoverRouter([]*upstreamNode{sNode, fNode}, 200*time.Millisecond)

	code, body := doChat(r, model)
	if code != 200 {
		t.Fatalf("expected failover to fast fallback after primary timeout, got %d body=%s", code, body)
	}
	// The slow node should be flagged unhealthy by the transport-timeout path.
	if sNode.healthy.Load() {
		t.Errorf("slow node should be marked unhealthy after a request timeout")
	}
	if fast.hits.Load() != 1 {
		t.Fatalf("expected fast fallback to serve exactly once, got %d", fast.hits.Load())
	}
}

// TestChaos_NoInfiniteLoopWhenAllNodesFail asserts termination + no lost
// request when every upstream is unhealthy: each node is tried at most once
// and the caller still receives a definite (relayed) status.
func TestChaos_NoInfiniteLoopWhenAllNodesFail(t *testing.T) {
	t.Parallel()
	const model = "minimax-m3"
	ups := make([]*programmableUpstream, 3)
	nodes := make([]*upstreamNode, 3)
	for i := range ups {
		ups[i] = newProgrammableUpstream(t, "down", model, always(upstreamBehavior{status: 502, body: `{"error":"down"}`}))
		nodes[i] = newTestNode(t, "n", ups[i].URL, "reasoning", 0, 1, []string{model}, 8, time.Minute, nil)
		nodes[i].cfg.Name = "n" + string(rune('0'+i))
	}
	r := newFailoverRouter(nodes, 2*time.Second)

	code, _ := doChat(r, model)
	if code != 502 {
		t.Fatalf("expected a relayed 502 when all nodes fail, got %d", code)
	}
	var totalHits int64
	for _, up := range ups {
		if h := up.hits.Load(); h > 1 {
			t.Fatalf("node retried more than once (%d) — possible loop", h)
		} else {
			totalHits += h
		}
	}
	// At most maxFailoverAttempts distinct nodes contacted; here exactly 3.
	if totalHits == 0 || totalHits > int64(maxFailoverAttempts) {
		t.Fatalf("expected 1..%d total upstream hits, got %d", maxFailoverAttempts, totalHits)
	}
}

// TestChaos_ConcurrentFailoverRaceClean fires many concurrent requests against
// a flapping set (primary 502s, fallback OK) and asserts every request returns
// a definite status with no hang. Run under -race to catch data races in the
// failover/breaker paths.
func TestChaos_ConcurrentFailoverRaceClean(t *testing.T) {
	t.Parallel()
	const (
		model = "minimax-m3"
		reqs  = 100
	)
	primary := newProgrammableUpstream(t, "primary", model, func(hit int64) upstreamBehavior {
		if hit%2 == 0 {
			return upstreamBehavior{status: 502, body: `{"error":"flap"}`}
		}
		return upstreamBehavior{}
	})
	fallback := newProgrammableUpstream(t, "fallback", model, always(upstreamBehavior{}))
	pNode := newTestNode(t, "primary", primary.URL, "reasoning", 0, 1, []string{model}, 1000, time.Minute, nil)
	fNode := newTestNode(t, "fallback", fallback.URL, "reasoning", 10, 1, []string{model}, 1000, time.Minute, nil)
	r := newFailoverRouter([]*upstreamNode{pNode, fNode}, 5*time.Second)

	var wg sync.WaitGroup
	var ok, served atomic.Int64
	for i := 0; i < reqs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := doChat(r, model)
			served.Add(1)
			if code == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()

	if served.Load() != reqs {
		t.Fatalf("expected all %d requests to return (no hang), got %d", reqs, served.Load())
	}
	// Every request must ultimately succeed because the fallback is always up.
	if ok.Load() != reqs {
		t.Fatalf("expected all %d requests to succeed via failover, got %d", reqs, ok.Load())
	}
}
