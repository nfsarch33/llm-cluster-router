package channel

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRotation_RequestCapIsExactAcrossThePoolSizeAndCapSweep is the measurement
// behind the operator decision "budget by requests, not tokens".
//
// Twelve combinations — four pool sizes against three per-key caps — each driven
// by a burst of 60 simultaneous callers, which is the shape that made the token
// cap overshoot by 50x. For every one of them the request cap is EXACT:
//
//   - the upstream sees min(burst, pool*cap) requests and not one more;
//   - the gateway answers every other caller 503 without a round trip;
//   - what the store charged equals what the upstream actually served;
//   - no key exceeds its own cap;
//   - nothing is left in flight once the burst has drained.
//
// The sweep must be CONCURRENT and it must cover several pool sizes. The same
// route driven sequentially is exact even with the cap broken, and a one-key
// pool cannot catch a per-key cap that is enforced per-route; both are ways this
// property has been "verified" before while remaining false in production.
//
// Note what the budget under test does NOT contain: estimate_tokens. A request
// cap needs no projection of what a response will cost, which is precisely why
// it is exact and a token cap is not.
func TestRotation_RequestCapIsExactAcrossThePoolSizeAndCapSweep(t *testing.T) {
	t.Parallel()
	const burst = 60
	for _, pool := range []int{1, 2, 3, 4} {
		for _, reqCap := range []int64{1, 5, 20} {
			name := fmt.Sprintf("pool%d_cap%d", pool, reqCap)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				assertRequestCapIsExact(t, name, pool, reqCap, burst)
			})
		}
	}
}

// assertRequestCapIsExact drives one cell of the sweep.
func assertRequestCapIsExact(t *testing.T, route string, pool int, reqCap int64, burst int) {
	t.Helper()

	plan := int64(pool) * reqCap
	if plan > int64(burst) {
		plan = int64(burst)
	}

	gate := newReleaseGate(burst)
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// Every admitted request is held until the WHOLE burst is at rest, so
		// admission control is the only thing that can bound the upstream: not
		// one lease has settled while the last caller is still being admitted.
		gate.note()
		gate.wait()
		_, _ = io.WriteString(w, `{"usage":{"total_tokens":1}}`)
	}))
	defer upstream.Close()

	keys := make([]string, 0, pool)
	for i := range pool {
		keys = append(keys, "k"+strconv.Itoa(i)+"-not-real")
	}
	srv := rotServer(t, rotatingConfig(t, route, upstream.URL, keys,
		&RotationConfig{Budget: Budget{Window: time.Hour, Requests: reqCap, SoftRatio: 1}}), nil, nil)
	handler := srv.Handler()

	var served, refused atomic.Int64
	var wg sync.WaitGroup
	wg.Add(burst)
	for range burst {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mm/v1/chat", nil))
			switch rec.Code {
			case http.StatusOK:
				served.Add(1)
			case http.StatusServiceUnavailable:
				refused.Add(1)
				gate.note() // refused without a round trip: this request is at rest
			default:
				refused.Add(1)
				gate.note()
				t.Errorf("status = %d, want 200 or 503", rec.Code)
			}
		}()
	}
	wg.Wait()

	if got := hits.Load(); got != plan {
		t.Errorf("upstream saw %d of %d burst requests against %d keys x %d requests, want %d",
			got, burst, pool, reqCap, plan)
	}
	if served.Load() != plan || refused.Load() != int64(burst)-plan {
		t.Errorf("served=%d refused=%d, want %d served and %d answered 503",
			served.Load(), refused.Load(), plan, int64(burst)-plan)
	}

	st := storeFor(t, srv, route)
	_, requests, _ := chargedTokens(st, route)
	if requests != hits.Load() {
		t.Errorf("charged %d requests but the upstream served %d: the charge must equal the work",
			requests, hits.Load())
	}
	if requests != plan {
		t.Errorf("charged %d requests against a %d-request plan (%d keys x %d), want %d",
			requests, plan, pool, reqCap, plan)
	}
	for i, k := range st.Snapshot(route) {
		if k.Requests > reqCap {
			t.Errorf("key %d charged %d requests against a %d-request cap", i, k.Requests, reqCap)
		}
		if k.InFlight != 0 {
			t.Errorf("key %d has %d leases still in flight after the burst drained", i, k.InFlight)
		}
		if k.Reclaimed != 0 {
			t.Errorf("key %d leaked %d leases: a reclaimed slot is readmitted and is the one way a request cap can be exceeded", i, k.Reclaimed)
		}
	}
}
