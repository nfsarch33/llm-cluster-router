package channel

import (
	"fmt"
	"testing"
	"time"
)

// TestClassifyVendorCode pins every code the official MiniMax error table
// documents that this gateway acts on. The three that must NOT be conflated
// are 1002 (burst), 2056 (plan cap) and 1008 (balance): they arrive through the
// same HTTP status and need opposite handling.
func TestClassifyVendorCode(t *testing.T) {
	cases := []struct {
		code int
		want VendorClass
		why  string
	}{
		{0, VendorNone, "success"},
		{1002, VendorRateLimited, "rate limit (RPM/TPM burst)"},
		{1041, VendorRateLimited, "conn limit (concurrency)"},
		{2045, VendorRateLimited, "rate growth limit"},
		{2056, VendorQuotaWindow, "usage limit exceeded -- THE plan cap"},
		{1008, VendorBalance, "insufficient balance"},
		{1004, VendorAuth, "not authorized"},
		{2049, VendorAuth, "invalid API key"},
		{1039, VendorRequest, "token limit is per-request, not a plan cap"},
		{2013, VendorRequest, "invalid params"},
		{1000, VendorTransient, "unknown error"},
		{1001, VendorTransient, "request timeout"},
		{1024, VendorTransient, "internal error"},
		{1033, VendorTransient, "system error"},
		{99999, VendorNone, "unrecognised code must not retire a working key"},
	}
	for _, c := range cases {
		if got := classifyVendorCode(c.code); got != c.want {
			t.Errorf("classifyVendorCode(%d) = %q, want %q (%s)", c.code, got, c.want, c.why)
		}
	}
}

// TestVendorSignal_RetiresAndReason pins which classes take a key out of
// rotation. Auth and request failures must NOT: the key is healthy and
// retiring on them drains a funded pool over a caller or config bug.
func TestVendorSignal_RetiresAndReason(t *testing.T) {
	cases := []struct {
		class      VendorClass
		wantRetire bool
		wantReason RetireReason
	}{
		{VendorRateLimited, true, ReasonRateLimit},
		{VendorQuotaWindow, true, ReasonQuota},
		{VendorBalance, true, ReasonBalance},
		{VendorAuth, false, ReasonError},
		{VendorRequest, false, ReasonError},
		{VendorTransient, false, ReasonError},
		{VendorNone, false, ReasonError},
	}
	for _, c := range cases {
		v := VendorSignal{Class: c.class}
		if got := v.Retires(); got != c.wantRetire {
			t.Errorf("class %q Retires() = %v, want %v", c.class, got, c.wantRetire)
		}
		if got := v.Reason(); got != c.wantReason {
			t.Errorf("class %q Reason() = %q, want %q", c.class, got, c.wantReason)
		}
	}
}

// TestParseVendorSignal_RealisticBodies covers the shapes a MiniMax-family
// upstream actually produces, including the one that motivated this change: an
// error reported in the body alongside HTTP 200.
func TestParseVendorSignal_RealisticBodies(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantFound bool
		wantCode  int
		wantClass VendorClass
	}{
		{
			name:      "plan cap in base_resp",
			body:      `{"choices":[],"base_resp":{"status_code":2056,"status_msg":"usage limit exceeded"}}`,
			wantFound: true, wantCode: 2056, wantClass: VendorQuotaWindow,
		},
		{
			name:      "burst limit",
			body:      `{"base_resp":{"status_code":1002,"status_msg":"rate limit"}}`,
			wantFound: true, wantCode: 1002, wantClass: VendorRateLimited,
		},
		{
			name:      "insufficient balance",
			body:      `{"base_resp":{"status_code":1008,"status_msg":"insufficient balance"}}`,
			wantFound: true, wantCode: 1008, wantClass: VendorBalance,
		},
		{
			name:      "success is not a signal",
			body:      `{"usage":{"total_tokens":42},"base_resp":{"status_code":0,"status_msg":"success"}}`,
			wantFound: false, wantCode: 0,
		},
		{
			name:      "auth failure does not retire",
			body:      `{"base_resp":{"status_code":1004,"status_msg":"not authorized"}}`,
			wantFound: true, wantCode: 1004, wantClass: VendorAuth,
		},
		{
			name:      "unknown code yields no actionable signal",
			body:      `{"base_resp":{"status_code":4242,"status_msg":"???"}}`,
			wantFound: false, wantCode: 4242,
		},
		{
			name:      "no vendor envelope at all",
			body:      `{"choices":[{"message":{"content":"hi"}}],"usage":{"total_tokens":7}}`,
			wantFound: false,
		},
		{
			name:      "last base_resp wins in a streamed tail",
			body:      `data: {"base_resp":{"status_code":0}}` + "\n" + `data: {"base_resp":{"status_code":2056,"status_msg":"usage limit exceeded"}}`,
			wantFound: true, wantCode: 2056, wantClass: VendorQuotaWindow,
		},
		{
			name:      "whitespace around the value",
			body:      `{"base_resp":{ "status_code" :  1002 , "status_msg":"rate limit"}}`,
			wantFound: true, wantCode: 1002, wantClass: VendorRateLimited,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found := parseVendorSignal([]byte(c.body))
			if found != c.wantFound {
				t.Fatalf("found = %v, want %v (signal %+v)", found, c.wantFound, got)
			}
			if c.wantCode != 0 && got.Code != c.wantCode {
				t.Errorf("code = %d, want %d", got.Code, c.wantCode)
			}
			if c.wantFound && got.Class != c.wantClass {
				t.Errorf("class = %q, want %q", got.Class, c.wantClass)
			}
		})
	}
}

// TestParseVendorSignal_EmptyTail guards the nil/empty case: an extractor that
// observed nothing must not manufacture a signal.
func TestParseVendorSignal_EmptyTail(t *testing.T) {
	if _, found := parseVendorSignal(nil); found {
		t.Error("nil tail produced a signal")
	}
	if _, found := parseVendorSignal([]byte{}); found {
		t.Error("empty tail produced a signal")
	}
}

// TestParseResetAt covers the best-effort reset extraction, including the
// cases that must NOT yield a time: a stale timestamp must never shorten a
// cooldown to nothing.
func TestParseResetAt(t *testing.T) {
	future := time.Now().Add(90 * time.Minute).Unix()
	past := time.Now().Add(-90 * time.Minute).Unix()

	t.Run("epoch seconds in the future is used", func(t *testing.T) {
		body := fmt.Sprintf(`{"base_resp":{"status_code":2056,"reset_at":%d}}`, future)
		sig, found := parseVendorSignal([]byte(body))
		if !found || sig.ResetAt.IsZero() {
			t.Fatalf("expected a reset time, got %+v", sig)
		}
		if sig.ResetAt.Unix() != future {
			t.Errorf("ResetAt = %d, want %d", sig.ResetAt.Unix(), future)
		}
	})

	t.Run("epoch millis in the future is used", func(t *testing.T) {
		body := fmt.Sprintf(`{"base_resp":{"status_code":2056,"reset_time":%d}}`, future*1000)
		sig, _ := parseVendorSignal([]byte(body))
		if sig.ResetAt.IsZero() || sig.ResetAt.Unix() != future {
			t.Errorf("millis not decoded: %+v", sig.ResetAt)
		}
	})

	t.Run("past timestamp is ignored", func(t *testing.T) {
		body := fmt.Sprintf(`{"base_resp":{"status_code":2056,"reset_at":%d}}`, past)
		sig, _ := parseVendorSignal([]byte(body))
		if !sig.ResetAt.IsZero() {
			t.Errorf("a stale reset time was accepted: %v", sig.ResetAt)
		}
	})

	t.Run("absent reset leaves zero", func(t *testing.T) {
		sig, _ := parseVendorSignal([]byte(`{"base_resp":{"status_code":2056}}`))
		if !sig.ResetAt.IsZero() {
			t.Errorf("invented a reset time: %v", sig.ResetAt)
		}
	})
}

// TestVendorRetireUntil is the behaviour the whole change exists for: a burst
// limit comes back in seconds, a plan cap holds for the window, and the
// vendor's own reset time beats every local guess.
func TestVendorRetireUntil(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	windowEnd := now.Add(2 * time.Hour)

	t.Run("burst limit clears in seconds, not a window", func(t *testing.T) {
		got := vendorRetireUntil(VendorSignal{Class: VendorRateLimited}, now, windowEnd)
		if want := now.Add(VendorRateCooldown); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got.Sub(now) >= time.Minute {
			t.Errorf("a burst limit parked the key for %v; the plan is not spent", got.Sub(now))
		}
	})

	t.Run("balance parks bounded, never forever", func(t *testing.T) {
		got := vendorRetireUntil(VendorSignal{Class: VendorBalance}, now, windowEnd)
		if want := now.Add(VendorBalanceCooldown); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got.Sub(now) > time.Hour {
			t.Errorf("balance cooldown %v is too close to permanent for a signal with documented false positives", got.Sub(now))
		}
	})

	t.Run("plan cap uses the vendor reset time when named", func(t *testing.T) {
		reset := now.Add(3 * time.Hour)
		got := vendorRetireUntil(VendorSignal{Class: VendorQuotaWindow, ResetAt: reset}, now, windowEnd)
		if !got.Equal(reset) {
			t.Fatalf("got %v, want the vendor reset %v", got, reset)
		}
	})

	t.Run("plan cap falls back to the accounting window", func(t *testing.T) {
		got := vendorRetireUntil(VendorSignal{Class: VendorQuotaWindow}, now, windowEnd)
		if !got.Equal(windowEnd) {
			t.Fatalf("got %v, want the window end %v", got, windowEnd)
		}
	})

	t.Run("plan cap with no window falls back to the documented 5 hours", func(t *testing.T) {
		got := vendorRetireUntil(VendorSignal{Class: VendorQuotaWindow}, now, time.Time{})
		if want := now.Add(VendorQuotaFallbackWindow); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("a stale reset time does not shorten the cooldown", func(t *testing.T) {
		stale := now.Add(-time.Hour)
		got := vendorRetireUntil(VendorSignal{Class: VendorQuotaWindow, ResetAt: stale}, now, windowEnd)
		if got.Before(now) {
			t.Fatalf("stale reset produced a past deadline %v", got)
		}
		if !got.Equal(windowEnd) {
			t.Errorf("got %v, want the window end %v", got, windowEnd)
		}
	})

	t.Run("non-retiring classes yield no deadline", func(t *testing.T) {
		for _, cl := range []VendorClass{VendorAuth, VendorRequest, VendorTransient, VendorNone} {
			if got := vendorRetireUntil(VendorSignal{Class: cl}, now, windowEnd); !got.IsZero() {
				t.Errorf("class %q produced deadline %v, want zero", cl, got)
			}
		}
	})
}

// TestTailExtractor_ImplementsVendorSignaler proves the seam the wiring relies
// on: the default extractor answers vendor questions from the SAME tail it
// already keeps for usage, so no extra buffering was introduced.
func TestTailExtractor_ImplementsVendorSignaler(t *testing.T) {
	ue := NewUsageExtractor()
	vs, ok := ue.(VendorSignaler)
	if !ok {
		t.Fatal("default UsageExtractor no longer implements VendorSignaler; settleLease would silently fall back to HTTP status only")
	}
	if _, found := vs.VendorSignal(); found {
		t.Error("an extractor that observed nothing reported a signal")
	}

	ue.Observe([]byte(`{"usage":{"total_tokens":11},"base_resp":{"status_code":2056,"status_msg":"usage limit exceeded"}}`))
	sig, found := vs.VendorSignal()
	if !found || sig.Code != 2056 || sig.Class != VendorQuotaWindow {
		t.Fatalf("signal = %+v found=%v, want 2056/quota", sig, found)
	}
	// The same bytes must still yield usage: the vendor scan must not consume
	// or disturb the tail.
	if got := ue.Result(); got.Tokens != 11 {
		t.Errorf("usage tokens = %d, want 11; the vendor scan disturbed the tail", got.Tokens)
	}
}

// TestVendorRetireUntil_PlanCapIgnoresShortAccountingWindow is the regression
// for a defect that shipped in the first cut of this classifier.
//
// The public edge configures budget.window: 5m as its own blast-radius bound.
// A MiniMax 2056 means the PLAN window is spent, and MiniMax documents that as
// a 5-HOUR window. Parking the key until the end of the 5-minute accounting
// window returned it almost immediately, drew 2056 again, and walked the pool.
// The two clocks must not be conflated.
func TestVendorRetireUntil_PlanCapIgnoresShortAccountingWindow(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	shortWindow := now.Add(5 * time.Minute) // the edge's accounting window

	got := vendorRetireUntil(VendorSignal{Class: VendorQuotaWindow}, now, time.Time{})
	if got.Sub(now) != VendorQuotaFallbackWindow {
		t.Fatalf("plan cap parked for %v, want the documented %v", got.Sub(now), VendorQuotaFallbackWindow)
	}
	if !got.After(shortWindow) {
		t.Errorf("a plan cap came back at %v, inside the 5m accounting window ending %v; "+
			"the key would draw 2056 again and walk the pool", got, shortWindow)
	}
}
