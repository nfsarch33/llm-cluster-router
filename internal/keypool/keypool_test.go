package keypool

import (
	"sync"
	"testing"
	"time"
)

func poolAt(keys []string, cooldown time.Duration, now *time.Time) *Pool {
	p := New(keys, cooldown)
	p.now = func() time.Time { return *now }
	return p
}

func TestNext_RoundRobinOverHealthyKeys(t *testing.T) {
	now := time.Unix(1000, 0)
	p := poolAt([]string{"a", "b", "c"}, time.Minute, &now)
	var got []string
	for i := 0; i < 6; i++ {
		k, _ := p.Next()
		got = append(got, k)
	}
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Next() sequence = %v, want %v", got, want)
		}
	}
}

// TestNext_SkipsExhaustedKey is the whole point of the pool: a key that hit
// its quota must stop receiving traffic until the cooldown expires, instead
// of blindly serving 1/len(keys) of requests into guaranteed failures.
func TestNext_SkipsExhaustedKey(t *testing.T) {
	now := time.Unix(1000, 0)
	p := poolAt([]string{"a", "b", "c"}, time.Minute, &now)

	_, idxA := p.Next() // "a"
	p.MarkExhausted(idxA)

	for i := 0; i < 4; i++ {
		k, _ := p.Next()
		if k == "a" {
			t.Fatalf("Next() returned exhausted key %q on draw %d", k, i)
		}
	}
	if got := p.Cooling(); got != 1 {
		t.Errorf("Cooling() = %d, want 1", got)
	}
}

func TestNext_ExhaustedKeyRecoversAfterCooldown(t *testing.T) {
	now := time.Unix(1000, 0)
	p := poolAt([]string{"a", "b"}, time.Minute, &now)

	_, idxA := p.Next()
	p.MarkExhausted(idxA)
	now = now.Add(61 * time.Second)

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		k, _ := p.Next()
		seen[k] = true
	}
	if !seen["a"] {
		t.Error("key a should re-enter rotation after its cooldown expired")
	}
	if got := p.Cooling(); got != 0 {
		t.Errorf("Cooling() = %d, want 0 after expiry", got)
	}
}

// TestNext_AllExhaustedStillServes: the pool must never strand a request.
// When every key is cooling the round-robin key is returned anyway — a
// last-resort retry is better than a synthetic local failure, and the node
// -level failover chain still runs above us.
func TestNext_AllExhaustedStillServes(t *testing.T) {
	now := time.Unix(1000, 0)
	p := poolAt([]string{"a", "b"}, time.Minute, &now)
	_, i1 := p.Next()
	p.MarkExhausted(i1)
	_, i2 := p.Next()
	p.MarkExhausted(i2)

	k, idx := p.Next()
	if k == "" || idx < 0 {
		t.Fatalf("Next() with all keys cooling = (%q,%d), want a real key", k, idx)
	}
	if !p.AllCooling() {
		t.Error("AllCooling() should report true while every key cools")
	}
}

func TestNew_EmptyAndSingle(t *testing.T) {
	if k, idx := New(nil, time.Minute).Next(); k != "" || idx != -1 {
		t.Errorf("empty pool Next() = (%q,%d), want (\"\",-1)", k, idx)
	}
	p := New([]string{"only"}, time.Minute)
	for i := 0; i < 3; i++ {
		if k, _ := p.Next(); k != "only" {
			t.Fatalf("single-key pool returned %q", k)
		}
	}
}

func TestPool_ConcurrentAccessIsSafe(t *testing.T) {
	p := New([]string{"a", "b", "c"}, time.Minute)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k, idx := p.Next()
				if k == "" {
					t.Error("empty key from non-empty pool")
					return
				}
				if i%17 == 0 {
					p.MarkExhausted(idx)
				}
			}
		}()
	}
	wg.Wait()
}
