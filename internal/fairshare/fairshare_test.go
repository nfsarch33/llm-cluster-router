package fairshare

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenBucket_AllowsUpToBurst(t *testing.T) {
	b := newBucket(10, 60*time.Second, 3)

	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("burst request %d should be allowed", i)
		}
	}
}

func TestTokenBucket_RejectsBeyondLimit(t *testing.T) {
	b := newBucket(5, 60*time.Second, 3)

	for i := 0; i < 5; i++ {
		b.Allow()
	}

	if b.Allow() {
		t.Fatal("request beyond max_requests_per_user should be rejected")
	}
}

func TestTokenBucket_RefillsAfterWindow(t *testing.T) {
	window := 50 * time.Millisecond
	b := newBucket(3, window, 3)

	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("initial request %d should be allowed", i)
		}
	}
	if b.Allow() {
		t.Fatal("should be exhausted")
	}

	time.Sleep(window + 10*time.Millisecond)

	if !b.Allow() {
		t.Fatal("should be allowed after window refill")
	}
}

func TestTokenBucket_PartialRefill(t *testing.T) {
	window := 100 * time.Millisecond
	b := newBucket(10, window, 5)

	for i := 0; i < 10; i++ {
		b.Allow()
	}

	time.Sleep(window/2 + 5*time.Millisecond)

	allowed := 0
	for i := 0; i < 10; i++ {
		if b.Allow() {
			allowed++
		}
	}
	if allowed < 4 || allowed > 6 {
		t.Fatalf("expected ~5 tokens refilled after half window, got %d", allowed)
	}
}

func TestFairScheduler_MultipleUsers_NoStarvation(t *testing.T) {
	s := New(Config{
		MaxRequestsPerUser: 20,
		Window:             time.Second,
		Burst:              5,
	})
	defer s.Stop()

	const numUsers = 10
	const reqsPerUser = 5

	var (
		mu       sync.Mutex
		results  = make(map[string]int)
		rejected atomic.Int64
	)

	var wg sync.WaitGroup
	for u := 0; u < numUsers; u++ {
		wg.Add(1)
		go func(userID string) {
			defer wg.Done()
			for i := 0; i < reqsPerUser; i++ {
				if s.Acquire(userID) {
					mu.Lock()
					results[userID]++
					mu.Unlock()
					s.Release(userID)
				} else {
					rejected.Add(1)
				}
			}
		}(fmt.Sprintf("user-%d", u))
	}
	wg.Wait()

	if rejected.Load() > 0 {
		t.Fatalf("no requests should be rejected with generous limits, got %d rejections", rejected.Load())
	}

	for u := 0; u < numUsers; u++ {
		key := fmt.Sprintf("user-%d", u)
		if results[key] != reqsPerUser {
			t.Errorf("user %s: expected %d completions, got %d", key, reqsPerUser, results[key])
		}
	}
}

func TestFairScheduler_RejectsOverLimit(t *testing.T) {
	s := New(Config{
		MaxRequestsPerUser: 3,
		Window:             time.Minute,
		Burst:              3,
	})
	defer s.Stop()

	user := "heavy-user"
	for i := 0; i < 3; i++ {
		if !s.Acquire(user) {
			t.Fatalf("request %d should be allowed", i)
		}
		s.Release(user)
	}

	if s.Acquire(user) {
		t.Fatal("4th request should be rejected (over per-user limit)")
	}
}

func TestFairScheduler_FallbackToTokenHash(t *testing.T) {
	s := New(Config{
		MaxRequestsPerUser: 5,
		Window:             time.Minute,
		Burst:              3,
	})
	defer s.Stop()

	token := "dummy-not-a-real-key-v18752"
	userID := UserFromToken(token)

	if userID == "" {
		t.Fatal("UserFromToken should return non-empty hash")
	}

	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))[:16]
	if userID != "token:"+expected {
		t.Fatalf("unexpected user ID from token: %s", userID)
	}

	if !s.Acquire(userID) {
		t.Fatal("first request with token-derived user should be allowed")
	}
	s.Release(userID)
}

func TestFairScheduler_Cleanup(t *testing.T) {
	s := New(Config{
		MaxRequestsPerUser: 5,
		Window:             50 * time.Millisecond,
		Burst:              3,
		CleanupInterval:    100 * time.Millisecond,
	})
	defer s.Stop()

	s.Acquire("ephemeral-user")
	s.Release("ephemeral-user")

	time.Sleep(200 * time.Millisecond)

	s.mu.RLock()
	_, exists := s.buckets["ephemeral-user"]
	s.mu.RUnlock()

	if exists {
		t.Fatal("expired bucket should have been cleaned up")
	}
}

func TestFairScheduler_ConcurrentAccess(t *testing.T) {
	s := New(Config{
		MaxRequestsPerUser: 100,
		Window:             time.Second,
		Burst:              10,
	})
	defer s.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			user := fmt.Sprintf("user-%d", id%5)
			for j := 0; j < 10; j++ {
				if s.Acquire(user) {
					s.Release(user)
				}
			}
		}(i)
	}
	wg.Wait()
}
