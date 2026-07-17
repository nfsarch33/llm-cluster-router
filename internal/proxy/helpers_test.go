package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON_EncodesAndSetsHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, http.StatusCreated, map[string]string{"ok": "true"})

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["ok"] != "true" {
		t.Errorf("body[ok] = %q, want true", body["ok"])
	}
}

func TestCopyHeaders_DuplicatesAllValues(t *testing.T) {
	src := http.Header{}
	src.Add("X-Foo", "a")
	src.Add("X-Foo", "b")
	src.Add("Content-Type", "application/json")

	dst := http.Header{}
	CopyHeaders(dst, src)

	if got := dst.Values("X-Foo"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("X-Foo values = %v, want [a b]", got)
	}
	if got := dst.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestCopyHeaders_EmptySrc(t *testing.T) {
	dst := http.Header{}
	dst.Set("X-Existing", "yes")
	CopyHeaders(dst, http.Header{})
	if dst.Get("X-Existing") != "yes" {
		t.Error("dst was modified by empty src")
	}
}

func TestLimitBody_AllowsUnderLimit(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		body, _ := io.ReadAll(r.Body)
		if len(body) != 5 {
			t.Errorf("body length = %d, want 5", len(body))
		}
		w.WriteHeader(http.StatusOK)
	})

	h := LimitBody(1024, next)
	req := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called {
		t.Error("next handler not called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestLimitBody_RejectsOverLimit(t *testing.T) {
	// When the body exceeds the limit, MaxBytesReader returns an error
	// at Read time. The next handler is responsible for catching that
	// error and responding with 413. We verify the body is truncated
	// at the limit so the next handler can detect the overflow.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			t.Errorf("expected error reading oversized body, got nil; body len=%d", len(body))
			w.WriteHeader(http.StatusOK)
			return
		}
		// Body is limited; reading should fail with MaxBytesError.
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	})
	h := LimitBody(8, next)
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 100)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rr.Code)
	}
}

func TestBearerAuth_EmptyTokenDisablesAuth(t *testing.T) {
	called := false
	h := BearerAuth("")(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if !called {
		t.Error("handler should be called when token is empty")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestBearerAuth_ValidToken(t *testing.T) {
	called := false
	h := BearerAuth("secret-token")(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	h(rr, req)
	if !called {
		t.Error("handler should be called with valid token")
	}
}

func TestBearerAuth_InvalidToken(t *testing.T) {
	called := false
	h := BearerAuth("secret-token")(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	h(rr, req)
	if called {
		t.Error("handler should NOT be called with invalid token")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "unauthorized") {
		t.Errorf("body = %q, want 'unauthorized'", rr.Body.String())
	}
}

func TestBearerAuth_MissingHeader(t *testing.T) {
	called := false
	h := BearerAuth("secret-token")(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if called {
		t.Error("handler should NOT be called without Authorization header")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestBearerAuthFunc_DynamicToken(t *testing.T) {
	token := "initial"
	called := false
	getToken := func() string { return token }

	h := BearerAuthFunc(getToken)(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// First call with initial token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer initial")
	rr := httptest.NewRecorder()
	h(rr, req)
	if !called {
		t.Error("handler should be called with initial token")
	}

	// Rotate the token and verify the next request is validated against the new value
	called = false
	token = "rotated"
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer initial") // stale
	rr = httptest.NewRecorder()
	h(rr, req)
	if called {
		t.Error("handler should NOT be called with stale token after rotation")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status after rotation = %d, want 401", rr.Code)
	}
}

func TestBearerAuthFunc_EmptyGetTokenDisablesAuth(t *testing.T) {
	called := false
	getToken := func() string { return "" } // dynamic but currently empty
	h := BearerAuthFunc(getToken)(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if !called {
		t.Error("handler should be called when dynamic token is empty")
	}
}

func TestFlushWriter_WriteForwardsAndFlushes(t *testing.T) {
	flushCount := 0
	inner := &countingFlusher{
		ResponseWriter: httptest.NewRecorder(),
		flushFn: func() {
			flushCount++
		},
	}
	fw := FlushWriter{ResponseWriter: inner}

	n, err := fw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write err: %v", err)
	}
	if n != 5 {
		t.Errorf("write returned %d, want 5", n)
	}
	if flushCount != 1 {
		t.Errorf("expected 1 flush, got %d", flushCount)
	}
}

type countingFlusher struct {
	http.ResponseWriter
	flushFn func()
}

func (c *countingFlusher) Flush() { c.flushFn() }
