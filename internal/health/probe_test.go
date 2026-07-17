package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProbePaths_PrimaryOnly(t *testing.T) {
	paths := ProbePaths("/healthz")
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	if paths[0] != "/healthz" {
		t.Errorf("primary path wrong: got %q", paths[0])
	}
	if paths[1] != "/v1/models" {
		t.Errorf("fallback path wrong: got %q", paths[1])
	}
}

func TestProbePaths_AlreadyModels(t *testing.T) {
	paths := ProbePaths("/v1/models")
	if len(paths) != 1 {
		t.Fatalf("expected 1 path (no double-append), got %d", len(paths))
	}
	if paths[0] != "/v1/models" {
		t.Errorf("got %q", paths[0])
	}
}

func TestProbeNodePath_2xxIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ok, status := ProbeNodePath(context.Background(), u, "/healthz")
	if !ok {
		t.Errorf("expected ok=true, got false (status=%d)", status)
	}
	if status != http.StatusOK {
		t.Errorf("status=%d, want 200", status)
	}
}

func TestProbeNodePath_404IsNotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ok, status := ProbeNodePath(context.Background(), u, "/missing")
	if ok {
		t.Error("expected ok=false for 404")
	}
	if status != http.StatusNotFound {
		t.Errorf("status=%d, want 404", status)
	}
}

func TestProbeNodePath_5xxIsNotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ok, _ := ProbeNodePath(context.Background(), u, "/healthz")
	if ok {
		t.Error("expected ok=false for 500")
	}
}

func TestProbeNodePath_UnreachableServer(t *testing.T) {
	// Build a URL that is guaranteed to refuse connections.
	u, _ := url.Parse("http://127.0.0.1:1") // port 1: privileged, usually unbound
	ok, status := ProbeNodePath(context.Background(), u, "/healthz")
	if ok {
		t.Error("expected ok=false for unreachable server")
	}
	if status != 0 {
		t.Errorf("status=%d, want 0 (transport failure)", status)
	}
}

func TestProbeNode_FallsBackOn404(t *testing.T) {
	calls := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ok := ProbeNode(context.Background(), 5*time.Second, "/healthz", u)
	if !ok {
		t.Error("expected fallback to /v1/models to succeed")
	}
	if calls["/healthz"] != 1 || calls["/v1/models"] != 1 {
		t.Errorf("expected both paths tried once, got %v", calls)
	}
}

func TestProbeNode_StopsOnNon404(t *testing.T) {
	// First path returns 503 (non-404, non-2xx) — should not try fallback.
	calls := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ok := ProbeNode(context.Background(), 5*time.Second, "/healthz", u)
	if ok {
		t.Error("expected ok=false when first path returns 503")
	}
	if calls["/healthz"] != 1 {
		t.Errorf("expected /healthz tried once, got %d", calls["/healthz"])
	}
	if calls["/v1/models"] != 0 {
		t.Errorf("expected /v1/models NOT tried after 503, got %d", calls["/v1/models"])
	}
}

func TestProbeNode_BothFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ok := ProbeNode(context.Background(), 5*time.Second, "/healthz", u)
	if ok {
		t.Error("expected ok=false when both paths return 404")
	}
}

func TestIsRetryableConnError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("server closed idle connection"), true},
		{errors.New("read tcp: connection reset by peer"), true},
		{errors.New("write: broken pipe"), true},
		{errors.New("context deadline exceeded"), false},
		{errors.New("connection refused"), false},
		{errors.New(""), false},
	}
	for _, c := range cases {
		got := IsRetryableConnError(c.err)
		if got != c.want {
			t.Errorf("IsRetryableConnError(%q) = %v, want %v", c.err, got, c.want)
		}
	}
}
