package relcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func fakeAPI(t *testing.T, hits *atomic.Int64, tagJSON string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tagJSON))
	}))
	t.Cleanup(srv.Close)
	old := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = old })
	return srv
}

func TestCheck_FlagsOutdatedBinary(t *testing.T) {
	var hits atomic.Int64
	fakeAPI(t, &hits, `[{"name":"v1.2.0"}]`)

	res, err := Check(context.Background(), "o", "r", "v1.1.0", t.TempDir())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Outdated || res.Latest != "v1.2.0" {
		t.Errorf("Check = %+v, want outdated with latest v1.2.0", res)
	}
}

func TestCheck_CurrentBinaryIsQuiet(t *testing.T) {
	var hits atomic.Int64
	fakeAPI(t, &hits, `[{"name":"v1.2.0"}]`)
	res, err := Check(context.Background(), "o", "r", "1.2.0", t.TempDir()) // v-prefix tolerated
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outdated {
		t.Errorf("Check = %+v, want not outdated for matching version", res)
	}
}

// TestCheck_DevBuildsNeverWarn: local builds must not nag or even hit the
// network — the check is for distributed binaries.
func TestCheck_DevBuildsNeverWarn(t *testing.T) {
	var hits atomic.Int64
	fakeAPI(t, &hits, `[{"name":"v9.9.9"}]`)
	for _, v := range []string{"", "dev", "v1.0.0-3-gabc123-dirty", "v1.0.0-11-g86256f1"} {
		res, err := Check(context.Background(), "o", "r", v, t.TempDir())
		if err != nil {
			t.Fatalf("Check(%q): %v", v, err)
		}
		if res.Outdated {
			t.Errorf("Check(%q) flagged outdated; dev builds must be exempt", v)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("dev-build checks hit the network %d times, want 0", hits.Load())
	}
}

// TestCheck_CacheStopsRepeatedAPICalls: a fleet of restarts must not
// rate-limit us — the second call inside the TTL is served from disk.
func TestCheck_CacheStopsRepeatedAPICalls(t *testing.T) {
	var hits atomic.Int64
	fakeAPI(t, &hits, `[{"name":"v2.0.0"}]`)
	dir := t.TempDir()
	if _, err := Check(context.Background(), "o", "r", "v1.0.0", dir); err != nil {
		t.Fatalf("first Check: %v", err)
	}
	if _, err := Check(context.Background(), "o", "r", "v1.0.0", dir); err != nil {
		t.Fatalf("second Check: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("API hit %d times, want 1 (second call must come from cache)", hits.Load())
	}
}

func TestCheck_EmptyTagListMeansNoWarning(t *testing.T) {
	var hits atomic.Int64
	fakeAPI(t, &hits, `[]`)
	res, err := Check(context.Background(), "o", "r", "v1.0.0", t.TempDir())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Outdated {
		t.Error("no tags upstream must mean no warning")
	}
}
