package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHelixChannelHeader_StampsResponseHeader asserts the
// additive middleware stamps the HelixChannel-Version response
// header on every reply, including the body and status code of the
// wrapped handler. This is the v18712-1 contract.
func TestHelixChannelHeader_StampsResponseHeader(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello-helixchannel"))
	})
	h := WithHelixChannelHeader(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatal("inner handler was not invoked")
	}
	if got := rr.Code; got != http.StatusTeapot {
		t.Errorf("status = %d, want %d", got, http.StatusTeapot)
	}
	if got := rr.Body.String(); got != "hello-helixchannel" {
		t.Errorf("body = %q, want %q", got, "hello-helixchannel")
	}
	if got := rr.Header().Get(HelixChannelHeader); got != HelixChannelVersion {
		t.Errorf("%s = %q, want %q", HelixChannelHeader, got, HelixChannelVersion)
	}
}

// TestHelixChannelHeader_PreservesExistingHeaders ensures the
// additive wrapper does not clobber a header the inner handler
// already set (e.g. Cache-Control or a custom X-Foo).
func TestHelixChannelHeader_PreservesExistingHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "inner-value")
		w.WriteHeader(http.StatusOK)
	})
	h := WithHelixChannelHeader(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Test"); got != "inner-value" {
		t.Errorf("X-Test = %q, want inner-value", got)
	}
	if got := rr.Header().Get(HelixChannelHeader); got != HelixChannelVersion {
		t.Errorf("%s = %q, want %q", HelixChannelHeader, got, HelixChannelVersion)
	}
}

// TestHelixChannelVersion_Stable asserts the version constant
// matches the v18712 sprint tag. Operators rely on this for
// header-based fingerprinting.
func TestHelixChannelVersion_Stable(t *testing.T) {
	if HelixChannelVersion != "v18712-1" {
		t.Errorf("HelixChannelVersion = %q, want v18712-1", HelixChannelVersion)
	}
}
