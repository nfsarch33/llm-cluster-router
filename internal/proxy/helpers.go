// Package proxy provides HTTP helper types and middleware for the
// llm-cluster-router's request proxying layer.
package proxy

import (
	"context"
	"encoding/json"
	"net/http"
)

// WriteJSON encodes payload as JSON and writes it with the given
// HTTP status code.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// CopyHeaders copies all HTTP headers from src to dst.
func CopyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// FlushWriter wraps an http.ResponseWriter and flushes after every
// Write call, enabling streaming SSE responses.
type FlushWriter struct {
	http.ResponseWriter
}

func (fw FlushWriter) Write(p []byte) (int, error) {
	n, err := fw.ResponseWriter.Write(p)
	if flusher, ok := fw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

// LimitBody wraps an http.Handler and limits request body size.
func LimitBody(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// BearerAuth returns middleware that validates a static bearer token.
// An empty token disables auth entirely.
func BearerAuth(token string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		if token == "" {
			return next
		}
		return func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+token {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

// BearerAuthFunc is the dynamic-token form that calls getToken() on
// each request so token rotation via SIGHUP is immediate.
func BearerAuthFunc(getToken func() string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := getToken()
			if token == "" {
				next(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+token {
				if onReject != nil {
					onReject(r.URL.Path)
				}
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

// onReject is the package-level hook invoked when BearerAuthFunc rejects a
// request. Wired by SetAuthRejectHook from main.go so the proxy package
// does not depend on internal/metrics.
var onReject func(path string)

// SetAuthRejectHook installs a callback invoked on every bearer-token
// rejection. Passing nil clears the hook (useful in tests). The callback
// runs synchronously on the hot path; keep it cheap (one prom Counter Inc).
func SetAuthRejectHook(fn func(path string)) { onReject = fn }

// WorkloadClass is the traffic class derived from credentials: every valid
// token is either "internal" or "customer". It is carried in the request
// context; callers cannot set it.
type WorkloadClass string

const (
	ClassInternal WorkloadClass = "internal"
	ClassCustomer WorkloadClass = "customer"
)

type classCtxKey struct{}

// ClassFromRequest reports the workload class derived at auth time.
// Requests that skipped auth (no configured token) read as internal.
func ClassFromRequest(r *http.Request) WorkloadClass {
	if c, ok := r.Context().Value(classCtxKey{}).(WorkloadClass); ok {
		return c
	}
	return ClassInternal
}

// ClassBearerAuthFunc is BearerAuthFunc extended with workload classes:
// the internal token (or an unset token) authenticates as internal; every
// token in customerTokens authenticates as customer. Any other bearer is
// rejected exactly like BearerAuthFunc. The class rides the request
// context — a caller-set header can never change it.
func ClassBearerAuthFunc(getInternalToken func() string, customerTokens func() []string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			internal := getInternalToken()
			auth := r.Header.Get("Authorization")
			if internal == "" && len(customerTokens()) == 0 {
				next(w, r)
				return
			}
			var class WorkloadClass
			match := false
			if internal != "" && auth == "Bearer "+internal {
				class, match = ClassInternal, true
			}
			if !match {
				for _, t := range customerTokens() {
					if t != "" && auth == "Bearer "+t {
						class, match = ClassCustomer, true
						break
					}
				}
			}
			if !match {
				if onReject != nil {
					onReject(r.URL.Path)
				}
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r.WithContext(context.WithValue(r.Context(), classCtxKey{}, class)))
		}
	}
}
