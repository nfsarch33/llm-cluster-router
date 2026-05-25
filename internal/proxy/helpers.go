// Package proxy provides HTTP helper types and middleware for the
// llm-cluster-router's request proxying layer.
package proxy

import (
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
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}
