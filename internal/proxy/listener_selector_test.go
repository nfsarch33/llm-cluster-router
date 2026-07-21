package proxy

import (
	"context"
	"testing"
)

// TestSelectListenerFactory_HelixChannelReturnsAESMTLS asserts that
// the production selector picks the AES/mTLS factory when
// HELIXCHANNEL_ENABLED=true (the v18712-2 default).
func TestSelectListenerFactory_HelixChannelReturnsAESMTLS(t *testing.T) {
	f := SelectListenerFactory(true)
	if f == nil {
		t.Fatal("SelectListenerFactory(true) returned nil")
	}
	if got := f.Channel(); got != "aes-mtls" {
		t.Errorf("Channel() = %q, want aes-mtls", got)
	}
}

// TestSelectListenerFactory_LegacyReturnsPlainHTTP asserts that
// the production selector picks the legacy plain HTTP factory
// when HELIXCHANNEL_ENABLED=false (back-compat opt-out).
func TestSelectListenerFactory_LegacyReturnsPlainHTTP(t *testing.T) {
	f := SelectListenerFactory(false)
	if f == nil {
		t.Fatal("SelectListenerFactory(false) returned nil")
	}
	if got := f.Channel(); got != "plain-http" {
		t.Errorf("Channel() = %q, want plain-http", got)
	}
}

// TestPlainHTTPListenerFactory_ListenRejectsEmptyAddr asserts the
// legacy factory honours the ListenerFactory contract: empty addr
// returns ErrEmptyAddr.
func TestPlainHTTPListenerFactory_ListenRejectsEmptyAddr(t *testing.T) {
	f := NewPlainHTTPListenerFactory()
	_, _, err := f.Listen(context.Background(), "")
	if err == nil {
		t.Fatal("expected ErrEmptyAddr for empty addr, got nil")
	}
}

// TestPlainHTTPListenerFactory_ListenBindsAndCancels asserts the
// legacy factory binds a TCP listener and the noop ServeLoop
// returns when the context is cancelled.
func TestPlainHTTPListenerFactory_ListenBindsAndCancels(t *testing.T) {
	f := NewPlainHTTPListenerFactory()
	addr := newAddr(t)

	ctx, cancel := context.WithCancel(context.Background())
	ln, serve, err := f.Listen(ctx, addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if ln == nil || serve == nil {
		t.Fatalf("Listen returned nil: ln=%v serve=%v", ln, serve)
	}
	defer ln.Close()

	// Confirm the listener bound to the requested address.
	if got := ln.Addr().String(); got != addr {
		t.Errorf("bound addr = %s, want %s", got, addr)
	}

	// Run the noop ServeLoop and cancel; it should return promptly.
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v, want nil", err)
		}
	case <-ctx.Done():
		// expected
	}
}
