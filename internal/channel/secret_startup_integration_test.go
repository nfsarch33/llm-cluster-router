//go:build integration

package channel

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestIT_NewServer_HungOPCLIFailsStartupInsteadOfHangingForever reproduces the
// finding through the PRODUCTION entry point rather than through an injected
// seam: a real config, NewServer, the default secret provider and the real
// execOPRead, with a stub `op` on PATH that leaves a grandchild holding the
// inherited stdout pipe.
//
// The measurement being reproduced: NewServer was still blocked at 45s against
// a 15s DefaultOPTimeout, because cmd.Output() waits on that pipe long after
// the context deadline has passed and the direct child has exited.
func TestIT_NewServer_HungOPCLIFailsStartupInsteadOfHangingForever(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	// Longer than DefaultOPTimeout plus the pipe-shutdown grace, so the child
	// is still holding stdout at every instant the test cares about.
	writeHungOPStub(t, dir, 40)
	prependToPATH(t, dir)

	cfg := &Config{
		Listen: "127.0.0.1:0",
		Routes: []Route{{
			Name: "mm", Prefix: "/mm/", Upstream: "https://upstream.invalid",
			Auth: AuthInject, Enabled: true,
			KeyRef: "op://example-vault/example-item/credential",
		}},
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := NewServer(cfg, nil, nil)
		done <- err
	}()

	// 45s is the measured hang. Startup must fail well inside it.
	const measuredHang = 45 * time.Second
	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("NewServer succeeded after %v against a CLI that never returns a value", elapsed)
		}
		if !errors.Is(err, ErrSecretUnavailable) {
			t.Errorf("errors.Is(err, ErrSecretUnavailable) = false, err = %v", err)
		}
		// Startup must say WHY, or the operator sees `op read` work by hand
		// and an unexplained gateway that will not come up.
		if !strings.Contains(err.Error(), "holding its output pipe") {
			t.Errorf("NewServer error = %v; it does not tell the operator that op left a child holding stdout", err)
		}
		if strings.Contains(err.Error(), "test-key-not-real") {
			t.Errorf("NewServer error carries the stub's stdout: %v", err)
		}
		if budget := DefaultOPTimeout + 10*time.Second; elapsed > budget {
			t.Errorf("NewServer took %v to fail; DefaultOPTimeout is %v, so startup overran its own declared budget by %v",
				elapsed, DefaultOPTimeout, elapsed-budget)
		}
	case <-time.After(measuredHang):
		t.Fatalf("NewServer still blocked after %v against a %v DefaultOPTimeout: "+
			"the gateway cannot start and cannot report why", measuredHang, DefaultOPTimeout)
	}
}
