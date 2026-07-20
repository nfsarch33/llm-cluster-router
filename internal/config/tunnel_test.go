// Copyright (c) 2026 nfsarch33. Test-only; do not export.
package config

import (
	"errors"
	"testing"
	"time"
)

func TestTunnelConfig_Disabled_ReturnsErrTunnelDisabled(t *testing.T) {
	_, err := TunnelConfig{}.ToRuntime()
	if !errors.Is(err, ErrTunnelDisabled) {
		t.Fatalf("got %v; want ErrTunnelDisabled", err)
	}
}

func TestTunnelConfig_ToRuntime_Happy(t *testing.T) {
	cfg := TunnelConfig{
		Enabled:        true,
		Host:           "jump.example",
		Port:           2222,
		User:           "ubuntu",
		IdentityFile:   "/k",
		LocalPort:      14443,
		ConnectTimeout: DurationValue{Duration: 5 * time.Second},
	}
	rt, err := cfg.ToRuntime()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rt.Host != cfg.Host || rt.Port != cfg.Port {
		t.Errorf("host/port mismatch: %+v", rt)
	}
	if rt.ConnectTimeout != 5*time.Second {
		t.Errorf("timeout lost: %v", rt.ConnectTimeout)
	}
}

func TestTunnelConfig_ToRuntime_Defaults(t *testing.T) {
	cfg := TunnelConfig{
		Enabled: true, Host: "h", User: "u", IdentityFile: "/k", LocalPort: 80,
	}
	rt, err := cfg.ToRuntime()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rt.ConnectTimeout != 10*time.Second {
		t.Errorf("default 10s timeout missing: got %v", rt.ConnectTimeout)
	}
	if rt.Port != 0 { // port 0 -> defaults to 22 elsewhere
		t.Errorf("port not preserved as 0: %d", rt.Port)
	}
}

func TestTunnelConfig_ToRuntime_RejectsInvalid(t *testing.T) {
	cases := map[string]TunnelConfig{
		"missing host":       {Enabled: true, User: "u", IdentityFile: "/k", LocalPort: 1},
		"missing user":       {Enabled: true, Host: "h", IdentityFile: "/k", LocalPort: 1},
		"missing identity":   {Enabled: true, Host: "h", User: "u", LocalPort: 1},
		"bad local_port low": {Enabled: true, Host: "h", User: "u", IdentityFile: "/k", LocalPort: 0},
		"bad local_port hi":  {Enabled: true, Host: "h", User: "u", IdentityFile: "/k", LocalPort: 70000},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.ToRuntime(); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}
