// Copyright (c) 2026 nfsarch33. Test-only; do not export.
//
// dial_more_test.go closes the v18760 coverage gap on the tunnel dial
// path: the New() boot probe, the DialContext select branches (success,
// ctx-cancel, deadline) and the exec-not-found classification. Every
// test drives the real DialContext against a scripted stand-in ssh, the
// same double the existing suite uses, so the assertions exercise the
// package's actual process- and socket-handling code.
package tunnel

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// writeFakeSSHBash drops a bash stand-in ssh in dir. bash (not sh) so the
// success double can open a TCP connection back into DialContext's
// loopback listener via /dev/tcp, which is how the package's -L contract
// completes a dial.
func writeFakeSSHBash(t *testing.T, dir, behaviour string) {
	t.Helper()
	script := "#!/bin/bash\n" + behaviour
	if err := os.WriteFile(dir+"/ssh", []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
}

func validCfg() SSHTunnelConfig {
	return SSHTunnelConfig{
		Host:         "jump.example",
		User:         "ubuntu",
		IdentityFile: "/k",
		LocalPort:    14443,
	}
}

func TestNew_HappyPathProbesSSH(t *testing.T) {
	tmp := t.TempDir()
	writeFakeSSHBash(t, tmp, "exit 0\n")
	t.Setenv("PATH", tmp)

	got, err := New(context.Background(), validCfg())
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}
	if got.Host != "jump.example" {
		t.Fatalf("New() returned mutated config: %+v", got)
	}
}

func TestNew_SSHMissingReturnsSentinel(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir: no ssh anywhere

	_, err := New(context.Background(), validCfg())
	if !errors.Is(err, ErrSSHNotInstalled) {
		t.Fatalf("New() = %v, want ErrSSHNotInstalled", err)
	}
}

func TestDialContext_UnsupportedNetwork(t *testing.T) {
	_, err := DialContext(context.Background(), validCfg(), "udp", "h:1")
	if err == nil || !strings.Contains(err.Error(), "unsupported network") {
		t.Fatalf("DialContext(udp) = %v, want unsupported-network error", err)
	}
}

// TestDialContext_SuccessAndCloseReapsChild drives the full happy path:
// the fake ssh parses its -L spec and connects back into the loopback
// listener, so DialContext returns a live conn; closing the conn must
// reap the child so no ssh process outlives the dial.
func TestDialContext_SuccessAndCloseReapsChild(t *testing.T) {
	tmp := t.TempDir()
	pidFile := tmp + "/pid"
	writeFakeSSHBash(t, tmp, strings.Join([]string{
		`echo $$ > ` + pidFile,
		`while [ "$1" != "-L" ]; do shift; done`,
		`spec="$2"`,
		`lport="${spec%%:*}"`,
		`exec 3<>"/dev/tcp/127.0.0.1/$lport"`,
		`sleep 30`,
	}, "\n")+"\n")
	t.Setenv("PATH", tmp)

	cfg := validCfg()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, cfg, "tcp", "jump.example:14443")
	if err != nil {
		t.Fatalf("DialContext success path failed: %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext returned nil conn with nil error")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close() = %v, want nil", err)
	}

	// The child must be gone shortly after Close (kill + reap).
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("fake ssh never wrote its pid: %v", err)
	}
	pid := strings.TrimSpace(string(data))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + pid); err != nil {
			return // process gone — reaped
		}
		// Zombie state also counts as reaped-in-progress; poll status.
		st, err := os.ReadFile("/proc/" + pid + "/stat")
		if err != nil || strings.Contains(string(st), ") Z ") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("ssh child pid=%s still alive 3s after conn.Close()", pid)
}

func TestDialContext_DeadlineFiresWhenSSHNeverConnects(t *testing.T) {
	tmp := t.TempDir()
	writeFakeSSHBash(t, tmp, "sleep 30\n")
	t.Setenv("PATH", tmp)

	cfg := validCfg()
	cfg.ConnectTimeout = 250 * time.Millisecond
	start := time.Now()
	_, err := DialContext(context.Background(), cfg, "tcp", "jump.example:14443")
	if err == nil {
		t.Fatal("DialContext = nil error, want timeout")
	}
	if !errors.Is(err, ErrSSHDial) || !strings.Contains(err.Error(), "timeout after") {
		t.Fatalf("DialContext = %v, want ErrSSHDial timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout branch took %v, want ~250ms", elapsed)
	}
}

func TestDialContext_CtxCancelWhileWaiting(t *testing.T) {
	tmp := t.TempDir()
	writeFakeSSHBash(t, tmp, "sleep 30\n")
	t.Setenv("PATH", tmp)

	cfg := validCfg()
	cfg.ConnectTimeout = 10 * time.Second // keep deadline out of the race
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	_, err := DialContext(ctx, cfg, "tcp", "jump.example:14443")
	if err == nil {
		t.Fatal("DialContext = nil error, want ctx cancellation")
	}
	if !errors.Is(err, ErrSSHDial) || !strings.Contains(err.Error(), "ctx:") {
		t.Fatalf("DialContext = %v, want ErrSSHDial ctx branch", err)
	}
}

func TestDialContext_StartFailureClassifiedAsNotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no ssh: cmd.Start returns *exec.Error

	_, err := DialContext(context.Background(), validCfg(), "tcp", "jump.example:14443")
	if !errors.Is(err, ErrSSHNotInstalled) {
		t.Fatalf("DialContext = %v, want ErrSSHNotInstalled", err)
	}
}

func TestIsExecNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"exec error", &exec.Error{Name: "ssh", Err: exec.ErrNotFound}, true},
		{"wrapped exec error", errors.Join(errors.New("outer"), &exec.Error{Name: "ssh", Err: exec.ErrNotFound}), true},
		{"plain error", errors.New("nope"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isExecNotFound(tc.err); got != tc.want {
				t.Fatalf("isExecNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
