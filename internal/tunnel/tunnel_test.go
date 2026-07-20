// Copyright (c) 2026 nfsarch33. Test-only; do not export.
package tunnel

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeFakeSSH drops a stand-in ssh binary in dir. We set PATH to dir so
// exec.LookPath resolves the fake instead of the system ssh. Script body
// is what the fake ssh should do on launch (typically: write a marker,
// then exit or idle).
func writeFakeSSH(t *testing.T, dir, behaviour string) string {
	t.Helper()
	path := dir + "/ssh"
	script := "#!/bin/sh\n" + behaviour
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	return path
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  SSHTunnelConfig
		want string
	}{
		{"happy", SSHTunnelConfig{Host: "jump.example", User: "ubuntu", IdentityFile: "/k", LocalPort: 14443}, ""},
		{"missing host", SSHTunnelConfig{User: "ubuntu", IdentityFile: "/k", LocalPort: 14443}, "host required"},
		{"missing user", SSHTunnelConfig{Host: "jump.example", IdentityFile: "/k", LocalPort: 14443}, "user required"},
		{"missing identity", SSHTunnelConfig{Host: "h", User: "u", LocalPort: 14443}, "identity_file required"},
		{"bad local port", SSHTunnelConfig{Host: "h", User: "u", IdentityFile: "/k", LocalPort: 70000}, "local_port must be 1..65535"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v; want substring %q", err, tc.want)
			}
		})
	}
}

func TestNew_RequiresConfig(t *testing.T) {
	if _, err := New(context.Background(), SSHTunnelConfig{}); err == nil {
		t.Fatal("expected error on empty config")
	}
}

// TestDialContext_InvokesFakeSSH proves that the supplied ssh binary is
// the one executed when a tunnel-enabled dial fires. The fake writes a
// marker file then exits 0; we assert the marker file appears, which
// proves exec.LookPath resolved ssh from our injected PATH and that
// DialContext reached cmd.Start().
func TestDialContext_InvokesFakeSSH(t *testing.T) {
	tmp := t.TempDir()
	called := tmp + "/invoked"
	writeFakeSSH(t, tmp, "echo called > "+called+"\nexit 0\n")
	t.Setenv("PATH", tmp)

	cfg := SSHTunnelConfig{
		Host:         "jump.example",
		User:         "ubuntu",
		IdentityFile: "/k",
		LocalPort:    14443,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The dial will fail (fake ssh exits without ever connecting back);
	// we only care that the marker file appears.
	_, dialErr := DialContext(ctx, cfg, "tcp", "jump.example:0")
	if _, err := os.Stat(called); err != nil {
		t.Fatalf("fake ssh was not invoked: %v (dial_err=%v)", err, dialErr)
	}
}

func TestDialContext_RejectsBadConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := DialContext(ctx, SSHTunnelConfig{}, "tcp", "h:0"); err == nil {
		t.Fatal("expected validation error")
	}
}

// TestIsSSHUnavailable maps every concrete ssh-exec error class that we
// want the circuit breaker to interpret as "tunnel offline".
func TestIsSSHUnavailable(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("some random error"), false},
		{ErrSSHNotInstalled, true},
		{ErrSSHDial, true},
		{&net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}, true},
	}
	for _, tc := range cases {
		if got := IsSSHUnavailable(tc.err); got != tc.want {
			t.Errorf("IsSSHUnavailable(%v) = %v; want %v", tc.err, got, tc.want)
		}
	}
}

// TestClose_KillsSSHChild proves the bridge-conn Close hook reaps the
// ssh child process so we never leak per-request ssh processes. We
// spin up a fake ssh that just idles, attach it to an sshConn via a
// pipe-pair conn, then call Close and assert the pid is gone.
func TestClose_KillsSSHChild(t *testing.T) {
	tmp := t.TempDir()
	writeFakeSSH(t, tmp, "trap '' TERM; sleep 60\n")
	t.Setenv("PATH", tmp)

	cmd := exec.Command(tmp + "/ssh")
	cmd.Stdin = openDevNull(t)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake ssh: %v", err)
	}
	pid := cmd.Process.Pid
	// Wait until the pid is actually alive before we test it.
	time.Sleep(50 * time.Millisecond)

	c1, c2 := net.Pipe()
	defer c2.Close()
	bridge := &sshConn{Conn: c1, cmd: cmd}
	if err := bridge.Close(); err != nil {
		t.Fatalf("bridge.Close: %v", err)
	}
	c1.Close()

	// On Linux, FindProcess always succeeds; Signal(0) returns an
	// error when the process is gone.
	proc, err := os.FindProcess(pid)
	if err != nil {
		// macOS path — FindProcess returns ESRCH for dead pids.
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("ssh child pid=%d still alive after bridge.Close()", pid)
}

func openDevNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	return f
}
