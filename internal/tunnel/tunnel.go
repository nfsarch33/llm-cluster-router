// Package tunnel exposes a small, stdlib-only SSH-tunnel dialer that the
// llm-cluster-router can plug into http.Transport.DialContext. The goal
// is to let the router's outbound HTTP requests flow through an OpenSSH
// `-L` local-port-forward to a remote jump host without depending on the
// operator having an out-of-band ssh -L running in the shell.
//
// Why stdlib + os/exec on the user's existing `ssh` binary?  We could
// vendor golang.org/x/crypto/ssh, but that pulls a maintained,
// non-trivial transitive into the binary. The OSS OpenSSH CLI is
// already on every Helixon fleet node, and shelling out to it keeps the
// surface tiny and idempotent: an SSH failure becomes a normal
// stdlib error the existing circuit breaker can already interpret.
//
// The package returns sentinel errors via IsSSHUnavailable so callers
// can flag a tunneled node offline without parsing strings.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Sentinel errors. Callers should match against these via errors.Is.
var (
	// ErrSSHNotInstalled is returned when `ssh` cannot be found in PATH.
	ErrSSHNotInstalled = errors.New("tunnel: ssh binary not found in PATH")
	// ErrSSHDial is wrapped around any underlying network error coming
	// out of the ssh stdout/stderr (host unreachable, auth failure,
	// connection refused, etc.). Use IsSSHUnavailable to detect.
	ErrSSHDial = errors.New("tunnel: ssh dial failed")
)

// SSHTunnelConfig configures a single SSH -L local-port forward used by
// DialContext. The zero value is invalid; call Validate first.
//
// Fields mirror the small subset of ssh CLI flags we care about. Add
// here only when a new flag is actually needed; do not turn this into a
// generic ssh-options struct.
type SSHTunnelConfig struct {
	// Host is the remote jump host, e.g. "203.0.113.10".
	Host string
	// User is the remote SSH user, e.g. "ubuntu".
	User string
	// IdentityFile is the path to the SSH private key on disk. Path
	// resolution is left to the ssh binary (it honours $HOME/.ssh and
	// ssh-agent).
	IdentityFile string
	// Port is the remote SSH port. Defaults to 22 when zero.
	Port int
	// LocalPort is the 127.0.0.1 port tunneld (or another HTTP server)
	// is listening on the remote host. This is the port the SSH -L
	// local-forward will route back to. Typically 14443 for tunneld.
	LocalPort int
	// ConnectTimeout is the per-dial network timeout. Defaults to 10s.
	ConnectTimeout time.Duration
}

// Validate returns nil if the config has the minimal fields set.
func (c SSHTunnelConfig) Validate() error {
	if c.Host == "" {
		return errors.New("tunnel: host required")
	}
	if c.User == "" {
		return errors.New("tunnel: user required")
	}
	if c.IdentityFile == "" {
		return errors.New("tunnel: identity_file required")
	}
	if c.LocalPort <= 0 || c.LocalPort > 65535 {
		return errors.New("tunnel: local_port must be 1..65535")
	}
	return nil
}

// New performs a one-shot validation + PATH probe. It returns the first
// error it finds, or nil if both pass. The router uses this at boot to
// refuse to start with a broken tunnel config rather than fail at first
// request.
func New(ctx context.Context, cfg SSHTunnelConfig) (SSHTunnelConfig, error) {
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return cfg, fmt.Errorf("%w: %v", ErrSSHNotInstalled, err)
	}
	_ = ctx // reserved for future init probes
	return cfg, nil
}

// DialContext opens an SSH local-port-forward and dials the resulting
// loopback listener, returning a net.Conn that tunnels through to the
// remote LocalPort. It is shaped exactly to fit
// http.Transport.DialContext: (ctx, network, addr) → (net.Conn, error).
//
// Note: for HTTP keep-alive performance the dial is a fresh -L channel
// per request; production use should add a connection pool. The
// circuit breaker upstream of this dial limits spam, so per-request
// overhead is acceptable for the current LLM traffic shape (long
// requests, low concurrency).
func DialContext(ctx context.Context, cfg SSHTunnelConfig, network, addr string) (net.Conn, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if network != "tcp" {
		return nil, fmt.Errorf("tunnel: unsupported network %q", network)
	}
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	timeout := cfg.ConnectTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	// Open a dedicated 127.0.0.1 listener, hand its port to ssh -L.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("%w: listen loopback: %v", ErrSSHDial, err)
	}
	// Defensive cleanup: if the ssh process never connects, close the
	// listener so we don't leak it. A successful Accept cancels the
	// cleanup timer.
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	hostPort := fmt.Sprintf("%s:%d", cfg.Host, port)
	sshArgs := []string{
		"-N", // no remote command
		"-L", // local forward
		fmt.Sprintf("%d:127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port, cfg.LocalPort),
		"-i", cfg.IdentityFile,
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "BatchMode=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(timeout.Seconds())),
		"-p", fmt.Sprintf("%d", port),
		fmt.Sprintf("%s@%s", cfg.User, cfg.Host),
	}

	// Accept on the loopback listener concurrently with starting ssh so
	// we don't miss the connection. Run ssh in-process — its lifecycle
	// is bounded by the lifetime of the returned conn (we keep its PID
	// and reap on Close).
	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	// SSH would emit "[kex]: ..." noise on stderr; capture to a builder
	// so callers can include it in error messages when the dial fails.
	stderrBuf := &strings.Builder{}
	cmd.Stderr = stderrBuf
	cmd.Stdout = &strings.Builder{}
	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		if isExecNotFound(err) {
			return nil, fmt.Errorf("%w: %v", ErrSSHNotInstalled, err)
		}
		return nil, fmt.Errorf("%w: ssh start: %v", ErrSSHDial, err)
	}

	// Accept the inbound loopback connection (from sshd) with a
	// bounded wait so we surface ExitOnForwardFailure quickly.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		resCh <- acceptResult{c, err}
	}()

	select {
	case <-ctx.Done():
		_ = ln.Close()
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("%w: ctx: %v ssh_stderr=%q",
			ErrSSHDial, ctx.Err(), stderrBuf.String())
	case r := <-resCh:
		if r.err != nil {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("%w: accept: %v ssh_stderr=%q",
				ErrSSHDial, r.err, stderrBuf.String())
		}
		// Bridge: when the conn closes, kill the ssh child so we never
		// leak an SSH process per request.
		conn := &sshConn{Conn: r.conn, cmd: cmd}
		return conn, nil
	case <-deadline.C:
		_ = ln.Close()
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("%w: timeout after %s connecting to %s ssh_stderr=%q",
			ErrSSHDial, timeout, hostPort, stderrBuf.String())
	}
}

// sshConn wraps the loopback TCP conn so closing it also reaps the
// ssh child process.
type sshConn struct {
	net.Conn
	cmd *exec.Cmd
}

func (c *sshConn) Close() error {
	err := c.Conn.Close()
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait() // reap so we don't leave a zombie
	}
	return err
}

// IsSSHUnavailable returns true when err indicates the tunnel cannot be
// used right now (binary missing, dial failure, transport-level
// connection error). Callers can plug it into the router's existing
// circuit breaker to mark tunneled nodes offline without parsing
// strings.
func IsSSHUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrSSHNotInstalled) || errors.Is(err, ErrSSHDial) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// isExecNotFound is a small duck-type for *exec.Error (PathError
// wrapping syscall.ENOENT). We avoid importing os here so the surface
// stays focused.
func isExecNotFound(err error) bool {
	var ee *exec.Error
	return errors.As(err, &ee)
}
