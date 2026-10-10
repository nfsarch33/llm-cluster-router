package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DialContext opens a TCP connection through the SOCKS5 proxy at proxyAddr
// and tunnels to target (host:port) using the no-auth handshake (RFC 1928).
// It returns a net.Conn that is already connected to the upstream target.
//
// This client implementation intentionally implements only the no-auth
// (0x00) method; the v18705 server uses the same. If the server replies
// with a non-success method, DialContext returns ErrAuthRequired.
//
// The implementation is bounded:
//   - connection establishment honours ctx (deadline / cancel);
//   - all reads have a 10-second timeout guarded by SetReadDeadline.
//
// v18706 introduced this client; v18709 extended it with a streaming
// helper (StreamSSE) used by the real-model E2E test.
func DialContext(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	return dialSOCKS5(ctx, proxyAddr, target, 10*time.Second)
}

// ErrAuthRequired is returned when the SOCKS5 server selects an
// authentication method we do not support (we only implement 0x00).
var ErrAuthRequired = errors.New("socks5: server requested authentication, client supports only no-auth")

// ErrServerReply is returned for any non-success SOCKS5 reply code.
type ErrServerReply struct{ Code uint8 }

func (e *ErrServerReply) Error() string {
	return fmt.Sprintf("socks5: server reply code 0x%02x", e.Code)
}

func dialSOCKS5(ctx context.Context, proxyAddr, target string, handshakeTimeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: handshakeTimeout}
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: set deadline: %w", err)
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: target addr: %w", err)
	}

	// Greeting: VER=5, NMETHODS=1, METHODS=[0x00 (no-auth)].
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: write greeting: %w", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: read greeting reply: %w", err)
	}
	if greet[0] != 0x05 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: bad greeting reply version 0x%02x", greet[0])
	}
	if greet[1] == 0xff || greet[1] != 0x00 {
		_ = conn.Close()
		return nil, ErrAuthRequired
	}

	// Connect request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (FQDN).
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: write connect: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: read reply header: %w", err)
	}
	if hdr[0] != 0x05 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: bad reply version 0x%02x", hdr[0])
	}
	if hdr[1] != 0x00 {
		_ = conn.Close()
		return nil, &ErrServerReply{Code: hdr[1]}
	}
	var addrLen int
	switch hdr[3] {
	case 0x01:
		addrLen = 4
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("socks5: read fqdn len: %w", err)
		}
		addrLen = int(l[0])
	case 0x04:
		addrLen = 16
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: unknown ATYP 0x%02x", hdr[3])
	}
	tail := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, tail); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: read reply tail: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// splitHostPort is net.SplitHostPort with bare-host fallback (port 443).
func splitHostPort(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = "443"
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	return host, uint16(p), nil
}

// StreamSSE opens a SOCKS5-tunneled TCP connection to target, sends a
// streaming HTTP request with body, and reads the response line-by-line,
// returning each parsed SSE chunk until [DONE] is observed, EOF is
// reached, or err is non-nil.
//
// StreamSSE is used by v18709-3 to verify end-to-end that the SOCKS5
// listener can tunnel a real LLM streaming call without truncating
// or interleaving chunks.
func StreamSSE(ctx context.Context, proxyAddr, target, httpMethod, httpPath, authHeaderValue, streamBody string) (<-chan SSEChunk, <-chan error) {
	chunks := make(chan SSEChunk, 8)
	errs := make(chan error, 1)
	go func() {
		defer close(chunks)
		defer close(errs)
		conn, err := dialSOCKS5(ctx, proxyAddr, target, 15*time.Second)
		if err != nil {
			errs <- err
			return
		}
		defer func() { _ = conn.Close() }()

		req := buildHTTPRequest(target, httpMethod, httpPath, authHeaderValue, streamBody)
		if _, err := conn.Write([]byte(req)); err != nil {
			errs <- fmt.Errorf("socks5 stream: write request: %w", err)
			return
		}

		bodyBuf, err := readHTTPHeaders(conn)
		if err != nil {
			errs <- err
			return
		}
		streamBodyLines(conn, bodyBuf, chunks, errs)
	}()
	return chunks, errs
}

// readHTTPHeaders reads bytes from conn until the CRLF-CRLF delimiter
// is found, returning the bytes after the header block. Bounded at
// 16 KiB to prevent runaway header growth.
func readHTTPHeaders(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 8192)
	headerBuf := []byte{}
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			headerBuf = append(headerBuf, buf[:n]...)
		}
		if err != nil {
			return nil, fmt.Errorf("socks5 stream: read headers: %w", err)
		}
		if idx := indexOf(headerBuf, []byte("\r\n\r\n")); idx >= 0 {
			return headerBuf[idx+4:], nil
		}
		if len(headerBuf) > 16384 {
			return nil, fmt.Errorf("socks5 stream: headers too large")
		}
	}
}

// streamBodyLines reads body bytes from conn, parses "data: ..." lines,
// and emits SSEChunk values onto chunks until [DONE] is seen or EOF.
// Errors are sent to errs (which has capacity 1).
func streamBodyLines(conn net.Conn, initial []byte, chunks chan<- SSEChunk, errs chan<- error) {
	bodyBuf := initial
	buf := make([]byte, 8192)
	for {
		for {
			idx := indexOf(bodyBuf, []byte("\n"))
			if idx < 0 {
				break
			}
			line := trimCR(string(bodyBuf[:idx]))
			bodyBuf = bodyBuf[idx+1:]
			if payload, ok := parseDataLine(line); ok {
				chunks <- SSEChunk{Data: payload, IsDone: payload == "[DONE]"}
				if payload == "[DONE]" {
					return
				}
			}
		}
		n, err := conn.Read(buf)
		if n > 0 {
			bodyBuf = append(bodyBuf, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				return
			}
			errs <- fmt.Errorf("socks5 stream: read body: %w", err)
			return
		}
	}
}

// parseDataLine returns (payload, true) if line is a "data: ..." SSE
// line; ("", false) otherwise.
func parseDataLine(line string) (string, bool) {
	if line == "" {
		return "", false
	}
	if len(line) > 6 && line[:6] == "data: " {
		return line[6:], true
	}
	return "", false
}

// SSEChunk is one parsed "data:" line from a Server-Sent Events
// stream. IsDone is true when the payload is "[DONE]".
type SSEChunk struct {
	Data   string
	IsDone bool
}

func buildHTTPRequest(target, method, path, authHeader, body string) string {
	host, _, _ := splitHostPort(target)
	var sb []byte
	sb = append(sb, method...)
	sb = append(sb, ' ')
	sb = append(sb, path...)
	sb = append(sb, ' ')
	sb = append(sb, "HTTP/1.1\r\n"...)
	sb = append(sb, "Host: "...)
	sb = append(sb, host...)
	sb = append(sb, "\r\n"...)
	sb = append(sb, "Authorization: "...)
	sb = append(sb, authHeader...)
	sb = append(sb, "\r\n"...)
	sb = append(sb, "Content-Type: application/json\r\n"...)
	sb = append(sb, "Accept: text/event-stream\r\n"...)
	sb = append(sb, "Connection: close\r\n"...)
	contentLen := len(body)
	lenStr := strconv.Itoa(contentLen)
	sb = append(sb, "Content-Length: "...)
	sb = append(sb, lenStr...)
	sb = append(sb, "\r\n\r\n"...)
	sb = append(sb, body...)
	return string(sb)
}

func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}
