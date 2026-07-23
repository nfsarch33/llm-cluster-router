// Package tailnet implements the HelixChannel TailNet IP allowlist
// (v18730-2). The HelixChannel production wire (TCP/443 on
// helixchannel.cylrl.dev) terminates TLS at nginx, but the upstream
// listener in `llm-cluster-router` should defend-in-depth by only
// accepting connections from Tailscale-allocated IPs in the operator's
// TailNet. This is the same posture Tailscale recommends for SSH and
// HTTPS endpoints reachable via a public hostname.
//
// Scope:
//
//   - Parse and validate Tailscale IP (100.64.0.0/10 CGNAT range) and
//     CIDR allowlist inputs.
//   - Provide a fast `Allow(addr) bool` membership check that the
//     daemon's HTTP handler can call before invoking the proxy.
//
// Non-scope:
//
//   - The package does NOT perform DNS lookup, peer-name resolution,
//     or Tailscale ACL enforcement. Those live in `tailscale acl`
//     (the TailNet policy file) and the daemon's ingress middleware.
//   - The package does NOT open sockets. Membership check is purely
//     a string/byte comparison; the caller supplies the resolved IP.
//
// The 100.64.0.0/10 range is IANA-reserved for Tailscale by default.
// Operators may extend by adding explicit CIDRs (e.g. for a future
// TailNet with overlapping allocations) via `WithExtraCIDRs`.
//
// # Why this exists
//
// The HelixChannel hostname (`helixchannel.cylrl.dev`) is publicly
// resolvable. Anyone on the public internet can reach TCP/443 on
// the Lightsail instance. The TLS layer (Let's Encrypt cert) keeps
// the wire confidential and authenticates the server, but does not
// restrict *who* may dial the listener. A TailNet IP allowlist adds
// the missing client-side gate: even with a valid TLS handshake,
// traffic from a non-Tailscale IP is rejected before reaching the
// LLM proxy. This is defence-in-depth — Tailscale ACL remains the
// authoritative gate for TailNet peers; this is the belt-and-braces
// guard for when the upstream ACL misconfig would otherwise leak
// the endpoint to the public internet.
package tailnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// TailscaleCGNAT is the IPv4 CGNAT range IANA reserved for Tailscale.
// Reference: https://tailscale.com/kb/1015/100.x-addresses
//
// `100.64.0.0/10` covers 100.64.0.0 .. 100.127.255.255 (4,194,304
// addresses). Every TailNet node receives an IP in this range.
var TailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// Allowlist is the parsed set of CIDRs accepted by `Allow`. The
// canonical TailNet range (`100.64.0.0/10`) is always included; the
// operator may add extra CIDRs via `WithExtraCIDRs` (e.g. for a
// future TailNet with overlapping allocations, or for an explicit
// single-IP whitelist such as `100.84.108.92/32`).
type Allowlist struct {
	cidrs []netip.Prefix
}

// ErrInvalidIP is returned when a candidate IP cannot be parsed.
var ErrInvalidIP = errors.New("tailnet: invalid IP")

// ErrInvalidCIDR is returned when an allowlist CIDR cannot be parsed.
var ErrInvalidCIDR = errors.New("tailnet: invalid CIDR")

// New parses a comma-separated CIDR list and returns an Allowlist
// that always includes the canonical Tailscale CGNAT range. The
// input may be empty (the canonical range alone is sufficient for
// every modern TailNet).
//
// CIDRs may be specified with or without a prefix length; a bare
// IP (no `/`) is treated as `/32` (IPv4) or `/128` (IPv6).
func New(cidrs string) (*Allowlist, error) {
	a := &Allowlist{cidrs: []netip.Prefix{TailscaleCGNAT}}
	s := strings.TrimSpace(cidrs)
	if s == "" {
		return a, nil
	}
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := parsePrefixOrAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q (%v)", ErrInvalidCIDR, raw, err)
		}
		a.cidrs = append(a.cidrs, p)
	}
	return a, nil
}

// MustNew is the panic-on-error constructor for tests and hard-coded
// startup paths. Production callers use `New` and surface the error.
func MustNew(cidrs string) *Allowlist {
	a, err := New(cidrs)
	if err != nil {
		panic(err)
	}
	return a
}

// WithExtraCIDRs returns a copy of the allowlist with the supplied
// CIDR strings appended. Useful when the operator's runtime config
// loads additional ranges after startup (e.g. `HELIXCHANNEL_TAILNET_EXTRA`).
func (a *Allowlist) WithExtraCIDRs(cidrs ...string) (*Allowlist, error) {
	out := &Allowlist{cidrs: append([]netip.Prefix(nil), a.cidrs...)}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := parsePrefixOrAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q (%v)", ErrInvalidCIDR, raw, err)
		}
		out.cidrs = append(out.cidrs, p)
	}
	return out, nil
}

// CIDRs returns the parsed CIDR list (canonical CGNAT first, then any
// extras in insertion order). The returned slice is a defensive copy
// so callers may not mutate the allowlist's internal state.
func (a *Allowlist) CIDRs() []netip.Prefix {
	out := make([]netip.Prefix, len(a.cidrs))
	copy(out, a.cidrs)
	return out
}

// Allow reports whether ip belongs to any CIDR in the allowlist.
//
// The input may be a bare IPv4/IPv6 string, an IPv4-mapped IPv6
// address (`::ffff:100.84.108.92`), or a host:port pair (the port
// is ignored). Strings that fail to parse return false (fail-closed).
func (a *Allowlist) Allow(ip string) bool {
	addr, err := parseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range a.cidrs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// AllowAddr is the typed sibling of `Allow`. It avoids the
// string-parsing step when the caller already holds a netip.Addr.
func (a *Allowlist) AllowAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range a.cidrs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ResolveClientIPs walks an http.Request's RemoteAddr / X-Forwarded-For
// chain and returns the resolved TailNet IPs it can see. The first
// entry is the canonical client IP; the slice preserves ordering.
//
// The function does NOT consult the TailNet ACL — it merely parses
// what the request already carries. Trust the X-Forwarded-For
// header only when the upstream proxy is itself in the TailNet.
func (a *Allowlist) ResolveClientIPs(remoteAddr, xForwardedFor string) []string {
	var out []string
	if remoteAddr != "" {
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			remoteAddr = host
		}
		if a.Allow(remoteAddr) {
			out = append(out, remoteAddr)
		}
	}
	if xForwardedFor != "" {
		for _, h := range strings.Split(xForwardedFor, ",") {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if a.Allow(h) {
				out = append(out, h)
			}
		}
	}
	return out
}

// parsePrefixOrAddr accepts either a CIDR (`100.84.108.92/32`) or a
// bare IP (`100.84.108.92`) and returns a netip.Prefix. A bare IP is
// normalised to /32 (v4) or /128 (v6).
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// parseAddr accepts an IP literal, an IPv4-mapped IPv6 address, or
// a host:port pair (the port is stripped). It returns the canonical
// netip.Addr. IPv4-mapped IPv6 addresses (e.g. `::ffff:100.84.108.92`)
// are unwrapped to their IPv4 form so the canonical CGNAT range match
// succeeds; this matches the behaviour of Tailscale's `tailscale
// whois` and net.SplitHostPort on dual-stack sockets.
func parseAddr(s string) (netip.Addr, error) {
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	// Strip surrounding brackets for IPv6 literals that survived
	// the host:port strip (e.g. `[::ffff:100.84.108.92]`).
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr, nil
}
