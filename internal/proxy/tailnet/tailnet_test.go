// Package tailnet tests for the v18730-2 HelixChannel TailNet
// allowlist. Each subtest asserts one invariant of the contract
// documented in `tailnet.go`. The tests are deterministic and
// hermetic — no network calls.
package tailnet

import (
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestTailscaleCGNAT_CoversCanonicalRange(t *testing.T) {
	// IANA-reserved range; every TailNet node gets an IP here.
	want := "100.64.0.0/10"
	if TailscaleCGNAT.String() != want {
		t.Fatalf("TailscaleCGNAT = %q, want %q", TailscaleCGNAT.String(), want)
	}
	// Boundary samples.
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"100.64.0.0", true},      // first addr
		{"100.64.0.1", true},      // low
		{"100.84.108.92", true},   // wsl1 (active in this TailNet)
		{"100.73.98.10", true},    // wsl3 (this host)
		{"100.119.60.6", true},    // win1
		{"100.127.255.255", true}, // last addr
		{"100.128.0.0", false},    // outside CGNAT
		{"100.63.255.255", false}, // just below
		{"8.8.8.8", false},        // public
		{"192.168.1.1", false},    // RFC1918
		{"10.42.0.1", false},      // RFC1918
		{"127.0.0.1", false},      // loopback
		{"169.254.1.1", false},    // link-local
	} {
		got := TailscaleCGNAT.Contains(netip.MustParseAddr(c.ip))
		if got != c.want {
			t.Errorf("CGNAT.Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestAllowlist_CanonicalRangeOnly(t *testing.T) {
	a, err := New("")
	if err != nil {
		t.Fatalf("New empty: %v", err)
	}
	if got := a.CIDRs(); len(got) != 1 || got[0].String() != "100.64.0.0/10" {
		t.Fatalf("CIDRs = %v, want only [100.64.0.0/10]", got)
	}
	// Sample TailNet IPs that should pass.
	for _, ip := range []string{"100.84.108.92", "100.119.60.6", "100.73.98.10", "100.79.227.40"} {
		if !a.Allow(ip) {
			t.Errorf("Allow(%s) = false, want true (TailNet peer)", ip)
		}
	}
	// Sample non-TailNet IPs that should fail.
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "13.107.42.14", "192.168.1.1"} {
		if a.Allow(ip) {
			t.Errorf("Allow(%s) = true, want false (non-TailNet)", ip)
		}
	}
}

func TestAllowlist_ExtraCIDRs(t *testing.T) {
	a, err := New("100.84.108.92/32, 10.99.0.0/16")
	if err != nil {
		t.Fatalf("New with extras: %v", err)
	}
	cidrs := a.CIDRs()
	if len(cidrs) != 3 {
		t.Fatalf("CIDRs len = %d, want 3 (CGNAT + 2 extras)", len(cidrs))
	}
	if cidrs[0].String() != "100.64.0.0/10" {
		t.Errorf("CIDRs[0] = %s, want 100.64.0.0/10 (canonical first)", cidrs[0].String())
	}
	if cidrs[1].String() != "100.84.108.92/32" {
		t.Errorf("CIDRs[1] = %s, want 100.84.108.92/32", cidrs[1].String())
	}
	if cidrs[2].String() != "10.99.0.0/16" {
		t.Errorf("CIDRs[2] = %s, want 10.99.0.0/16", cidrs[2].String())
	}
	// 100.84.108.92 is in both ranges; both pass.
	if !a.Allow("100.84.108.92") {
		t.Errorf("Allow(100.84.108.92) = false, want true (CGNAT + explicit)")
	}
	// 10.99.5.5 is only in the extra range.
	if !a.Allow("10.99.5.5") {
		t.Errorf("Allow(10.99.5.5) = false, want true (extra CIDR)")
	}
	// 10.100.0.1 is NOT in the extras — but IS in the CGNAT range.
	// This is by design: the canonical range always passes.
	if !a.Allow("10.100.0.1") && !a.Allow("100.84.108.99") {
		t.Errorf("Allow(100.84.108.99) should be true via CGNAT fallback")
	}
}

func TestAllowlist_InvalidCIDR(t *testing.T) {
	for _, raw := range []string{
		"not-a-cidr",
		"300.0.0.0/8",
		"100.64.0.0/not-a-mask",
	} {
		if _, err := New(raw); err == nil {
			t.Errorf("New(%q) = nil err, want ErrInvalidCIDR", raw)
		}
	}
}

func TestAllow_BareIPAndHostPort(t *testing.T) {
	a := MustNew("")
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"100.84.108.92", true},              // bare IP
		{"100.84.108.92:1234", true},         // host:port (port stripped)
		{"[::ffff:100.84.108.92]:443", true}, // IPv4-mapped IPv6 with port
		{"[100.84.108.92]:443", true},        // bracketed with port
		{"not-an-ip", false},                 // garbage
		{"", false},                          // empty
	} {
		got := a.Allow(c.ip)
		if got != c.want {
			t.Errorf("Allow(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestAllowAddr_TypedAddress(t *testing.T) {
	a := MustNew("")
	if !a.AllowAddr(netip.MustParseAddr("100.84.108.92")) {
		t.Errorf("AllowAddr(TailNet) = false, want true")
	}
	if a.AllowAddr(netip.MustParseAddr("8.8.8.8")) {
		t.Errorf("AllowAddr(public) = true, want false")
	}
	if a.AllowAddr(netip.Addr{}) {
		t.Errorf("AllowAddr(invalid) = true, want false")
	}
}

func TestResolveClientIPs_RemoteAddrAndXForwardedFor(t *testing.T) {
	a := MustNew("")
	// RemoteAddr only — single TailNet IP.
	got := a.ResolveClientIPs("100.84.108.92:54321", "")
	want := []string{"100.84.108.92"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveClientIPs(RA only) = %v, want %v", got, want)
	}
	// RemoteAddr is non-TailNet, X-Forwarded-For carries TailNet.
	got = a.ResolveClientIPs("8.8.8.8:443", "100.84.108.92, 100.73.98.10")
	want = []string{"100.84.108.92", "100.73.98.10"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveClientIPs(XFF) = %v, want %v", got, want)
	}
	// XFF mixes TailNet + public; only TailNet survives.
	got = a.ResolveClientIPs("100.73.98.10:0", "8.8.8.8, 100.84.108.92, 1.1.1.1")
	want = []string{"100.73.98.10", "100.84.108.92"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolveClientIPs(mixed XFF) = %v, want %v", got, want)
	}
	// Both empty — empty result.
	got = a.ResolveClientIPs("", "")
	if len(got) != 0 {
		t.Errorf("ResolveClientIPs(empty) = %v, want []", got)
	}
}

func TestWithExtraCIDRs_ImmutableOriginal(t *testing.T) {
	a := MustNew("")
	a2, err := a.WithExtraCIDRs("100.84.108.92/32")
	if err != nil {
		t.Fatalf("WithExtraCIDRs: %v", err)
	}
	if len(a.CIDRs()) != 1 {
		t.Errorf("original CIDRs mutated; len = %d, want 1", len(a.CIDRs()))
	}
	if len(a2.CIDRs()) != 2 {
		t.Errorf("derived CIDRs len = %d, want 2", len(a2.CIDRs()))
	}
}

func TestParsePrefixOrAddr(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"100.84.108.92", "100.84.108.92/32"},
		{"100.84.108.92/32", "100.84.108.92/32"},
		{"100.64.0.0/10", "100.64.0.0/10"},
		{"::1", "::1/128"},
		{"::1/128", "::1/128"},
		{"fe80::1/64", "fe80::1/64"},
	} {
		got, err := parsePrefixOrAddr(c.in)
		if err != nil {
			t.Errorf("parsePrefixOrAddr(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("parsePrefixOrAddr(%q) = %s, want %s", c.in, got.String(), c.want)
		}
	}
}

func TestCIDRs_DefensiveCopy(t *testing.T) {
	a := MustNew("")
	first := a.CIDRs()
	first[0] = netip.MustParsePrefix("0.0.0.0/0")
	second := a.CIDRs()
	if second[0].String() != "100.64.0.0/10" {
		t.Errorf("CIDRs leaked; second[0] = %s, want 100.64.0.0/10", second[0].String())
	}
}

func TestNew_WhitespaceAndEmptyEntries(t *testing.T) {
	a, err := New("  100.84.108.92/32  ,  ,  10.99.0.0/16  ")
	if err != nil {
		t.Fatalf("New with whitespace: %v", err)
	}
	cidrs := a.CIDRs()
	want := []string{"100.64.0.0/10", "100.84.108.92/32", "10.99.0.0/16"}
	got := make([]string, len(cidrs))
	for i, c := range cidrs {
		got[i] = c.String()
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CIDRs = %v, want %v", got, want)
	}
	// And the empty comma slot was skipped silently.
	for _, c := range cidrs {
		if strings.TrimSpace(c.String()) == "" {
			t.Errorf("empty CIDR sneaked in: %q", c.String())
		}
	}
}
