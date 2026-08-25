package channel

import (
	"net"
	"strconv"
	"strings"
)

// This file answers ONE question, in two places: does a CONNECT target name the
// machine the gateway is running on?
//
// It matters because the CONNECT leg and the reverse-proxy leg share a socket.
// handleConnect dials the target verbatim, so a tunnel to the gateway's own
// address arrives back at the gateway over the loopback interface, and
// isLoopbackPeer — which reads the accepted connection and nothing else, and is
// right to — sees a local caller. Under gateway_auth's token_loopback_exempt
// posture that is the whole authentication decision. A remote holder of the
// CONNECT token could therefore launder itself into a loopback caller and spend
// every key on every enabled route, which is precisely the power the CONNECT
// token is NOT supposed to carry.
//
// The two places are deliberate and answer different halves:
//
//   - connectSelfReference, at config-validation time, decides what can be
//     decided from the config text alone. It performs NO name resolution: a
//     validator that consults a resolver makes startup depend on whoever
//     answers that resolver, and lets a poisoned answer decide whether the
//     gateway boots.
//   - connectDialRefusal, at dial time, sees what a name actually resolved to.
//     It is the only layer that can, and it is why the config-time gap below
//     is a gap and not a hole.

// reservedLoopbackNames are host NAMES that resolve to loopback on every
// platform this ships to.
//
// This map is a BLOCKLIST OF LITERAL SPELLINGS, not a decision procedure, and
// the distinction is load-bearing: any name at all can have a 127.0.0.1 A
// record, and nothing readable in the config says which do. Deciding that here
// would mean a DNS lookup during Validate. Names this map does not know are
// caught by connectDialRefusal instead, after the address is known.
var reservedLoopbackNames = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"ip6-localhost":         true,
	"ip6-loopback":          true,
}

// localTargetKind names WHY a host string denotes the local machine, or returns
// "" if it does not.
//
// The IP forms are decided soundly: net.ParseIP settles the dotted-quad and
// IPv6 spellings including the IPv4-mapped "::ffff:127.0.0.1", and
// parseIPv4Numeric settles the inet_aton spellings ParseIP refuses. The NAME
// forms are the blocklist described above.
func localTargetKind(host string) string {
	h := bareHost(host)
	if h == "" {
		// net.Dial with an empty host dials the local system. ":443" is the
		// spelling of that which looks like a typo rather than a target.
		return "an empty host, which dials the local machine"
	}
	if ip := net.ParseIP(h); ip != nil {
		switch {
		case ip.IsLoopback():
			return "a loopback address"
		case ip.IsUnspecified():
			return "the unspecified address, which dials the local machine"
		}
		return ""
	}
	if ip, ok := parseIPv4Numeric(h); ok {
		switch {
		case ip.IsLoopback():
			return "a loopback address written in an alternative numeric form"
		case ip.IsUnspecified():
			return "the unspecified address written in an alternative numeric form"
		}
		return ""
	}
	if isReservedLoopbackName(h) {
		return "a reserved loopback name"
	}
	return ""
}

// isReservedLoopbackName reports whether a host string is one of the literal
// loopback SPELLINGS above.
//
// It is its own function because two callers read the same answer in opposite
// directions, and the difference is the whole of why isLoopbackListen does not
// use it: see the comment there.
func isReservedLoopbackName(host string) bool {
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	return reservedLoopbackNames[name] || strings.HasSuffix(name, ".localhost")
}

// parseIPv4Numeric parses the numeric IPv4 spellings net.ParseIP refuses but a
// C resolver accepts.
//
// Go's own ParseIP takes dotted quads only, so "127.1", "0x7f000001" and
// "2130706433" all fail it — yet every one of them is 127.0.0.1 to inet_aton,
// which is what getaddrinfo falls back on and therefore what a cgo-built binary
// (or any platform resolver) will dial. Checking ParseIP alone would leave the
// escalation open to anyone who spells the address differently.
//
// This IS a decision procedure for that class rather than a list: it implements
// inet_aton's grammar — one to four parts, each decimal, octal (leading 0) or
// hex (leading 0x), with the final part absorbing the remaining bytes — so a
// spelling nobody enumerated ("0177.0.0.1", "017700000001", "127.0.1") is
// decided correctly. The pure-Go resolver would reject these as hostnames and
// the dial would simply fail; refusing them costs nothing and does not depend
// on which resolver the binary was built with.
func parseIPv4Numeric(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, false
	}
	vals := make([]uint64, 0, 4)
	for _, p := range parts {
		v, ok := parseIPv4Part(p)
		if !ok {
			return nil, false
		}
		vals = append(vals, v)
	}
	n := len(vals)
	for i := 0; i < n-1; i++ {
		if vals[i] > 0xff {
			return nil, false
		}
	}
	// The last part carries every byte the earlier parts did not: with one
	// part it is the whole 32 bits, with two it is the low 24, and so on.
	if vals[n-1] >= uint64(1)<<(8*(5-n)) {
		return nil, false
	}
	var addr uint32
	for i := 0; i < n-1; i++ {
		addr |= uint32(vals[i]) << (8 * (3 - i))
	}
	addr |= uint32(vals[n-1])
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)), true
}

// parseIPv4Part parses one inet_aton component: decimal, 0-prefixed octal, or
// 0x-prefixed hex.
func parseIPv4Part(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	switch {
	case strings.HasPrefix(p, "0x"), strings.HasPrefix(p, "0X"):
		base, p = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}
	if p == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(p, base, 64)
	if err != nil || v > 0xffffffff {
		return 0, false
	}
	return v, true
}

// sameHost reports whether two host strings denote the same address, comparing
// as addresses when both parse and as names otherwise. It resolves nothing.
func sameHost(a, b string) bool {
	ipA, okA := hostIP(a)
	ipB, okB := hostIP(b)
	if okA && okB {
		return ipA.Equal(ipB)
	}
	if okA != okB {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// bareHost strips the brackets an IPv6 host wears inside an address string and
// any zone suffix, leaving the part net.ParseIP can read. A zone ("::1%lo") is
// not part of the address and ParseIP rejects it, but net.Listen and net.Dial
// both split it off and parse the rest as a literal, so dropping it here keeps
// this file's answer and the OS's answer aligned.
func bareHost(host string) string {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	return h
}

// hostIP parses a host string as an address in any spelling this file decides.
func hostIP(host string) (net.IP, bool) {
	h := bareHost(host)
	if ip := net.ParseIP(h); ip != nil {
		return ip, true
	}
	return parseIPv4Numeric(h)
}

// isLoopbackListen reports whether a bind address reaches loopback ONLY.
//
// It deliberately does NOT share this file's CONNECT-target procedure, and the
// asymmetry is the point rather than an oversight. Both questions say
// "loopback"; they are not the same question:
//
//   - As a CONNECT TARGET, loopback-ness is decided by OUR code and nothing
//     else, and answering yes REFUSES the entry. A generous reading therefore
//     fails CLOSED, which is exactly why localTargetKind implements inet_aton's
//     whole grammar and keeps a blocklist of reserved names.
//   - As the LISTEN address, the OS resolver decides what actually gets bound.
//     Our parse is only a PREDICTION, and answering yes RELAXES three separate
//     things: it waives the gateway-token requirement, it permits loopback
//     allowed_hosts entries, and it disarms connectDialRefusal. A generous
//     reading therefore fails OPEN.
//
// So this predicate trusts only what it can decide soundly on its own: an
// address LITERAL as net.ParseIP reads it, zone stripped. Everything a resolver
// would get a say in is non-loopback here and needs a token.
//
// Two classes are excluded on purpose, and each was accepted here at some point:
//
//   - NAMES, "localhost" included. A name is decidable only by resolving it,
//     and a validator that consults a resolver makes startup depend on whoever
//     answers it. A host whose /etc/hosts pointed localhost at a routable
//     address would otherwise switch all three relaxations off silently.
//   - inet_aton NUMERIC spellings: "127.1", "127.0.1", "2130706433",
//     "0x7f000001", "0177.0.0.1". These read as 127.0.0.1 to a C resolver, so
//     localTargetKind must recognise them as targets — but net.Listen does not
//     parse them as literals either. It hands them to the platform resolver,
//     hosts file and DNS included, so what gets bound is a resolver's answer.
//     Trusting them was measured binding 10.255.255.254 while this function
//     said loopback: tokenless startup accepted, an anonymous caller served
//     200, the upstream key spent.
//
// Recognising the numeric forms here also bought nothing in a shipped artifact.
// Every container build sets CGO_ENABLED=0, and the pure-Go resolver never reads
// an inet_aton spelling as an ADDRESS — it looks the string up as a NAME. All six
// were measured failing to bind at all on a host with no such entry ("listen tcp:
// lookup 127.1: no such host"; 0x7f000001 went as far as DNS). So the generous
// parse rescued no real loopback deployment; it replaced a legible config-time
// refusal with an obscure runtime failure, and on a host that DOES answer for the
// string it handed the socket — and all three relaxations — to whoever answered.
//
// The cost is that "listen: localhost:14443" and "listen: 127.1:14443" need a
// gateway_auth token or the literal spelling. loopbackListenHint makes every
// refusal that causes say which word to change.
func isLoopbackListen(addr string) bool {
	host, _ := splitHostPortLenient(addr)
	ip := net.ParseIP(bareHost(host))
	return ip != nil && ip.IsLoopback()
}

// loopbackListenHint returns the sentence that turns a refusal caused by a bind
// this package cannot decide soundly into something an operator can act on, or
// "" when the refusal is not about a spelling. It carries no leading or
// trailing punctuation: callers join it. A startup refusal on a fresh host is
// only useful if the message names the word to change.
func loopbackListenHint(listen string) string {
	if hint := loopbackNameHint(listen); hint != "" {
		return hint
	}
	return loopbackNumericHint(listen)
}

// loopbackNameHint covers a bind that NAMES loopback: "localhost" and the rest
// of the reserved blocklist.
func loopbackNameHint(listen string) string {
	host, _ := splitHostPortLenient(listen)
	if !isReservedLoopbackName(host) {
		return ""
	}
	return "listen " + strconv.Quote(listen) +
		" NAMES loopback but does not spell it, and a host name is not accepted as proof of a loopback-only bind: deciding one would mean resolving it at startup, which lets whoever answers the resolver choose this gateway's security posture. Write the address instead — 127.0.0.1 or [::1] — if the bind really is loopback-only"
}

// loopbackNumericHint covers a bind written in one of inet_aton's numeric
// spellings of a loopback address.
//
// It is a separate sentence because the operator's mistake is a different one:
// they did write an address, and it does mean 127.0.0.1 to a C resolver. What
// they may not know is that Go will not parse it as a literal, so net.Listen
// treats it exactly as it treats a name — which is why this package cannot
// treat it as proof of anything.
func loopbackNumericHint(listen string) string {
	host, _ := splitHostPortLenient(listen)
	h := bareHost(host)
	if net.ParseIP(h) != nil {
		return ""
	}
	ip, ok := parseIPv4Numeric(h)
	if !ok || !ip.IsLoopback() {
		return ""
	}
	return "listen " + strconv.Quote(listen) + " is an inet_aton spelling of " + ip.String() +
		", which Go does not parse as an address literal: net.Listen hands it to the platform resolver — hosts file and DNS included — so what this bind actually opens is a resolver's answer rather than anything decidable from the config text, and it is refused as proof of a loopback-only bind for the same reason a name is. Write the address in full — 127.0.0.1 — if the bind really is loopback-only. (A CGO_ENABLED=0 build, which is every container image here, does not read this as an address at all — it looks the string up as a name — so this spelling would fail to bind rather than reach loopback.)"
}

// splitHostPortLenient splits "host:port", tolerating the empty host that
// net.SplitHostPort accepts (":14443") and returning the raw string as the host
// when there is no port at all.
func splitHostPortLenient(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, ""
}

// connectSelfReference reports why an allowed_hosts entry names the gateway
// itself, or "" if it does not. host and port are the entry's parts; listen is
// Config.Listen.
//
// The rule has two shapes because the risk does:
//
//   - Bind is NOT loopback-only. Every local target is refused, whatever its
//     port. The gateway is reachable from other hosts, so a tunnel to any local
//     service is the gateway lending its network position to a remote caller —
//     and a tunnel to its OWN port is additionally the laundering path that
//     turns the CONNECT token into the gateway token.
//   - Bind IS loopback-only. Only the gateway's own port is refused. Every
//     CONNECT client is already a local process, so a tunnel to loopback hands
//     it nothing it could not open itself; there is no privilege to escalate.
//     What remains refused is the gateway dialling its own socket, which is a
//     loop rather than an escalation, and which nobody configures on purpose.
//
// The third shape is the gateway's own ROUTABLE address written out ("listen:
// 10.0.0.5:14443" with "10.0.0.5:<anything>" allowlisted). That is the local
// machine as certainly as 127.0.0.1 is, and is refused on any port.
//
// What this does NOT decide, stated plainly: a wildcard bind ("0.0.0.0:14443")
// plus one of the machine's own routable addresses ("10.0.0.5:14443") is not
// distinguishable here from a legitimate neighbour, because deciding it would
// mean enumerating the host's interfaces at validation time — an answer that is
// stale the moment an address is added. Nor can any NAME be decided without a
// resolver. Both gaps are covered at dial time by connectDialRefusal.
func connectSelfReference(host, port, listen string) string {
	lhost, lport := splitHostPortLenient(listen)
	if kind := localTargetKind(host); kind != "" {
		if isLoopbackListen(listen) {
			if port == lport && port != "" {
				return "names " + kind + " on the gateway's own listen port, so the gateway would tunnel into its own socket"
			}
			return ""
		}
		why := "names " + kind + ", and listen " + strconv.Quote(listen) +
			" is not loopback-only, so the gateway would dial itself: the tunnelled request arrives on the loopback interface and is served as a LOCAL caller, handing a remote holder of the connect token the gateway_auth loopback exemption"
		if hint := loopbackListenHint(listen); hint != "" {
			why += ". " + hint
		}
		return why
	}
	if lhost != "" && localTargetKind(lhost) == "" && sameHost(host, lhost) {
		return "names the gateway's own listen address " + strconv.Quote(listen) +
			", so the gateway would dial itself and serve the tunnelled request as a local caller"
	}
	return ""
}

// connectDialRefusal is the second layer, and the only one that can see where a
// NAME actually pointed.
//
// It runs after the dial and before any byte is copied, so an allowlist entry
// whose A record is 127.0.0.1 — or whose answer changed after startup — is
// refused even though the config text was undecidable. It reads the socket the
// kernel actually opened and no header, so nothing a caller sends can influence
// it.
//
// It is skipped entirely on a loopback-only bind, for the reason
// connectSelfReference gives: there is no remote caller to launder, and a
// tunnel to a loopback service is the ordinary, intended use on such a
// deployment (it is also what the existing end-to-end tunnel test exercises).
//
// The two refusals:
//
//   - a loopback or unspecified peer is this machine, decided outright.
//   - a peer whose address equals our own end of the same socket is this
//     machine too: dialling one of the host's own addresses is routed over the
//     loopback interface with the source address equal to the destination. This
//     branch is what covers the wildcard-bind case connectSelfReference cannot
//     decide. It cannot produce a false refusal — if the far end of a socket
//     has our source address, the far end IS us — but note that the routing
//     behaviour it relies on is asserted from the platform's semantics, not
//     proven by a test in CI, which cannot bind a second routable address.
func connectDialRefusal(listen string, local, remote net.Addr) string {
	if isLoopbackListen(listen) {
		return ""
	}
	rip := addrIP(remote)
	if rip == nil {
		return ""
	}
	if rip.IsLoopback() || rip.IsUnspecified() {
		return "target_resolves_to_loopback"
	}
	if lip := addrIP(local); lip != nil && lip.Equal(rip) {
		return "target_resolves_to_gateway_host"
	}
	return ""
}

// addrIP extracts the IP from a net.Addr, or nil when it carries none.
func addrIP(a net.Addr) net.IP {
	if a == nil {
		return nil
	}
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP
	}
	host, _ := splitHostPortLenient(a.String())
	return net.ParseIP(bareHost(host))
}
