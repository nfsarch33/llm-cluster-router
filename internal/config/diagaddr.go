package config

import "net"

// LoopbackHost is the interface a host-less diagnostic listen address
// resolves to.
const LoopbackHost = "127.0.0.1"

// DefaultMetricsAddr is where the Prometheus exposition listener binds
// when metrics_addr is omitted. Loopback, because the scrape is local to
// the router host; an operator who needs it reachable from elsewhere says
// so with an explicit host (see DiagnosticListenAddr).
const DefaultMetricsAddr = LoopbackHost + ":9091"

// DiagnosticListenAddr resolves the listen address of a diagnostic
// listener -- the Prometheus exposition endpoint (metrics_addr) and the
// net/http/pprof debug endpoint (debug_addr) -- so that a HOST-LESS
// spelling binds loopback instead of every interface.
//
//	""                -> ""                (caller decides: disabled, or a default)
//	":6060"           -> "127.0.0.1:6060"  (a port choice, not an interface choice)
//	"0.0.0.0:6060"    -> "0.0.0.0:6060"    (an explicit, deliberate opt-out)
//	"[::]:6060"       -> "[::]:6060"       (likewise)
//	"10.0.0.5:9091"   -> "10.0.0.5:9091"   (likewise)
//
// The distinction it draws is between a port and an interface. `:6060` is
// what an operator writes when they are choosing a PORT; Go's listener
// then reads the empty host as "every interface", which is a decision
// nobody made. These two listeners are the reason that matters: pprof
// serves heap and goroutine dumps plus a CPU-profile endpoint that blocks
// for its whole duration, and the metrics surface describes the fleet --
// neither sits behind the bearer middleware that guards /v1/*, so on a
// wildcard bind every LAN and tailnet peer holds them. Reading the
// missing host as loopback makes the DEFAULT safe while leaving the
// choice available: an operator who genuinely wants a wildcard bind spells
// it 0.0.0.0 or ::, and gets it.
//
// An address that does not parse as host:port is returned unchanged, so
// this never turns a misconfiguration into a different misconfiguration
// -- ListenAndServe reports it exactly as it does today.
func DiagnosticListenAddr(addr string) string {
	if addr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host != "" {
		return addr
	}
	return net.JoinHostPort(LoopbackHost, port)
}
