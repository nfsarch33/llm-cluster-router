package channel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// httpStateNewIdleGrace is net/http's OWN threshold for reclaiming a connection
// that has been accepted but has not yet sent a request header.
//
// http.Server.Shutdown drains by repeatedly closing idle connections, and the
// closeIdleConns it calls counts such a connection as idle only once it is
// older than this (stdlib issue 22682):
//
//	// Issue 22682: treat StateNew connections as if they're idle if we
//	// haven't read the first request's header in over 5 seconds.
//	if st == StateNew && unixSec < time.Now().Unix()-5 { st = StateIdle }
//
// It is hard-coded in the standard library and cannot be configured, so it is a
// floor that every shutdown budget in this package has to clear. It is spelled
// out here so the number below reads as a derivation rather than a guess.
const httpStateNewIdleGrace = 5 * time.Second

// shutdownGrace is how long a graceful drain may take before whatever is left
// is closed outright.
//
// It is DERIVED from httpStateNewIdleGrace rather than written as a literal,
// because the two being EQUAL is precisely the defect this constant exists to
// prevent. Every listener in this package used to shut down with a flat
// `context.WithTimeout(context.Background(), 5*time.Second)` -- the same five
// seconds -- so a connection that was accepted and then said nothing could not
// be reclaimed before the budget expired. Shutdown returned
// context.DeadlineExceeded, that error was propagated to the caller unchanged,
// and `helixchannel gateway` therefore exited NON-ZERO on an ordinary SIGTERM.
//
// Measured 2026-09-06 against the old code. One connection, varying ONLY its
// age at the moment shutdown began:
//
//	no connection at all                     ->  0s, nil
//	one silent connection, just opened       ->  5s, context deadline exceeded
//	the same connection, aged past the 5s    ->  0s, nil
//
// The third row is what identifies the mechanism: the same connection, clean
// once it is old enough. Nothing about the connection blocks shutdown; the
// budget simply expired at the same instant the connection became reclaimable.
//
// Reaching the middle row needs no misbehaving client. A load balancer health
// probe, a connection pool pre-dialling, a client still in its TLS handshake --
// each is accepted before it writes a request header. So this was never a test
// artefact; it is what systemd saw on any stop that coincided with one.
const shutdownGrace = 3 * httpStateNewIdleGrace

// shutdownHTTPServer takes srv down within the package's standard budget and
// always waits for the goroutine running its serve loop to return. serveErr is
// that goroutine's result channel.
func shutdownHTTPServer(srv *http.Server, serveErr <-chan error) error {
	return shutdownHTTPServerWithin(srv, serveErr, shutdownGrace)
}

// shutdownHTTPServerWithin is shutdownHTTPServer with an explicit budget.
//
// The budget is a parameter purely so the forced-close path below can be tested
// in milliseconds instead of shutdownGrace; production callers all go through
// shutdownHTTPServer. It is deliberately NOT a mutable package var: a test that
// lowers a global and forgets to restore it changes the behaviour of every
// other test in the package.
//
// Three properties, in the order they matter:
//
//  1. IT ALWAYS JOINS. Returning while the serve goroutine is still live hands
//     the caller a server it does not own -- the process may exit, or a test may
//     finish, with a listener and its connections still being serviced. The join
//     is cheap on every path, because both Shutdown and Close close the
//     listener, and closing the listener is what makes Serve return.
//
//  2. THE DRAIN IS BOUNDED, AND EXCEEDING THE BOUND IS NOT THE END OF IT. A
//     Shutdown that runs out of budget leaves its remaining connections OPEN:
//     it stops waiting, it does not stop them. Returning at that point left the
//     caller holding a server that could not finish shutting down for exactly
//     the reason its own shutdown had just abandoned. Close() finishes the job,
//     and is also what makes the join in (1) terminate.
//
//  3. THE DEADLINE IS REPORTED, NOT SWALLOWED. A drain that had to be forced is
//     a real event belonging in the journal, so it returns an error saying what
//     happened and how long it waited. Returning nil would make a forced close
//     indistinguishable from a clean one, which is the failure mode this estate
//     keeps rediscovering: an artefact reporting something other than what it
//     did.
func shutdownHTTPServerWithin(srv *http.Server, serveErr <-chan error, budget time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	shutErr := srv.Shutdown(ctx)
	if errors.Is(shutErr, context.DeadlineExceeded) {
		_ = srv.Close()
		shutErr = fmt.Errorf(
			"graceful shutdown did not finish within %s; remaining connections were closed: %w",
			budget, shutErr)
	}

	serr := <-serveErr

	if shutErr != nil {
		return shutErr
	}
	return serr
}
