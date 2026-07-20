//go:build realmodel

package integration

import (
	"context"
	"net"

	"github.com/nfsarch33/llm-cluster-router/internal/proxy/socks5"
)

// socks5Dial is a thin wrapper around the project's SOCKS5 client so the
// real-model E2E test exercises the same code path as any other upstream
// integration that uses the llm-cluster-router SOCKS5 listener. If this
// helper ever diverges from `socks5.DialContext`, the v18710-3 commit must
// be re-justified in the PR body.
func socks5Dial(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	return socks5.DialContext(ctx, proxyAddr, target)
}
