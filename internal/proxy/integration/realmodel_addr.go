//go:build realmodel

package integration

import (
	"os"
	"strings"
)

// lightsailSSHAddr returns the SSH-22 dynamic-port-forward endpoint that the
// realmodel test will use as its SOCKS5 server. The endpoint is resolved
// from env vars in priority order:
//
//	REALMODEL_LIGHTSAIL_SOCKS5  -- explicit override (e.g. "127.0.0.1:1080")
//	LLM_ROUTER_LIGHTSAIL_HOST   -- SSH host alias (resolves to "127.0.0.1:1080"
//	                               unless SSH_DYNAMIC_PORT is also set)
//	SSH_DYNAMIC_PORT            -- port the test rig put an SSH -D on (default 1080)
//
// If none are set the helper returns a false-y empty string and the test is
// expected to SKIP (per ADR-083 C4). No hostnames or IPs are ever baked in
// (per no-shell-leak Cat 2; the live config comes from
// ~/.config/runx/hosts.yaml + ~/.ssh/config.d/).
func lightsailSSHAddr() string {
	if v := strings.TrimSpace(os.Getenv("REALMODEL_LIGHTSAIL_SOCKS5")); v != "" {
		return v
	}
	host := strings.TrimSpace(os.Getenv("LLM_ROUTER_LIGHTSAIL_HOST"))
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(os.Getenv("SSH_DYNAMIC_PORT"))
	if port == "" {
		port = "1080"
	}
	return "127.0.0.1:" + port
}

// upstreamHTTPSAddr returns the upstream LLM HTTPS endpoint that the test will
// dial through the SSH-22 SOCKS5 tunnel. Default is the Aliyun DashScope
// OpenAI-compatible chat completions endpoint, which is reachable from the
// Lightsail Sydney instance (ap-southeast-2). The v18710-3 plan originally
// named minimaxi M3; the operator-provided 1Password item for this sprint is
// the Aliyun Qwen key, so the upstream is dashscope.aliyuncs.com. The
// upstream URL can be overridden via UPSTREAM_HTTPS_ADDR env var.
func upstreamHTTPSAddr() string {
	if v := strings.TrimSpace(os.Getenv("UPSTREAM_HTTPS_ADDR")); v != "" {
		return v
	}
	return "dashscope.aliyuncs.com:443"
}

// upstreamModel returns the LLM model name to invoke. Default is the Aliyun
// Qwen Turbo model (qwen-turbo). Override via UPSTREAM_MODEL env var.
func upstreamModel() string {
	if v := strings.TrimSpace(os.Getenv("UPSTREAM_MODEL")); v != "" {
		return v
	}
	return "qwen-turbo"
}
