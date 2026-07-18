// Package router — minimax live pilot wire-up (v18688-1).
//
// This file implements the deterministic URL/auth builders for the
// minimax live pilot. The router's main() loop reads
// configs/router.minimax.live.yml and uses these helpers to format
// each request before proxying to api.minimaxi.com (the canonical
// international base path).
//
// Design constraints (per harness-engineering-defaults.mdc):
//   - Pure functions only; no goroutines, no IO.
//   - Zero allocation when auth is empty (per sentrux-always.mdc).
//   - URL builders are deterministic and side-effect-free, so the
//     RED tests can assert exact strings without race detection.
package router

import (
	"errors"
	"net/url"
	"strings"
)

// MinChatBase is the live pilot's canonical base URL.
// This MUST stay `api.minimaxi.com/v1` per the plan; api.minimax.io
// is the international host and is forbidden for personal-stack use
// (see deprecation-semble-check.mdc, "minimax international").
const MinChatBase = "https://api.minimaxi.com/v1"

// MinChatCompletionPath is the chat-completion v2 path used by the
// router to proxy OpenAI-compatible requests.
const MinChatCompletionPath = "/text/chatcompletion_v2"

// ErrMinEmptyAPIKey signals that no Bearer token was supplied.
// The router treats this as a 502 (upstream not configured), not 401.
var ErrMinEmptyAPIKey = errors.New("minimax api key is empty")

// ErrMinForbiddenHost guards against accidental use of a forbidden
// international host (api.minimax.io, api.minimax.com). The router
// surfaces this as a config-time error.
var ErrMinForbiddenHost = errors.New("minimax base URL is on a forbidden host")

// forbiddenMinimaxBases is the canonical deny-list for the URL builder.
// Keep in sync with TestMinChat_RejectsForbiddenURL below and
// deprecation-semble-check.mdc.
var forbiddenMinimaxBases = []string{
	"https://api.minimax.io/v1",
	"https://api.minimax.com/v1",
}

// MinChatURL builds the full URL the router dials. The base argument
// MUST equal MinChatBase; any value matching forbiddenMinimaxBases
// returns ErrMinForbiddenHost.
//
// Examples:
//
//	MinChatURL(MinChatBase) → "https://api.minimaxi.com/v1/text/chatcompletion_v2"
//	MinChatURL("https://api.minimax.io/v1") → ErrMinForbiddenHost
func MinChatURL(base string) (string, error) {
	for _, bad := range forbiddenMinimaxBases {
		if base == bad {
			return "", ErrMinForbiddenHost
		}
	}
	if base == "" {
		base = MinChatBase
	}
	if base != MinChatBase {
		return "", ErrMinForbiddenHost
	}
	u, err := url.JoinPath(base, strings.TrimPrefix(MinChatCompletionPath, "/"))
	if err != nil {
		return "", err
	}
	return u, nil
}

// MinChatAuthorizationHeader builds the `Authorization` header value
// from a non-empty API key. Empty keys return ErrMinEmptyAPIKey;
// the router must not silently inject an empty Bearer token.
func MinChatAuthorizationHeader(apiKey string) (string, error) {
	if strings.TrimSpace(apiKey) == "" {
		return "", ErrMinEmptyAPIKey
	}
	return "Bearer " + strings.TrimSpace(apiKey), nil
}

// IsMinChatModel returns true if the supplied model id is one the
// minimax live pilot routes accept. This guards against silent
// drift into other model ids when callers pass `MiniMax-M3` vs
// `MiniMax-Text-01`.
func IsMinChatModel(model string) bool {
	switch strings.TrimSpace(model) {
	case "MiniMax-M3", "MiniMax-Text-01", "minimax-M3", "minimax-Text-01":
		return true
	default:
		return false
	}
}
