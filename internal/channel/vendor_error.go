package channel

import (
	"bytes"
	"strconv"
	"time"
)

// Vendor error classification for MiniMax-family upstreams.
//
// WHY THIS EXISTS. The reverse-proxy leg used to decide "this key's plan is
// spent" from the HTTP status alone (429 or 402). That conflates three failures
// that need opposite handling, and MiniMax-family upstreams routinely report
// all of them in the BODY — often alongside HTTP 200 — as
// `base_resp.status_code`:
//
//   - 1002 "rate limit" is a burst (RPM/TPM) problem. Parking the key for a
//     whole accounting window over a momentary burst removes a funded plan from
//     rotation for hours.
//   - 2056 "usage limit exceeded" IS the plan cap, and its official remedy is
//     to wait for the next 5-hour window. Giving it the short default cooldown
//     means re-selecting a key that cannot serve, burning the pool.
//   - 1008 "insufficient balance" needs a human. It is also documented
//     returning false positives at 0% usage, so it must NOT permanently remove
//     a key; it parks briefly and pages instead.
//
// Codes that describe the REQUEST (1039 token limit, 2013 invalid params) or
// the CREDENTIAL (1004, 2049) must never retire a key: retiring on those hides
// a configuration bug behind a rotation that silently drains the pool.
//
// Source of truth: platform.minimax.io/docs/api-reference/errorcode.

// VendorClass is what an upstream vendor error code means for KEY SELECTION,
// which is a different question from what it means for the caller.
type VendorClass string

const (
	// VendorNone means no vendor code was found in the observed body.
	VendorNone VendorClass = ""
	// VendorTransient is an upstream hiccup: retry later, keep the key.
	VendorTransient VendorClass = "transient"
	// VendorRateLimited is a burst limit (requests, tokens or connections per
	// unit time). The plan is NOT spent; back the key off briefly.
	VendorRateLimited VendorClass = "rate"
	// VendorQuotaWindow is the plan cap for the accounting window. The key
	// cannot serve again until the window resets.
	VendorQuotaWindow VendorClass = "quota"
	// VendorBalance is an account balance/entitlement signal. It needs a human,
	// and it is unreliable enough that it parks rather than removes.
	VendorBalance VendorClass = "balance"
	// VendorRequest means the caller's request is malformed or oversized. The
	// key is healthy; retrying the same bytes will fail identically.
	VendorRequest VendorClass = "request"
	// VendorAuth means the credential is wrong. Retiring would hide it.
	VendorAuth VendorClass = "auth"
)

// Cooldowns applied per class. These are deliberately different from
// DefaultQuotaCooldown, which remains the fallback when no vendor code is
// present and the route declares no accounting window.
const (
	// VendorRateCooldown parks a burst-limited key just long enough for the
	// next selection to prefer a sibling. It is seconds, not minutes: the plan
	// is not spent and the key is expected back immediately.
	VendorRateCooldown = 30 * time.Second

	// VendorBalanceCooldown bounds how long an "insufficient balance" key stays
	// out. Bounded rather than permanent because the signal is documented
	// returning false positives at 0% usage; an alert carries the urgency
	// instead of an unbounded park.
	VendorBalanceCooldown = 15 * time.Minute

	// VendorQuotaFallbackWindow is used for a plan-cap signal that names no
	// reset time and whose route declares no accounting window. It matches the
	// 5-hour rolling window MiniMax documents for Token Plan quota.
	VendorQuotaFallbackWindow = 5 * time.Hour
)

// VendorSignal is a parsed vendor error observed on a proxied response.
type VendorSignal struct {
	// Code is the vendor's own status code (base_resp.status_code).
	Code int
	// Class is what Code means for key selection.
	Class VendorClass
	// ResetAt is when the vendor said the limit clears, when the payload named
	// a time. Zero otherwise — callers must fall back to a configured window.
	ResetAt time.Time
}

// Retires reports whether this signal should take the key out of rotation.
// Request and auth failures deliberately do not: the key is fine.
func (v VendorSignal) Retires() bool {
	switch v.Class {
	case VendorRateLimited, VendorQuotaWindow, VendorBalance:
		return true
	default:
		return false
	}
}

// Reason maps the class onto the rotation store's retire reason, so the
// existing per-reason metric and audit vocabulary keep working.
func (v VendorSignal) Reason() RetireReason {
	switch v.Class {
	case VendorRateLimited:
		return ReasonRateLimit
	case VendorBalance:
		return ReasonBalance
	case VendorQuotaWindow:
		return ReasonQuota
	default:
		return ReasonError
	}
}

// classifyVendorCode maps a MiniMax-family status code onto its selection
// meaning. Unknown codes are VendorNone so an unrecognised value never silently
// retires a working key.
func classifyVendorCode(code int) VendorClass {
	switch code {
	case 0:
		return VendorNone // success
	case 1002, 1041, 2045:
		// 1002 rate limit (RPM/TPM), 1041 conn limit (concurrency),
		// 2045 rate growth limit. All burst-shaped; the plan is not spent.
		return VendorRateLimited
	case 2056:
		// "usage limit exceeded" — the plan cap for the window.
		return VendorQuotaWindow
	case 1008:
		return VendorBalance
	case 1004, 2049:
		return VendorAuth
	case 1039, 2013, 1026, 1027, 1042:
		// 1039 token limit is a per-request context/generation cap, not a plan
		// cap: the official advice is "retry later", but retrying the same
		// oversized request fails identically, and the KEY is healthy.
		return VendorRequest
	case 1000, 1001, 1024, 1033:
		return VendorTransient
	default:
		return VendorNone
	}
}

var (
	baseRespMarker  = []byte(`"base_resp"`)
	statusCodeField = []byte(`"status_code"`)
)

// parseVendorSignal extracts a vendor error from an observed response tail.
//
// It scans for base_resp.status_code, preferring the LAST base_resp in the tail
// so a streamed body's final frame wins. The tail is the same rolling window
// the usage extractor already keeps, so this costs no additional buffering and
// cannot interfere with streaming.
func parseVendorSignal(tail []byte) (VendorSignal, bool) {
	if len(tail) == 0 {
		return VendorSignal{}, false
	}
	// Prefer a status_code that follows a base_resp marker; fall back to the
	// last bare status_code, which is the shape some error envelopes use.
	search := tail
	if at := bytes.LastIndex(tail, baseRespMarker); at >= 0 {
		search = tail[at:]
	}
	at := bytes.Index(search, statusCodeField)
	if at < 0 {
		if at = bytes.LastIndex(tail, statusCodeField); at < 0 {
			return VendorSignal{}, false
		}
		search = tail
	}
	code, ok := parseIntAfter(search[at+len(statusCodeField):])
	if !ok {
		return VendorSignal{}, false
	}
	class := classifyVendorCode(code)
	if class == VendorNone {
		return VendorSignal{Code: code}, false
	}
	return VendorSignal{Code: code, Class: class, ResetAt: parseResetAt(search)}, true
}

// parseIntAfter reads the first integer following a JSON field name, skipping
// the colon and any whitespace. It tolerates the value being negative.
func parseIntAfter(b []byte) (int, bool) {
	i := 0
	for i < len(b) && (b[i] == ':' || b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r' || b[i] == '"') {
		i++
	}
	start := i
	if i < len(b) && b[i] == '-' {
		i++
	}
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == start {
		return 0, false
	}
	n, err := strconv.Atoi(string(b[start:i]))
	if err != nil {
		return 0, false
	}
	return n, true
}

var resetMarkers = [][]byte{
	[]byte(`"reset_at"`), []byte(`"reset_time"`), []byte(`"reset"`),
	[]byte(`"next_reset_time"`), []byte(`"recovery_time"`),
}

// parseResetAt best-effort extracts a reset instant a quota payload may name.
//
// BEST EFFORT ON PURPOSE. A live 2056 payload is reported to carry a reset
// timestamp, but its exact field name and encoding are not documented, so this
// accepts several field names and both epoch seconds and epoch milliseconds,
// and returns the zero time when it recognises nothing. A zero return is not a
// failure: the caller falls back to the route's accounting window, which is the
// behaviour that existed before this parser. It never invents a time.
func parseResetAt(b []byte) time.Time {
	for _, m := range resetMarkers {
		at := bytes.Index(b, m)
		if at < 0 {
			continue
		}
		n, ok := parseIntAfter(b[at+len(m):])
		if !ok || n <= 0 {
			continue
		}
		// Discriminate seconds from milliseconds by magnitude: epoch seconds
		// stay below 10^11 until the year 5138.
		var t time.Time
		if n > 100000000000 {
			t = time.UnixMilli(int64(n))
		} else {
			t = time.Unix(int64(n), 0)
		}
		// Ignore a timestamp that is not in the future: a stale or misparsed
		// value must not shorten a cooldown to nothing.
		if t.After(time.Now()) {
			return t
		}
	}
	return time.Time{}
}

// vendorRetireUntil computes when a key retired for this signal may serve
// again. windowEnd is the route's accounting-window end when it declares one
// (zero otherwise), and is preferred over the fallback for a plan cap.
func vendorRetireUntil(v VendorSignal, now, windowEnd time.Time) time.Time {
	switch v.Class {
	case VendorRateLimited:
		return now.Add(VendorRateCooldown)
	case VendorBalance:
		return now.Add(VendorBalanceCooldown)
	case VendorQuotaWindow:
		// The vendor's own reset time is the most accurate answer available.
		if !v.ResetAt.IsZero() && v.ResetAt.After(now) {
			return v.ResetAt
		}
		if windowEnd.After(now) {
			return windowEnd
		}
		return now.Add(VendorQuotaFallbackWindow)
	default:
		return time.Time{}
	}
}
