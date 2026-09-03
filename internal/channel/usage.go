package channel

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// UsageTailBytes is how many trailing bytes of a response body are retained
// while looking for a usage object.
//
// A TAIL rather than a prefix: OpenAI-compatible providers put "usage" at the
// end of a JSON body and in the final SSE data frame, while the body itself
// may be megabytes. Retaining a fixed tail keeps the gateway's memory ceiling
// independent of what a caller asks the upstream to generate — the same
// property forward.go protects by streaming rather than buffering.
const UsageTailBytes = 8 * 1024

// usageMarker is the only field worth scanning for: every OpenAI-compatible
// provider reports the authoritative figure as usage.total_tokens.
var usageMarker = []byte(`"total_tokens"`)

// UsageExtractor reads a proxied response as it streams past and reports the
// token usage it carried, if any.
type UsageExtractor interface {
	// Observe is called with each chunk of body as it is written to the
	// client. It must not retain b beyond the call.
	Observe(b []byte)
	// Result reports the extracted usage once the body is fully copied.
	// Tokens is TokensUnknown when no usage was found — including when the
	// usage object fell outside the retained tail. That case is an ESTIMATE,
	// never a zero.
	Result() UsageSample
}

// VendorSignaler is an OPTIONAL capability of a UsageExtractor: reporting a
// vendor error code seen in the same observed tail.
//
// It is a separate interface rather than a method on UsageExtractor so that
// third-party extractors keep compiling, and so the caller must opt in with a
// type assertion — an extractor that cannot answer simply leaves the previous
// HTTP-status-only behaviour in place.
//
// Reusing the usage tail is the whole point: MiniMax-family upstreams report
// errors in the body, frequently alongside HTTP 200, and the rolling tail that
// already streams past for token accounting carries base_resp too. Inspecting
// it costs no extra buffering and cannot interfere with streaming.
type VendorSignaler interface {
	VendorSignal() (VendorSignal, bool)
}

// tailExtractor keeps a rolling UsageTailBytes window of the body.
//
// One implementation serves both plain JSON and SSE, because a rolling tail is
// agnostic to chunk boundaries and to whether the frame is wrapped in "data: ".
type tailExtractor struct{ tail []byte }

// NewUsageExtractor returns the default extractor: a rolling UsageTailBytes
// window scanned for the last "total_tokens": N. It also implements
// VendorSignaler over the same window.
func NewUsageExtractor() UsageExtractor { return &tailExtractor{} }

// VendorSignal reports a vendor error code found in the retained tail. It reads
// the same bytes Result does, retains nothing further, and is the optional
// VendorSignaler half of this extractor.
func (e *tailExtractor) VendorSignal() (VendorSignal, bool) { return parseVendorSignal(e.tail) }

func (e *tailExtractor) Observe(b []byte) {
	if len(b) == 0 {
		return
	}
	e.tail = append(e.tail, b...)
	if len(e.tail) > UsageTailBytes {
		// append-over-self is a memmove, so the retained window neither grows
		// nor pins the earlier bytes.
		e.tail = append(e.tail[:0], e.tail[len(e.tail)-UsageTailBytes:]...)
	}
}

func (e *tailExtractor) Result() UsageSample {
	rest := e.tail
	for {
		at := bytes.LastIndex(rest, usageMarker)
		if at < 0 {
			break
		}
		if n, ok := parseUsageValue(rest[at+len(usageMarker):]); ok {
			return UsageSample{Outcome: OutcomeCompleted, Tokens: n}
		}
		rest = rest[:at]
	}
	return UsageSample{Outcome: OutcomeCompleted, Tokens: TokensUnknown, Estimated: true}
}

// parseUsageValue reads `: 1234` following the marker. It requires the digits
// to be followed by a byte that actually ENDS a JSON value, so a number
// truncated by the tail boundary — or one whose digits are merely a prefix of
// something else — is reported as unreadable rather than as a plausible-looking
// short value.
//
// The terminator rule is what stops a fractional total being charged as an
// authoritative integer. `"total_tokens":1.5` scans one digit, and a bare
// "is there a byte after the digits" check accepted the '.' as proof the number
// was complete: the charge became 1, with Estimated FALSE. That combination is
// the worst of both worlds — it under-charges the budget arbitrarily AND
// suppresses leastTokens' degrade-to-request-ordering guard, which only fires
// when a sample is marked estimated. Every other hostile shape (a quoted
// number, a negative, a non-numeric) already failed the digit scan; this one
// did not, so the fix belongs at the terminator.
//
// Unreadable is never zero: the caller demotes a false return to
// Budget.EstimateTokens, which is the documented answer for "the upstream
// reported nothing this gateway can trust".
func parseUsageValue(b []byte) (int64, bool) {
	i := skipSpace(b, 0)
	if i >= len(b) || b[i] != ':' {
		return 0, false
	}
	i = skipSpace(b, i+1)
	start := i
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == start || i == len(b) || !endsJSONValue(b[i]) {
		return 0, false
	}
	n, err := strconv.ParseInt(string(b[start:i]), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// endsJSONValue reports whether c can legally follow a complete JSON number.
// Anything else means the digits scanned were only a PREFIX of the real value.
func endsJSONValue(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// copyResponseObserving streams an upstream response back to the caller,
// preserving status and headers and flushing incrementally so streamed
// completions arrive as they are produced rather than at the end.
//
// The usage extractor is teed off the same buffer, so usage is derived from
// bytes already being copied and no second pass or second allocation of the
// body occurs. A nil ue makes it behave exactly as copyResponse did before
// rotation existed.
func copyResponseObserving(w http.ResponseWriter, resp *http.Response, ue UsageExtractor) (int64, error) {
	for k, vs := range resp.Header {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, canFlush := w.(http.Flusher)
	if !canFlush && ue == nil {
		return io.Copy(w, resp.Body)
	}
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if ue != nil {
				ue.Observe(buf[:n])
			}
			written, werr := w.Write(buf[:n])
			total += int64(written)
			if canFlush {
				flusher.Flush()
			}
			if werr != nil {
				return total, werr
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
