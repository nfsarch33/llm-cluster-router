package channel

import (
	"net/http"
	"strings"
	"unicode"
)

// CallerHeader carries the caller identity (machine/tenant) from the
// ClientProxy to the gateway. It is metadata for the audit stream ONLY:
// nothing authorises on it, and the gateway never trusts it for access
// decisions — the CONNECT token remains the credential.
const CallerHeader = "X-HLXN-Caller"

// maxCallerLen bounds the recorded identity; identities are short host or
// tenant labels, and the bound keeps a hostile or misconfigured client from
// using the field as a log-volume vector.
const maxCallerLen = 64

// SanitiseCaller strips control characters and whitespace noise and
// truncates. Empty input returns "" so omitempty keeps legacy audit lines
// byte-identical.
func SanitiseCaller(in string) string {
	var b strings.Builder
	for _, r := range in {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxCallerLen {
			break
		}
	}
	return b.String()
}

// stampCaller adds the caller-identity header when the proxy has one.
func (c *ClientProxy) stampCaller(req *http.Request) {
	if id := SanitiseCaller(c.CallerID); id != "" {
		req.Header.Set(CallerHeader, id)
	}
}
