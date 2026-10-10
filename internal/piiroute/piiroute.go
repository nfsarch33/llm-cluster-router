// Package piiroute enforces the PII-local routing rule: a request whose
// body carries personal information (names in orders, addresses, emails,
// Australian phone numbers, customer enquiries) is served ONLY by nodes
// marked pii_local in the router config — the local hardware. Cloud
// nodes never receive a personal payload; when no pii-local node can
// serve the request the router refuses it (fail closed) rather than
// spill. The detector is deliberately cheap and explainable: a handful
// of deterministic shapes, conservative in the safe direction (a
// false positive routes local; a false negative is the risk the tests
// pin shut).
package piiroute

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	// The local part admits a literal quote: JSON-escaped bodies carry
	// user\"@example.com, and the decoded pass must match it too.
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+\-\"]+@[a-z0-9.-]+\.[a-z]{2,}`)
	// Australian phone shapes, each branch with its own row in the
	// tests: mobiles 04xx xxx xxx and the +61 international mobile form
	// (+61 412 345 678, spaces/dashes optional); landlines (02) 9876
	// 5432, 02 9876 5432 bare, and 0298765432 compact (4+4 digits).
	// Phones: separators may be spaces, dashes OR dots (0412.345.678).
	auPhoneRe = regexp.MustCompile(`(?:\+61[\s.-]?4\d{2}[\s.-]?\d{3}[\s.-]?\d{3}|\b04\d{2}[\s.-]?\d{3}[\s.-]?\d{3}|(?:\+61[\s.-]?|\(0[2-8]\)[\s.-]?|\b0[2378][\s.-]?)\d{4}[\s.-]?\d{4})`)
	// Card PANs and TFNs match as CANDIDATE digit runs first and are
	// confirmed by CHECKSUM (Luhn for cards, the ATO weighted sum for
	// TFNs): an epoch-ms timestamp or a byte count is digits but never a
	// valid PAN/TFN, and routine agent traffic carries such numbers
	// constantly (round-3 finding). Without a card/TFN keyword nearby,
	// only GROUPED runs (with separators) count — bare unseparated
	// digit runs stay ordinary numbers.
	cardCandidateRe = regexp.MustCompile(`\b(?:\d[\s.-]?){12,19}\b|\b\d{3}[\s]?\d{3}[\s]?\d{3}\b|\b\d{2}[\s]?\d{3}[\s]?\d{3}\b`)
	cardKeywordRe   = regexp.MustCompile(`(?i)\b(card|visa|mastercard|amex|pan|payment)\b`)
	tfnKeywordRe    = regexp.MustCompile(`(?i)\b(tfn|tax[[:space:]]+file)\b`)
	// Address shapes: a number + street word, or an AU state + 4-digit
	// postcode tail.
	addressRe  = regexp.MustCompile(`(?i)\b\d{1,4}\s+[A-Z][a-z]+\s(st|street|rd|road|ave|avenue|dr|drive|ln|lane|ct|court|blvd|parade|pde)\b`)
	postcodeRe = regexp.MustCompile(`(?i)\b(NSW|VIC|QLD|WA|SA|TAS|NT|ACT)\s+\d{4}\b`)
	// Order data: an order/reference id with a name-like possessive or a
	// "ship to / billing" block — the shapes merchant payloads carry.
	// The case-INSENSITIVE flag is scoped to the keyword only: the id
	// token stays case-SENSITIVE (uppercase/digits), so "order number
	// trends" is talk and "Order #A-10493" is data. A leading (?i) over
	// the whole pattern made [A-Z0-9] match lowercase words (round-1
	// finding) — (?i:order) keeps the token strict.
	orderRe = regexp.MustCompile(`(?i:order)[\s#:-]*(?:(?i:id|no|number)|#)\s*[:#-]?\s*[A-Z0-9][A-Z0-9-]{3,}`)
	// Enquiry: a named greeting beside contact detail markers.
	enquiryRe = regexp.MustCompile(`(?i)\b(dear|hi|hello|to whom)\b[^.]{0,60}\b(my (name|address|phone|email) is)\b`)
)

// DetectPersonal reports whether the request body carries a personal
// information shape. Callers classify before any smartroute rewrite.
// The body is scanned as-is AND with its JSON string values decoded:
// an e-mail split across JSON escapes (user\"@example.com) or nested
// one level deep (messages[].content) must not slip past.
func DetectPersonal(body []byte) bool {
	s := string(body)
	if matchesAny(s) {
		return true
	}
	for _, decoded := range decodeJSONStrings(body) {
		if matchesAny(decoded) {
			return true
		}
	}
	return false
}

func matchesAny(s string) bool {
	if emailRe.MatchString(s) ||
		auPhoneRe.MatchString(s) ||
		addressRe.MatchString(s) ||
		postcodeRe.MatchString(s) ||
		orderRe.MatchString(s) ||
		enquiryRe.MatchString(s) {
		return true
	}
	return panOrTFN(s)
}

// panOrTFN confirms card/TFN candidates by checksum, with the
// keyword-or-grouping rule from the comment above.
func panOrTFN(s string) bool {
	cardCtx := cardKeywordRe.MatchString(s)
	tfnCtx := tfnKeywordRe.MatchString(s)
	for _, m := range cardCandidateRe.FindAllString(s, -1) {
		digits := keepDigits(m)
		grouped := strings.ContainsAny(m, " .-")
		switch {
		case len(digits) == 9 && tfnValid(digits):
			if tfnCtx || grouped {
				return true
			}
		case len(digits) >= 13 && luhnValid(digits):
			if cardCtx || grouped {
				return true
			}
		}
	}
	return false
}

func keepDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhnValid is the mod-10 checksum every card PAN carries.
func luhnValid(digits string) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// tfnValid is the ATO weighted checksum (1,4,3,7,5,8,6,9,2; sum % 11 == 0).
func tfnValid(digits string) bool {
	if len(digits) != 9 {
		return false
	}
	w := [9]int{1, 4, 3, 7, 5, 8, 6, 9, 2}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(digits[i]-'0') * w[i]
	}
	return sum%11 == 0
}

// decodeJSONStrings walks ONE nesting level of a JSON body and returns
// every string value found on objects and arrays (recursively for
// nested containers, bounded by the encoding/json parser itself). This
// is where a payload hides an address inside
// {"messages":[{"content":"..."}]}.
func decodeJSONStrings(body []byte) []string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

// PersonalBlocks is the selection-time predicate: true when this
// request must NOT go to the given node. A personal request blocks
// every node not marked pii-local; a non-personal request blocks
// nothing (the rule adds a constraint, never a privilege).
func PersonalBlocks(personal, nodePIILocal bool) bool {
	return personal && !nodePIILocal
}

// RuleArmed is the arming policy over the configured rule mode:
//
//	auto (empty) — armed only when at least one node carries
//	               pii_local: true; a config without a marked node
//	               routes exactly as before the rule existed.
//	enforce      — armed ALWAYS; with no marked node personal payloads
//	               are REFUSED (fail closed), never routed to a cloud.
//	off          — detection stays observability-only.
func RuleArmed(mode string, anyNodePIILocal bool) bool {
	switch mode {
	case "enforce":
		return true
	case "off":
		return false
	default: // "" or "auto"
		return anyNodePIILocal
	}
}
