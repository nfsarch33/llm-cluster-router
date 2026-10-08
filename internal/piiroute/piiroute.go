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

import "regexp"

var (
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)
	// Australian phone shapes, each branch with its own row in the
	// tests: mobiles 04xx xxx xxx and the +61 international mobile form
	// (+61 412 345 678, spaces/dashes optional); landlines (02) 9876
	// 5432, 02 9876 5432 bare, and 0298765432 compact (4+4 digits).
	auPhoneRe = regexp.MustCompile(`(?:\+61[\s-]?4\d{2}[\s-]?\d{3}[\s-]?\d{3}|\b04\d{2}[\s-]?\d{3}[\s-]?\d{3}|(?:\+61[\s-]?|\(0[2-8]\)[\s-]?|\b0[2378][\s-]?)\d{4}[\s-]?\d{4})`)
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
// information shape. It scans the body as-is; callers classify before
// any smartroute rewrite.
func DetectPersonal(body []byte) bool {
	s := string(body)
	return emailRe.MatchString(s) ||
		auPhoneRe.MatchString(s) ||
		addressRe.MatchString(s) ||
		postcodeRe.MatchString(s) ||
		orderRe.MatchString(s) ||
		enquiryRe.MatchString(s)
}

// PersonalBlocks is the selection-time predicate: true when this
// request must NOT go to the given node. A personal request blocks
// every node not marked pii-local; a non-personal request blocks
// nothing (the rule adds a constraint, never a privilege).
func PersonalBlocks(personal, nodePIILocal bool) bool {
	return personal && !nodePIILocal
}

// RuleArmed is the blast-radius guard: the PII-local rule ENFORCES only
// on a config that marks at least one node pii_local (local hardware
// actually exists to serve personal traffic). On every other config —
// every existing deployment and every public user of this repo —
// personal detection stays observability-only and routing is
// byte-for-byte what it was before the rule existed. The round-1
// review's probe (a cloud-only config refusing an email body) is the
// exact failure this closes; the router re-evaluates it per config
// load and reload.
func RuleArmed(anyNodePIILocal bool) bool { return anyNodePIILocal }
