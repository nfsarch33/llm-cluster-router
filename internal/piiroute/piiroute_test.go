package piiroute

import "testing"

// The gherkin's classes, each with a realistic payload shape: names in
// order data, addresses, emails, Australian phones, enquiries. A clean
// system prompt or a code body must NOT trip the rule.
func TestDetectPersonal(t *testing.T) {
	personal := map[string]string{
		"email":     `Send the invoice to sarah.chen@example.com.au please`,
		"au mobile": `Customer called back on 0412 345 678 about the order`,
		"au land":   `Ring the shop on (02) 9876 5432 before noon`,
		"address":   `Ship to 42 Wattle Street, Bendigo VIC 3550`,
		"postcode":  `Delivery region: NSW 2000 metro only`,
		"order id":  `Order #A-10493 for the merino beanie has shipped`,
		"enquiry":   `Hi team, my name is Dana and my address is 8/12 King St`,
	}
	for class, body := range personal {
		if !DetectPersonal([]byte(body)) {
			t.Errorf("%s payload must be personal: %q", class, body)
		}
	}
	notPersonal := map[string]string{
		"system prompt": `You are a shop assistant. Draft a warm product description for a merino beanie. Use Australian spelling.`,
		"code":          `func main() { fmt.Println("order of operations") }`,
		"model talk":    `Summarise the quarterly order flow trends by category.`,
	}
	for class, body := range notPersonal {
		if DetectPersonal([]byte(body)) {
			t.Errorf("%s payload must NOT be personal: %q", class, body)
		}
	}
}

// The named mutant's kill: a mutant that sends a personal payload to a
// cloud endpoint. PersonalBlocks is the selection predicate the router
// applies; the mutant (rule inverted or dropped) fails the cloud rows.
func TestPersonalNeverClouds(t *testing.T) {
	type node struct {
		name  string
		local bool
	}
	nodes := []node{
		{"local-qwen", true},
		{"cloud-m3", false},
		{"cloud-alt", false},
	}
	personal := true
	var served []string
	for _, n := range nodes {
		if !PersonalBlocks(personal, n.local) {
			served = append(served, n.name)
		}
	}
	if len(served) != 1 || served[0] != "local-qwen" {
		t.Fatalf("a personal payload may only ever be served by the local node, got %v", served)
	}
	// The rule adds a constraint, never a privilege: non-personal
	// payloads keep every node.
	var open []string
	for _, n := range nodes {
		if !PersonalBlocks(false, n.local) {
			open = append(open, n.name)
		}
	}
	if len(open) != 3 {
		t.Fatalf("a non-personal payload must keep all nodes, got %v", open)
	}
}
