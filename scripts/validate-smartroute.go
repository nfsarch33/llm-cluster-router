//go:build ignore

// Standalone validator: proves the SHIPPED example policy loads and routes
// as documented. Run with: go run scripts/validate-smartroute.go
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/nfsarch33/llm-cluster-router/internal/smartroute"
)

func main() {
	path := "configs/smartroute.example.yml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	p, err := smartroute.LoadPolicy(path)
	if err != nil {
		fmt.Println("LOAD_FAIL:", err)
		os.Exit(1)
	}
	r := smartroute.NewRouter(p)
	req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	cases := []struct{ name, body string }{
		{"code", `{"model":"auto","messages":[{"role":"user","content":"func main() {}"}]}`},
		{"chat", `{"model":"auto","messages":[{"role":"user","content":"hello there"}]}`},
		{"explicit", `{"model":"gpt-4o","messages":[{"role":"user","content":"func x"}]}`},
		{"summarise", `{"model":"auto","messages":[{"role":"user","content":"tl;dr this"}]}`},
	}
	fail := 0
	for _, tc := range cases {
		d, err := r.Decide(req, []byte(tc.body))
		if err != nil {
			fmt.Println("DECIDE_FAIL:", tc.name, err)
			fail++
			continue
		}
		out, err := r.Rewrite([]byte(tc.body), d)
		if err != nil {
			fmt.Println("REWRITE_FAIL:", tc.name, err)
			fail++
			continue
		}
		fmt.Printf("%-10s class=%-13s model=%-18s tier=%-7s source=%-15s body=%dB\n",
			tc.name, d.Class, d.Model, d.Tier, d.Source, len(out))
	}
	if fail > 0 {
		os.Exit(1)
	}
	fmt.Println("example policy OK")
}
