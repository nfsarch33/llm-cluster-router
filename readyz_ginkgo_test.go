//go:build integration

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// Ready is a new pure function on *router introduced by q10b-8. It
// evaluates the canonical readiness contract:
//
//   - At least one upstream must be healthy (healthy_nodes >= 1).
//   - The current queue depth must be at or below MaxQueueDepth.
//   - No breaker on any upstream may currently be Open
//     (otherwise the router would return errors to callers even
//     though /healthz might still claim "ok").
//
// The function returns (ready bool, reason string). The string is
// empty when ready=true; otherwise it explains which gate failed.
// Tests can call Ready() directly without spinning up a real HTTP
// listener; the integration assertion (HTTP status code) is performed
// by TestReadyzHTTPHandler below.
//
// TDD contract (L0 rule 42):
//   - RED: this spec fails to compile on main because Ready does not exist.
//   - GREEN: after the implementation lands, this spec passes.
var _ = ginkgo.Describe("router.Ready", func() {
	// build is a tiny helper that mirrors the production wiring in
	// main_test.go so the readiness decision is exercised against
	// realistic state without needing a real backend.
	build := func(healthy []bool) *router {
		nodes := make([]*upstreamNode, len(healthy))
		for i, h := range healthy {
			u, _ := url.Parse("http://127.0.0.1:1") // never dialed in these tests
			nodes[i] = &upstreamNode{
				cfg: nodeConfig{
					Name: "n-" + string(rune('a'+i)),
					Tier: "edge",
				},
				baseURL: u,
			}
			nodes[i].healthy.Store(h)
		}
		return &router{
			cfg: config{
				Defaults: defaults{
					MaxQueueDepth: 8,
				},
			},
			nodes: nodes,
		}
	}

	ginkgo.When("no upstream is healthy", func() {
		ginkgo.It("reports not-ready with an explicit reason", func() {
			r := build([]bool{false, false})
			ready, reason := r.Ready()
			gomega.Expect(ready).To(gomega.BeFalse())
			gomega.Expect(reason).To(gomega.ContainSubstring("no healthy upstream"))
		})
	})

	ginkgo.When("at least one upstream is healthy", func() {
		ginkgo.It("reports ready with empty reason", func() {
			r := build([]bool{false, true})
			ready, reason := r.Ready()
			gomega.Expect(ready).To(gomega.BeTrue())
			gomega.Expect(reason).To(gomega.BeEmpty())
		})
	})

	ginkgo.When("queue depth has reached the configured ceiling", func() {
		ginkgo.It("reports not-ready with a queue-depth reason", func() {
			r := build([]bool{true})
			r.queueDepth.Store(9) // > MaxQueueDepth (8)
			ready, reason := r.Ready()
			gomega.Expect(ready).To(gomega.BeFalse())
			gomega.Expect(reason).To(gomega.ContainSubstring("queue depth"))
			gomega.Expect(reason).To(gomega.ContainSubstring("9"))
		})
	})
})

// TestReadyzHTTPHandler covers the integration-tier assertion:
// /readyz must surface 200/503 with a JSON body explaining why. This
// is what kubelet / sentrux gates will observe. Lives in the same
// _test.go file because it shares the imports above.
var _ = ginkgo.Describe("router.handleReadyz", func() {
	ginkgo.When("the router reports ready", func() {
		ginkgo.It("responds 200 with ready=true", func() {
			node := &upstreamNode{
				cfg:     nodeConfig{Name: "live", Tier: "edge"},
				baseURL: mustParse("http://127.0.0.1:1"),
			}
			node.healthy.Store(true)
			r := &router{
				cfg:   config{Defaults: defaults{MaxQueueDepth: 4}},
				nodes: []*upstreamNode{node},
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			r.handleReadyz(w, req)
			gomega.Expect(w.Code).To(gomega.Equal(http.StatusOK))
			gomega.Expect(w.Body.String()).To(gomega.ContainSubstring(`"ready":true`))
		})
	})

	ginkgo.When("the router reports not-ready", func() {
		ginkgo.It("responds 503 with reason in JSON", func() {
			r := &router{
				cfg:   config{Defaults: defaults{MaxQueueDepth: 1}},
				nodes: nil, // no upstreams
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			r.handleReadyz(w, req)
			gomega.Expect(w.Code).To(gomega.Equal(http.StatusServiceUnavailable))
			gomega.Expect(w.Body.String()).To(gomega.ContainSubstring(`"ready":false`))
			gomega.Expect(w.Body.String()).To(gomega.ContainSubstring("reason"))
		})
	})
})

// mustParse is a tiny helper that fails the spec if url.Parse fails
// on a literal constant. Lifted out so the spec bodies stay compact.
func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		// Use gomega so the failure surfaces through Ginkgo's reporter.
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "invalid URL %q", s)
	}
	return u
}

// Compile-time assertion: keep the helper above referenced even if
// the spec bodies evolve.
var _ = strings.Contains
