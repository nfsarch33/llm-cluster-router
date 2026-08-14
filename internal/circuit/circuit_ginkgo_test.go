//go:build integration

package circuit_test

import (
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/nfsarch33/llm-cluster-router/internal/circuit"
)

// BreakerStats is a new API introduced by q10b-1. The Ginkgo spec is
// RED on main (no implementation), GREEN once the method is added to
// circuit.Breaker.
//
// TDD contract (L0 rule 42):
//   - RED: this spec fails to compile on main because Stats does not exist.
//   - GREEN: after the implementation lands, this spec passes.
//
// Spec design rationale: Stats returns an immutable snapshot of the
// breaker's current health so dashboards can render it without taking
// the breaker mutex. Fields cover the classic three-state breaker
// telemetry: current state, consecutive failure count, threshold,
// cooldown remaining, and node name.
var _ = ginkgo.Describe("circuit.Breaker Stats", func() {
	var (
		cb *circuit.Breaker
	)

	ginkgo.BeforeEach(func() {
		cb = circuit.NewBreaker(3, 30*time.Second).WithName("node-a")
	})

	ginkgo.When("the breaker is freshly constructed", func() {
		ginkgo.It("reports state=closed with zero consecutive failures", func() {
			stats := cb.Stats()
			gomega.Expect(stats.State).To(gomega.Equal(circuit.Closed))
			gomega.Expect(stats.ConsecutiveFailures).To(gomega.Equal(0))
			gomega.Expect(stats.Threshold).To(gomega.Equal(3))
			gomega.Expect(stats.NodeName).To(gomega.Equal("node-a"))
		})
	})

	ginkgo.When("the breaker has recorded failures but not yet opened", func() {
		ginkgo.It("reports the running consecutive-failure count", func() {
			cb.RecordFailure()
			cb.RecordFailure()
			stats := cb.Stats()
			gomega.Expect(stats.State).To(gomega.Equal(circuit.Closed))
			gomega.Expect(stats.ConsecutiveFailures).To(gomega.Equal(2))
		})
	})

	ginkgo.When("the breaker has just opened", func() {
		ginkgo.It("reports state=open and a non-zero cooldown remaining", func() {
			cb.RecordFailure()
			cb.RecordFailure()
			cb.RecordFailure() // third failure trips it open
			stats := cb.Stats()
			gomega.Expect(stats.State).To(gomega.Equal(circuit.Open))
			gomega.Expect(stats.ConsecutiveFailures).To(gomega.Equal(3))
			// CooldownRemaining should be > 0 and <= 30s (the configured cooldown)
			gomega.Expect(stats.CooldownRemaining).To(gomega.BeNumerically(">", time.Duration(0)))
			gomega.Expect(stats.CooldownRemaining).To(gomega.BeNumerically("<=", 30*time.Second))
		})
	})
})