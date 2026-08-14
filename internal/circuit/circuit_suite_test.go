//go:build integration

package circuit_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/nfsarch33/llm-cluster-router/internal/circuit"
)

// Run the Ginkgo suite via go test's TestMain. The standard
// `ginkgo bootstrap` template is preserved verbatim to match every
// other Helixon core service per L0 rule 42 (integration-test-gating).
func TestCircuit(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "llm-cluster-router internal/circuit package")
}

// _ keeps imports referenced even before the first spec is written
// (RED state). Once specs below compile, this alias can be dropped —
// keep it as documentation that RED state compiles.
var (
	_ = circuit.NewBreaker
	_ = ginkgo.Describe
	_ = gomega.Expect
)