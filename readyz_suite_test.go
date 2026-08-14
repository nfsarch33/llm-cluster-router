//go:build integration

package main

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// Run the Ginkgo suite via go test's TestMain. The standard
// `ginkgo bootstrap` template is preserved verbatim to match every
// other Helixon core service per L0 rule 42 (integration-test-gating).
func TestReadyzGinkgo(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "llm-cluster-router readyz (main package)")
}

// _ keeps imports referenced even before the first spec is written
// (RED state). Once specs below compile, this alias can be dropped —
// keep it as documentation that RED state compiles.
var (
	_ = newRouter
	_ = ginkgo.Describe
	_ = gomega.Expect
)