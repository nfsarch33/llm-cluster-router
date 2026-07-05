package main

// This file bridges the internal/circuit package back into package
// main via type aliases and constructor wrappers so existing code
// and tests compile unchanged. It will be removed when downstream
// consumers import internal/circuit directly.

import (
	"time"

	"github.com/nfsarch33/llm-cluster-router/internal/circuit"
)

type circuitState = circuit.State
type circuitBreaker = circuit.Breaker

const (
	circuitClosed   = circuit.Closed
	circuitOpen     = circuit.Open
	circuitHalfOpen = circuit.HalfOpen
)

func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	return circuit.NewBreaker(threshold, cooldown)
}

// circuitStateGauge re-exports the metric so dashboard tests find it.
var circuitStateGauge = circuit.StateGauge

// Keep bridge aliases referenced for golangci-lint unused check.
var (
	_ circuitState     = circuitClosed
	_ *circuitBreaker  = newCircuitBreaker(1, time.Second)
	_                  = circuitStateGauge
)
