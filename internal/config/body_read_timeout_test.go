package config

import (
	"strings"
	"testing"
	"time"
)

// defaults.body_read_timeout bounds how long the proxy handler waits for the
// next bytes of a request body while it is holding a queue slot. Its whole
// reason for existing is deployments that never heard of it, so the way it
// reads a value it was not given matters more than the way it reads one it
// was.

const bodyReadTimeoutFixture = `
listen: ":8787"
defaults:
  max_queue_depth: 4
  max_concurrency: 2
%s
nodes:
  - name: local
    url: "http://127.0.0.1:9999/v1"
    tier: "0"
    enabled: "true"
    models:
      - "m1"
`

func loadWithBodyReadTimeout(t *testing.T, line string) (Config, error) {
	t.Helper()
	return LoadConfig(writeTempConfig(t, strings.Replace(bodyReadTimeoutFixture, "%s", line, 1)))
}

// TestBodyReadTimeout_OmittedKeyGetsTheDefault is the case every config in the
// tree is in.
//
// The key is new, so nothing on disk sets it. If an absent key resolved to "no
// bound" then the only deployments running unbounded would be precisely the
// ones the key was added to protect, and the fix would ship as a no-op wearing
// a config option.
func TestBodyReadTimeout_OmittedKeyGetsTheDefault(t *testing.T) {
	cfg, err := loadWithBodyReadTimeout(t, "")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.Defaults.BodyReadTimeout.Duration; got != DefaultBodyReadTimeout {
		t.Fatalf("body_read_timeout = %v for a config that omits the key, want the default %v: every config in the tree omits it, so this is the value that decides whether the bound exists at all", got, DefaultBodyReadTimeout)
	}
}

// TestBodyReadTimeout_ZeroMeansTheDefaultNotUnlimited pins the convention this
// branch already applies to connect.max_concurrent and connect.idle_timeout.
//
// Zero is the Go zero value AND a value an operator can type, and the two must
// not disagree: if a written 0 meant "wait forever" then the same integer
// would mean opposite things depending on whether a human put it there.
func TestBodyReadTimeout_ZeroMeansTheDefaultNotUnlimited(t *testing.T) {
	cfg, err := loadWithBodyReadTimeout(t, "  body_read_timeout: 0s")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.Defaults.BodyReadTimeout.Duration; got != DefaultBodyReadTimeout {
		t.Fatalf("body_read_timeout = %v for an explicit 0s, want the default %v: there is deliberately no spelling for \"wait forever\"", got, DefaultBodyReadTimeout)
	}
}

// TestBodyReadTimeout_NegativeIsAStartupError refuses the value rather than
// rounding it.
//
// A negative deadline is already in the past, so honouring it literally would
// reject every request the instant it arrived; clamping it to the default
// would serve a bound the operator did not write under a value that says
// otherwise. Neither is something to discover from traffic, so it is refused
// at startup, where the operator is still watching.
func TestBodyReadTimeout_NegativeIsAStartupError(t *testing.T) {
	_, err := loadWithBodyReadTimeout(t, "  body_read_timeout: -1s")
	if err == nil {
		t.Fatal("LoadConfig accepted body_read_timeout: -1s; a deadline in the past is not a bound and must not start")
	}
	if !strings.Contains(err.Error(), "body_read_timeout") {
		t.Fatalf("error does not name the key the operator has to fix: %v", err)
	}
}

// TestBodyReadTimeout_ExplicitValueSurvives makes sure the defaulting above is
// defaulting and not overwriting.
func TestBodyReadTimeout_ExplicitValueSurvives(t *testing.T) {
	cfg, err := loadWithBodyReadTimeout(t, "  body_read_timeout: 3s")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got, want := cfg.Defaults.BodyReadTimeout.Duration, 3*time.Second; got != want {
		t.Fatalf("body_read_timeout = %v, want %v: the operator's value was replaced by the default", got, want)
	}
}
