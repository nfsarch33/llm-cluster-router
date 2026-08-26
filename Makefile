# Makefile — the exact commands CI runs, so "green locally" means "green in CI".
# Every target mirrors a .github/workflows/ci.yml step.
#
# Two tiers, deliberately:
#
#   `make all` is the MERGE GATE. Everything in it is deterministic and bounded.
#   If it is red, the change does not merge.
#
#   `make fuzz`, `make bench`, `make realmodel`, `make adversarial` are
#   SCHEDULED work, run nightly, NOT part of the gate. Fuzzing is unbounded by
#   nature, benchmark numbers are wall-clock and therefore noisy on a shared
#   runner, and the realmodel tier needs live provider credentials. Any of the
#   three inside the gate would make the gate slow or flaky, and a slow or
#   flaky gate is a gate people learn to bypass.

GO ?= go

# golangci-lint must be v2.x: CI pins golangci-lint-action v8 / v2.13.0, and a
# v1.x binary refuses to load a go1.25+ module at all. Override when the binary
# on PATH is the wrong one:  make lint GOLANGCI=/path/to/golangci-lint
GOLANGCI ?= golangci-lint

# Non-gate tunables. CI overrides FUZZTIME for the nightly budget.
FUZZTIME   ?= 30s
BENCHTIME  ?= 1s
BENCHCOUNT ?= 1
BENCH_OUT  ?= .bench/current.txt

# Every build tag in the tree. `make vet-tags` type-checks each one, so a tier
# that no scheduled job runs still cannot rot into non-compiling.
# Regenerate with:  rg -n '^//go:build' --glob '*.go' | sed 's/.*go:build //' | sort -u
BUILD_TAGS := realmodel adversarial adr083_test socks5_stream release_gate_test integration live_e2e

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.buildVersion=$(VERSION)

.PHONY: all build vet vet-tags test race-shuffle integration live-e2e lint security tidy help
.PHONY: fuzz bench bench-save realmodel adversarial

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

all: vet vet-tags test race-shuffle integration lint ## THE MERGE GATE

build: ## Build the router with a stamped version (relcheck warns on stale binaries)
	go build -ldflags "$(LDFLAGS)" -o llm-router .

vet: ## go vet, default build (matches ci.yml `test`)
	$(GO) vet ./...

vet-tags: ## go vet under every build tag, so a dormant tier cannot rot (matches ci.yml `vet-tags`)
	@set -eu; for t in $(BUILD_TAGS); do \
	  echo "==> go vet -tags=$$t ./..."; \
	  $(GO) vet -tags=$$t ./...; \
	done

test: ## Unit tests with race + coverage (matches ci.yml `test`)
	$(GO) test -race -coverprofile=coverage.out ./...

race-shuffle: ## Unit tests again in randomised order, twice over (matches ci.yml `race-shuffle`)
	# Randomised order is what catches a test that only passes because some
	# other test left state behind — and shared state between tests is the
	# same defect class as shared state between goroutines. -count=2 reshuffles,
	# so each run samples two orderings per package.
	$(GO) test -race -count=2 -shuffle=on ./...

integration: ## Integration tests, mock upstreams (matches ci.yml `integration`)
	$(GO) test -tags=integration -timeout=2m -count=1 -race -run TestIT_ ./...

live-e2e: ## Regression suite against the deployed edge (needs HELIXCHANNEL_LIVE_* env)
	$(GO) test -tags=live_e2e -count=1 -v -run TestLive_ ./internal/channel/

fuzz: ## Every fuzz target, FUZZTIME each; non-zero on a crasher (nightly, NOT the gate)
	FUZZTIME=$(FUZZTIME) GO=$(GO) bash tools/fuzz-all.sh

bench: ## Every benchmark with -benchmem (nightly, NOT the gate)
	$(GO) test -run='^$$' -bench=. -benchmem -benchtime=$(BENCHTIME) -count=$(BENCHCOUNT) ./...

bench-save: ## As `bench`, teed into $(BENCH_OUT) for benchstat comparison
	# A benchmark number is only meaningful next to the host and toolchain that
	# produced it, so record both alongside the numbers.
	@mkdir -p $(dir $(BENCH_OUT))
	@{ echo "# go:   $$($(GO) version)"; \
	   echo "# host: $$(uname -srm)"; \
	   echo "# cpu-count: $$(getconf _NPROCESSORS_ONLN)"; \
	   echo "# date: $$(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > $(BENCH_OUT)
	$(GO) test -run='^$$' -bench=. -benchmem -benchtime=$(BENCHTIME) -count=$(BENCHCOUNT) ./... | tee -a $(BENCH_OUT)

realmodel: ## Real-provider tier, build tag `realmodel` (nightly; needs live provider credentials)
	$(GO) test -tags=realmodel -timeout=10m -count=1 -race ./...

adversarial: ## Hostile-input tier, build tag `adversarial` (nightly)
	$(GO) test -tags=adversarial -timeout=5m -count=1 -race ./...

lint: ## golangci-lint (matches ci.yml `lint`, which pins v2.13.0)
	@v=$$($(GOLANGCI) version 2>/dev/null | head -1); \
	case "$$v" in \
	  *"version 2."*) ;; \
	  *) echo "make lint: need golangci-lint v2.x to match CI (action v8 / v2.13.0); got: $${v:-not on PATH}." >&2; \
	     echo "           run: make lint GOLANGCI=/path/to/v2/golangci-lint" >&2; exit 1;; \
	esac
	$(GOLANGCI) run

security: ## govulncheck (matches ci.yml `security`)
	govulncheck ./...

tidy: ## go mod tidy
	$(GO) mod tidy
