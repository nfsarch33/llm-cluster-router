# Makefile — the exact commands CI runs, so "green locally" means "green in CI".
# Every target mirrors a .github/workflows/ci.yml step.

GO ?= go

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.buildVersion=$(VERSION)

build: ## Build the router with a stamped version (relcheck warns on stale binaries)
	go build -ldflags "$(LDFLAGS)" -o llm-router .

.PHONY: build
.PHONY: all vet test integration live-e2e lint security tidy help

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

all: vet test integration lint ## Vet, unit, integration, lint (the merge gate)

vet: ## go vet
	$(GO) vet ./...

test: ## Unit tests with race + coverage (matches ci.yml `test`)
	$(GO) test -race -coverprofile=coverage.out ./...

integration: ## Integration tests, mock upstreams (matches ci.yml `integration`)
	$(GO) test -tags=integration -timeout=2m -count=1 -race -run TestIT_ ./...

live-e2e: ## Regression suite against the deployed edge (needs HELIXCHANNEL_LIVE_* env)
	$(GO) test -tags=live_e2e -count=1 -v -run TestLive_ ./internal/channel/

lint: ## golangci-lint (matches ci.yml `lint`)
	golangci-lint run

security: ## govulncheck (matches ci.yml `security`)
	govulncheck ./...

tidy: ## go mod tidy
	$(GO) mod tidy
