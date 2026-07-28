# Contributing

## Anti-leak guardrails

This is a public mirror. Before opening a PR, run:

```bash
bash tools/leak-scan.sh
```

The CI gate `.github/workflows/leak-scan.yml` enforces the same scan on
every PR.

See `.github/NO-EVIDENCE.md` for the full list of forbidden content.

## Code style

- `gofmt -s` for formatting
- `go vet ./...` for sanity
- `golangci-lint run` for the lint battery
- Public API contracts are pinned via the `vendor_integration_test.go`
  admission tests; do not weaken them.

## Adding new vendors

1. Add a new peer block to `configs/llm-cluster-router.yml` with the
   `vendor:`, `enabled: true`, `api_key_env:`, `quota_detect_regex:` fields.
2. Mirror the pattern in `internal/router/minimax.go` (or create a new
   vendor package).
3. Add a `Vendor` accessor case in `internal/router/url_builder.go`.
4. Add unit tests in `internal/config/config_vendor_test.go` and
   `internal/router/vendor_integration_test.go`.

## Adding new Slack alerts

1. The router posts Slack alerts via `internal/quota.Detector.Notify`.
2. Set `slack_webhook_url` and `slack_channel` in
   `configs/llm-cluster-router.yml`.
3. The webhook URL is loaded from `LLM_ROUTER_SLACK_WEBHOOK_URL` env var;
   never commit it to this repo.
