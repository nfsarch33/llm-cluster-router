# RELEASE NOTES

This file tracks user-visible release notes for `llm-cluster-router`.
The chronological order is newest-first; the most recent release is
at the top of the file. Each entry must include the sprint id, the
release date, a one-paragraph summary, and a bullet list of
additive / changing / removing changes.

## v18712 (2026-07-22) — HelixChannel release announcement

The v18712 sprint promotes the operator-facing name "HelixChannel"
for the AES-256-GCM application-layer encrypted HTTP channel. The
underlying implementation is unchanged; the naming + additive
metadata are new.

### Additive

- **HelixChannel brand name.** Every response carries the
  `HelixChannel-Version: v18712-1` response header so operators can
  fingerprint the build with `curl -I`. See
  `internal/proxy/helixchannel_header.go`.
- **Additive metric families.**
  `llm_cluster_router_helixchannel_connections_total` and
  `llm_cluster_router_helixchannel_bytes_total` mirror the legacy
  `llm_cluster_router_*` series under the operator-facing brand.
  Both label sets are populated in lock-step from the dual-listener
  ServeLoop; existing Grafana panels that key off
  `listener="aes-mtls"` keep working unchanged.
- **README "HelixChannel (encrypted dual-listener)" section.**
  Documents the threat model, ListenerFactory contract, and the
  `HELIXCHANNEL_*` operator-facing config keys.
- **ListenerFactory wire (v18712-2).** Production `main.go`
  constructs the `aesMTLSListenerFactory` by default; the
  `HELIXCHANNEL_ENABLED=false` env override keeps the legacy plain
  HTTP listener for back-compat. ADR-085 supersedes the ADR-084
  deferral.

### Changed

- `internal/proxy/listener.go` package comment updated with the
  HelixChannel brand name and the ADR-085 reference.
- `internal/proxy/observability/observability.go` adds two new
  counter vectors; existing counters untouched.

### Removed

- None.
