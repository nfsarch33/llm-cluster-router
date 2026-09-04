# Containerfile for llm-cluster-router (v14617 Pair 2 #4)
# Source: github.com/nfsarch33/llm-cluster-router
# Replaces upstream alpine Dockerfile with our standard distroless pattern.
#
# LLM router: receives /v1/chat/completions from Helixon agents and
# forwards to whichever upstream (Ollama wsl1/wsl2/wsl4, Minimax, etc.)
# matches the request's model + priority + circuit-breaker state.
#
# Two listeners (per upstream Dockerfile): :8080 (proxy) and :9091 (metrics).
# Live systemd unit binds ":8787"; CMD overrides default :8080.

FROM golang:1.27-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/llm-cluster-router .

FROM gcr.io/distroless/base-debian12:nonroot

LABEL org.opencontainers.image.title="llm-cluster-router" \
      org.opencontainers.image.description="LLM Cluster Router (Helixon fleet central)" \
      org.opencontainers.image.source="https://github.com/nfsarch33/llm-cluster-router" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.helixon.sprint="v14617" \
      io.helixon.service="llm-cluster-router"

COPY --from=builder /out/llm-cluster-router /llm-cluster-router

USER 65532:65532

# Live systemd unit (v14547): serve -c /home/.../configs/llm-cluster-router.yml
# Default upstream CMD points at /etc/llm-cluster-router/router.yml (k3s ConfigMap).
ENTRYPOINT ["/llm-cluster-router"]
CMD ["serve", "-config", "/etc/llm-cluster-router/router.yml"]

EXPOSE 8787 9091
