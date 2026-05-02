# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-05-02

### Added
- Initial public release; extracted from nfsarch33/ironclaw-ops
- OpenAI-compatible `/v1/chat/completions` and `/v1/models` proxy
- Fair-share per-user queuing with sliding-window rate limiting
- Multi-upstream routing with tier, priority, and weight controls
- SSE streaming pass-through for chat completions
- Automatic health checking for vLLM (`/health`) and Ollama (`/v1/models`) backends
- Prometheus `/metrics` endpoint with request latency, queue depth, and node health
- Built-in `bench` subcommand for throughput and latency benchmarking
- `probe-gpu` subcommand for NVIDIA GPU inventory via nvidia-smi
- Bearer token authentication for `/v1/*` endpoints
- Environment variable expansion (`${VAR}`) in YAML config
- Retry with alternate upstream on hard connection failures
