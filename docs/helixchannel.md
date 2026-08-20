# HelixChannel

HelixChannel keeps provider API keys off client machines and keeps agent traffic opaque to the network in between.

Without it, every laptop running an agent holds a copy of every provider key. Rotating one means touching every machine, a leaked key is hard to attribute, and the traffic itself is only as private as whatever network the laptop is on.

With it, keys live on one host you control. Clients authenticate to the channel, not to the provider.

## How it works

```
agent  ──►  TLS  ──►  HelixChannel gateway  ──►  TLS  ──►  provider
                       (holds the real key)
```

Two request styles are supported, because agents differ in how they authenticate.

### Reverse proxy (path prefixes)

The client sends an ordinary OpenAI-compatible request to `https://gateway/<route>/v1/...`. The gateway matches the prefix, strips it, applies credentials and forwards. The client's base URL is the only thing that changes.

Use this for anything driven by an API key: Kilo Code, Cursor, Codex CLI, scripts, CI jobs.

### CONNECT tunnel

Some clients cannot be pointed at a rewritten base URL without losing features, and some hold a session credential that has to terminate at the provider. For those, the gateway accepts an authenticated `CONNECT`, dials an allowlisted target and copies bytes. It never terminates the inner TLS, so the client's session is end-to-end encrypted and unreadable by the gateway itself.

Use this for Claude Code (see [Claude Code setup](claude-code-setup.md)).

## Auth modes

| Mode | Who supplies the credential | Use for |
|---|---|---|
| `inject` | The gateway, from `key_env` or `key_file`. The caller's `Authorization` header is **replaced**, so a client cannot reach the upstream as another account and the placeholder it sends never leaves the gateway. | API-key providers |
| `passthrough` | The caller. Forwarded untouched. | Clients holding their own session token |

## Configuration

```yaml
listen: "127.0.0.1:14445"    # bind loopback when a TLS terminator fronts it
timeout: 90s
audit_log: /var/log/helixchannel/gateway.ndjson   # empty = stdout

routes:
  - name: minimax
    prefix: /minimax/
    upstream: https://api.minimaxi.com
    auth: inject
    key_file: /run/secrets/minimax.key
    enabled: true

  - name: codex
    prefix: /codex/
    upstream: https://api.openai.com
    auth: inject
    key_file: /run/secrets/openai.key
    enabled: false          # feature flag

connect:
  enabled: true
  token_file: /run/secrets/connect.token
  dial_timeout: 10s
  allowed_hosts:            # exact host:port matches; empty is rejected
    - api.anthropic.com:443

tls:                        # only needed when the gateway owns a public socket
  cert_file: /etc/helixchannel/tls.crt
  key_file: /etc/helixchannel/tls.key
```

Adding a provider is one entry. Turning it on is one boolean. Nothing is compiled in: route names, prefixes, upstreams and auth modes are all data, and the config is validated at startup so a typo in a route that is switched off today does not become an outage the day it is switched on.

`enabled: false` routes are not registered at all — requests to their prefix return 404, and `/healthz` lists only what is actually being served.

## Running it

### Container (recommended)

```bash
podman build -t helixchannel-gateway:local -f deploy/helixchannel/Containerfile.gateway .

podman run -d --name helixchannel-gateway \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v ./gateway.yml:/etc/helixchannel/gateway.yml:ro,Z \
  -v ./secrets:/run/secrets:ro,Z \
  -p 127.0.0.1:14445:14443 \
  helixchannel-gateway:local
```

The image is distroless with no shell and runs as a non-root user. Under rootless Podman, add `--userns=keep-id --user "$(id -u):$(id -g)"` so the container can read host-owned secret files.

### Binary with systemd

```ini
[Service]
ExecStart=/usr/local/bin/helixchannel gateway --config /etc/helixchannel/gateway.yml
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
```

Use this on small hosts where a container runtime is not worth its memory.

### Behind a TLS terminator

For the reverse-proxy routes, bind the gateway to loopback and let nginx or Caddy terminate TLS. Forward the **full path** — the gateway matches on the prefix itself:

```nginx
location /minimax/ { proxy_pass http://127.0.0.1:14445; }   # no trailing slash
location = /healthz { proxy_pass http://127.0.0.1:14445/healthz; }
```

Proxy `/healthz` to the gateway rather than answering it from a literal. A static health response cannot tell "edge is up" from "upstreams are configured", and that difference is exactly what an outage looks like.

The CONNECT leg cannot be relayed by an ordinary HTTP reverse proxy. Give it its own port with `tls:` configured so the gateway owns that socket.

## Verifying

```bash
# Live route set — reflects the enabled flags, not a hardcoded string
curl -s https://gateway.example.com/healthz
# {"status":"ok","service":"helixchannel-gateway","routes":["minimax","qwen"],"connect":true}

# A route end-to-end
curl -s https://gateway.example.com/minimax/v1/models -H "Authorization: Bearer $CLIENT_TOKEN"

# The CONNECT leg, and that the certificate is the provider's
curl -v -x http://127.0.0.1:47810 https://api.anthropic.com/ 2>&1 | grep -E 'subject:|verify'
# subject: CN=api.anthropic.com ... SSL certificate verify ok
```

That last check is the one worth keeping: if the tunnel were being intercepted, the certificate would be the gateway's.

## Audit log

One NDJSON line per event, with request metadata only — no bodies, no headers, no credentials:

```json
{"ts":"2026-08-20T01:14:09Z","event":"connect_established","request_id":"5c470a65","target":"api.anthropic.com:443","status":200,"latency_ms":1}
{"ts":"2026-08-20T01:09:11Z","event":"connect_denied","target":"example.com:443","status":403,"error":"host_not_allowlisted"}
```

Errors are recorded as classes (`timeout`, `refused`, `dns`, `tls`, `upstream_error`) rather than raw strings, so a URL carrying a token cannot reach the log.

## Threat model

**Protects against:** provider keys spreading across client machines; credential theft from a laptop; passive observation or tampering on the path between agent and provider; a client reaching the upstream as another account.

**Does not protect against:** a compromised gateway host — it holds the keys; a malicious client that has a valid channel token, within its allowlisted scope; provider-side logging. The CONNECT allowlist bounds what a stolen token can reach, which is why it is required and why it should stay short.
