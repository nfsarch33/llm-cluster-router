# Claude Code through HelixChannel

Claude Code holds its own session credential, and pointing it at a rewritten base URL disables features that depend on talking to Anthropic directly. So it does not use the reverse-proxy routes — it uses the [CONNECT tunnel](helixchannel.md#connect-tunnel), which carries its traffic through the channel while leaving its TLS session end-to-end with Anthropic.

```
Claude Code ──HTTPS_PROXY──► helixchannel proxy ──TLS──► gateway ──► api.anthropic.com
                             (loopback)                  (allowlisted CONNECT)
                             └──────── inner TLS stays end-to-end ────────┘
```

The gateway sees encrypted bytes and a destination, nothing more.

## Which of the two paths you want

There are two ways to put Claude Code behind HelixChannel, and they are not
interchangeable. Pick deliberately:

| | **CONNECT tunnel** (the rest of this page) | **Reverse-proxy route** |
|---|---|---|
| Credential Claude Code uses | its own — your claude.ai login stays the active credential | the gateway's, or one you supply |
| Billing | your subscription | per token, to whoever owns the credential the gateway forwards |
| Client-side install | the `helixchannel` binary, run as a user service | none |
| Which channel secret | the **CONNECT** token, in `Proxy-Authorization` | the **gateway** token, in `X-HLXN-Token` |
| Feature loss | none | base-URL override disables Remote Control |
| What the gateway can see | destination host and encrypted bytes | the full request and response |

The CONNECT tunnel is the default for Claude Code because it is the only one
that preserves the subscription and keeps TLS end-to-end with Anthropic. Use the
reverse-proxy route when you deliberately want the gateway's credential, its
audit trail, and its spend controls applied to this traffic.

### The reverse-proxy route, if that is what you want

```bash
export ANTHROPIC_BASE_URL="https://gateway.example.com/anthropic"
export ANTHROPIC_AUTH_TOKEN="placeholder"            # stripped on inject routes
export ANTHROPIC_CUSTOM_HEADERS="X-HLXN-Token: <the gateway token>"
```

or the same three under `env` in `~/.claude/settings.json`. `ANTHROPIC_AUTH_TOKEN`
travels as `Authorization: Bearer`; `ANTHROPIC_API_KEY` travels as `x-api-key`.
Which one the gateway wants depends on the route's `auth` mode — on `passthrough`
the value you set is the credential that reaches Anthropic, so put a real one
there; on `inject` it is a placeholder the gateway drops and replaces.

Setting `ANTHROPIC_BASE_URL` **without** a credential variable does not replace
your subscription: requests route through the gateway but the saved claude.ai
login stays active, and a gateway passing that traffic on to Anthropic has to
forward the OAuth capability in `anthropic-beta`.

The two tokens are different secrets on purpose and are not interchangeable. The
CONNECT token opens a byte tunnel bounded by an exact-match host allowlist; the
gateway token authorises spending every key on every enabled route. Sending one
where the other is expected fails closed — `407` on the tunnel, `401` on the
reverse-proxy leg — rather than quietly granting the wider power.

## 1. Enable the tunnel on the gateway

```yaml
connect:
  enabled: true
  token_file: /run/secrets/connect.token
  allowed_hosts:
    - api.anthropic.com:443
    - statsig.anthropic.com:443

tls:
  cert_file: /etc/helixchannel/tls.crt
  key_file: /etc/helixchannel/tls.key
```

The CONNECT leg needs its own TLS port — an HTTP reverse proxy cannot relay `CONNECT`. Generate the token once and keep it root-owned:

```bash
head -c 32 /dev/urandom | base64 | sudo tee /etc/helixchannel/connect.token >/dev/null
sudo chmod 600 /etc/helixchannel/connect.token
```

Open that port in your firewall or cloud security group, and confirm the listener:

```bash
curl -sk https://gateway.example.com:8443/healthz
# {"status":"ok","service":"helixchannel-gateway","connect":true,...}
```

## 2. Run the client proxy

Copy the token to the client machine (`~/.config/helixchannel/connect.token`, mode 600), then:

```bash
helixchannel proxy \
  --listen 127.0.0.1:47810 \
  --gateway gateway.example.com:8443 \
  --token-file ~/.config/helixchannel/connect.token
```

Add `--insecure` only while the gateway still serves a self-signed certificate. It relaxes verification of the **outer** hop to the gateway; Claude Code's own TLS to Anthropic is still verified end to end.

Keep it running with a user service:

```ini
# ~/.config/systemd/user/helixchannel-proxy.service
[Service]
ExecStart=%h/bin/helixchannel proxy --listen 127.0.0.1:47810 --gateway gateway.example.com:8443 --token-file %h/.config/helixchannel/connect.token
Restart=always

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now helixchannel-proxy
loginctl enable-linger "$USER"   # survive logout and reboot
```

## 3. Point Claude Code at it

```bash
helixchannel proxy --listen 127.0.0.1:47810 --print-env
```

Put those values in `~/.claude/settings.json` under `env`:

```json
{
  "env": {
    "HTTPS_PROXY": "http://127.0.0.1:47810",
    "HTTP_PROXY": "http://127.0.0.1:47810",
    "https_proxy": "http://127.0.0.1:47810",
    "http_proxy": "http://127.0.0.1:47810",
    "NO_PROXY": "127.0.0.1,localhost,::1"
  }
}
```

Merge into the existing file — do not replace it. `settings.json` also holds hooks and permissions, and overwriting it silently disables them.

Use `HTTPS_PROXY`, not `ANTHROPIC_BASE_URL`: the base-URL override disables Remote Control, while the proxy variables are the supported path and coexist with it.

Do not set `SSL_CERT_FILE`. It *replaces* the system trust store rather than adding to it, and since these variables also reach tool subprocesses, it breaks TLS for `curl`, `git` and anything else the agent runs.

## 4. Verify

```bash
# The request reaches Anthropic (401 = no credential attached, which is correct here)
curl -x http://127.0.0.1:47810 -o /dev/null -w '%{http_code}\n' \
  -X POST https://api.anthropic.com/v1/messages \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"claude-sonnet-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'

# The certificate is Anthropic's, so the tunnel is not being intercepted
curl -v -x http://127.0.0.1:47810 https://api.anthropic.com/ 2>&1 | grep -E 'subject:|verify'
# subject: CN=api.anthropic.com
# SSL certificate verify ok.

# A host outside the allowlist is refused
curl -x http://127.0.0.1:47810 https://example.com/    # fails: 403 host_not_allowlisted
```

Then restart Claude Code and use it normally. Server-side, each session shows up as `connect_established` in the gateway's audit log.

## Rollback

Remove the five proxy keys from `~/.claude/settings.json` and restart the app. Keep a timestamped backup of the file before editing so this is a copy, not a re-edit.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every request fails after wiring the env | Proxy not running | `systemctl --user status helixchannel-proxy`; check `enable-linger` |
| `403` from the gateway | Host not allowlisted | Add the exact `host:port` to `allowed_hosts` and restart the gateway |
| `407` from the gateway | Token missing or wrong | Compare the client token file with the gateway's |
| `curl: (56) CONNECT tunnel failed, response 502` | **Both of the above look like this from the client.** The gateway distinguishes them correctly — it returns `403 host_not_allowlisted` or `407 bad_token` — but the client proxy reports its own `502` to the local caller either way, so the status code you see does not tell you which happened | Read the gateway's audit log, not the client's status. `connect_denied` carries the real `status` and an `error` of `host_not_allowlisted` or `bad_token`. Verified against a live edge: a disallowed host and a wrong token both surfaced as 502 locally while the gateway logged 403 and 407 respectively |
| TLS error dialling the gateway | Self-signed certificate | Issue a CA-signed certificate. `--insecure` is a piloting crutch, not a configuration: it relaxes verification of the outer hop only — Claude Code's TLS to Anthropic stays verified end to end — but an unverified outer hop means anyone in the path can present their own certificate and read the CONNECT request line and the `Proxy-Authorization` token you send with it. On a managed laptop, prefer a real certificate over asking for a trust exception you may not be allowed to grant. |
| `Self-signed certificate detected` from Claude Code while `curl` to the same URL succeeds | Node uses its own bundled CA store, not the one `curl` reads | Point `NODE_EXTRA_CA_CERTS` at the CA bundle. It *adds* to the trust store; do not use `SSL_CERT_FILE`, which replaces it and breaks TLS for `git`, `curl` and everything else the agent runs. |
| `curl` works, agent does not | Agent read a stale config | Fully restart the app; confirm the keys are in the user-level `settings.json` |

## Local models and the per-agent gate

Claude Code's Anthropic traffic keeps using the CONNECT proxy above (OAuth
intact, keys never proxied in plain form). Independently of that, tooling on
the same machine can call the local model pool through the router:

- Base URL `http://127.0.0.1:8787/v1`, model `qwen3.8-27b-local` (or `auto`).
- Claude Code is a first-class gated agent: the smart-route policy carries a
  `claude-code` boolean (`scripts/agent-route.sh claude-code on|off`). A
  gated-off agent receives `403 route disabled for agent "claude-code"` —
  that response comes from the router's policy, not from Anthropic.
