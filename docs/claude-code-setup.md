# Claude Code through HelixChannel

Claude Code holds its own session credential, and pointing it at a rewritten base URL disables features that depend on talking to Anthropic directly. So it does not use the reverse-proxy routes — it uses the [CONNECT tunnel](helixchannel.md#connect-tunnel), which carries its traffic through the channel while leaving its TLS session end-to-end with Anthropic.

```
Claude Code ──HTTPS_PROXY──► helixchannel proxy ──TLS──► gateway ──► api.anthropic.com
                             (loopback)                  (allowlisted CONNECT)
                             └──────── inner TLS stays end-to-end ────────┘
```

The gateway sees encrypted bytes and a destination, nothing more.

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
| TLS error dialling the gateway | Self-signed certificate | Use a CA-issued certificate, or `--insecure` while piloting |
| `curl` works, agent does not | Agent read a stale config | Fully restart the app; confirm the keys are in the user-level `settings.json` |
