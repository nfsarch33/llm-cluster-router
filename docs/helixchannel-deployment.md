# HelixChannel Production Deployment

> **Historical document.** This describes the v186xx pilot wiring (router
> :8742 AES wire, prefix-less `/v1` base URL). The CURRENT deployment is the
> `helixchannel gateway` on 127.0.0.1:14443 behind nginx with route-prefixed
> base URLs (`/<route>/v1`) and server-side key injection — see
> [helixchannel.md](helixchannel.md) and the setup guides
> ([kilo-code-setup.md](kilo-code-setup.md), [claude-code-setup.md](claude-code-setup.md)).
> Kept for the operational history only; do not wire new clients from this page.


This document is the canonical runbook for exposing the HelixChannel
production wire behind a stable public hostname (`helixchannel.example.com`).
It supersedes the per-IP quickstart shipped in earlier `feat/v18714-*`
branches. The earlier story (`v18714-1`, ADR-086) moved the wire from
TCP/22 (SSH SOCKS5) to TCP/443 (TLS-tunneled nginx); this story
(`v18714-11`) binds a real DNS name + Let's Encrypt cert on top of
that path so the pilot consumer (Kilo Code, Peer, etc.) never has to
hard-code a Lightsail IP.

## Topology

```
┌────────────────────────┐      DNS A-record (DreamHost)
│  Operator / IDE        │  ─────────────────────────────────────►
│  curl https://helixchannel.example.com/v1/chat/completions
│                        │
└────────────────────────┘
            │
            ▼   TCP/443 (Let's Encrypt TLS)
┌────────────────────────┐
│  Lightsail instance    │
│  lightsail-tunnel        │   203.0.113.10 (static IP, ap-southeast-2a)
│  ubuntu_22_04 / nano_3_2
│                        │
│  nginx :443            │   terminate TLS (certbot-managed)
│      │                 │
│      ▼                 │
│  router :8742          │   AES-256-GCM HelixChannel wire
│  (HelixonChannel binary)
│      │                 │
└──────│─────────────────┘
       ▼
   upstream LLM providers (vLLM, Ollama, MiniMax-M3, ...)
```

The Lightsail firewall (per `aws lightsail get-instance-port-states`)
MUST allow `tcp:443` inbound. The rule is `lightsail-tunnel` instance,
`fromPort=443`, `toPort=443`, `protocol=tcp`, `state=open`. The
`helixchannel doctor` `lightsail_tcp443` check enforces this in the
release-gate JSON envelope.

## DNS A-record (DreamHost)

| Zone | Record | Type | Value | TTL |
|---|---|---|---|---|
| `example.com` | `helixchannel` | A | `203.0.113.10` | 300 |

The DreamHost API key is in 1Password `<1password-vault>` vault, item
`DreamHost` (UUID and field UUID per
`cursor-global-kb/global-memories/credentials-index.md`).

### Add / refresh the A-record (idempotent + rollback-safe)

```bash
# 1. Resolve the DreamHost API key from 1Password (NEVER on argv).
#    Look up the item + field UUID in
#    cursor-global-kb/global-memories/credentials-index.md first.
op read "op://<1password-vault>/<dreamhost-item-uuid>/<api-key-field-uuid>" \
  --out-file -f /tmp/.dh-key && KEY=$(cat /tmp/.dh-key) && rm -f /tmp/.dh-key

# 2. POST a new A-record via DreamHost's dns-add_record command.
#    `unique_id` makes the call idempotent; same payload → no-op.
curl -sS --data-urlencode "key=$KEY" \
  --data-urlencode "cmd=dns-add_record" \
  --data-urlencode "record=helixchannel" \
  --data-urlencode "type=A" \
  --data-urlencode "value=203.0.113.10" \
  --data-urlencode "unique_id=helixchannel-example-com-2026-07" \
  https://api.dreamhost.com/
```

`result=success` is the expected response. If the record already
exists, DreamHost returns `result=error` with
`data=already_exists`; treat that as success for the idempotency
path.

### Verify DNS propagation

```bash
# Third-party resolver (NOT the Lightsail VPC).
dig +short @8.8.8.8 helixchannel.example.com
# Expected: 203.0.113.10
```

DreamHost API posts propagate within <60 s. If the third-party
resolver returns NXDOMAIN, wait 60 s and re-probe.

## TLS (Let's Encrypt via certbot on Lightsail)

```bash
# 1. SSH into the Lightsail host (operator-only path; the v18714
#    SSH hop on wsl3 was disrupted for several hours — see
#    session-handoffs/evidence/2026-07-22-lightsail-ssh-hop-down.md).
ssh ubuntu@203.0.113.10

# 2. Install certbot (one-time; nginx plugin pulls in the deps).
sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx

# 3. Issue the cert. certbot's nginx plugin auto-edits
#    /etc/nginx/sites-enabled/helixchannel to listen :443 and
#    redirects :80 -> :443. The HelixChannel systemd service
#    upstream is unchanged.
sudo certbot --nginx \
  -d helixchannel.example.com \
  --non-interactive --agree-tos -m ops@<host>

# 4. certbot.timer auto-renews within 30 days of expiry.
sudo systemctl status certbot.timer
sudo certbot renew --dry-run
```

### TLS verification

```bash
# From a third-party host (not the Lightsail box itself):
curl -sfI https://helixchannel.example.com/v1/models | head -1
# Expected: HTTP/2 200

openssl s_client -connect helixchannel.example.com:443 \
  -servername helixchannel.example.com < /dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -dates -subject
# Expected:
#   issuer=O = Let's Encrypt, CN = R10 / R11
#   notBefore=... notAfter=... (>=30 days remaining)
#   subject=CN = helixchannel.example.com
```

A `self-signed` issuer or a `notAfter < now+30d` result means the
certbot step did not complete; re-run `sudo certbot --nginx -d
helixchannel.example.com` and re-verify.

## nginx reverse-proxy config

The Lightsail host serves a single nginx site at
`/etc/nginx/sites-enabled/helixchannel`:

```nginx
# /etc/nginx/sites-enabled/helixchannel
#
# certbot's --nginx plugin maintains the listen :443 + cert paths
# below; this is the manual fallback if certbot cannot reach the
# webroot (e.g. ports 80/443 blocked at first deploy).

server {
    listen 80;
    server_name helixchannel.example.com;
    # certbot http-01 challenge; do not redirect, certbot needs :80.
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name helixchannel.example.com;

    ssl_certificate     /etc/letsencrypt/live/helixchannel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/helixchannel.example.com/privkey.pem;

    # AES-256-GCM cipher preference is enforced at the application
    # layer; nginx only does TLS 1.2+ with modern ciphers.
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;

    # Proxy to the HelixChannel router on loopback.
    location / {
        proxy_pass http://127.0.0.1:8742;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        # SSE / streaming responses: turn off buffering.
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

After editing, reload nginx without dropping in-flight requests:

```bash
sudo nginx -t    # syntax check
sudo systemctl reload nginx
```

## Rollback

If the public hostname is causing issues (cert expiry, DNS outage,
mistaken nginx config):

1. **DNS rollback** (operator can run from any host):
   ```bash
   KEY=$(op read op://<1password-vault>/<dreamhost-item-uuid>/<api-key-field-uuid> --out-file -f /tmp/.dh-key && cat /tmp/.dh-key && rm -f /tmp/.dh-key)
   curl -sS --data-urlencode "key=$KEY" \
     --data-urlencode "cmd=dns-remove_record" \
     --data-urlencode "record=helixchannel" \
     --data-urlencode "type=A" \
     --data-urlencode "value=203.0.113.10" \
     https://api.dreamhost.com/
   ```
2. **Nginx fallback** (Lightsail box): the binary clients keep the
   raw-IP fallback. Set `HELIXCHANNEL_BASE_URL=https://203.0.113.10`
   on each consumer; the hostname is dropped without code change.
3. **Certbot cleanup**: `sudo certbot delete --cert-name
   helixchannel.example.com` (non-destructive; nginx is left with a
   config that references the missing cert path; reload will fail
   until the site is disabled with `sudo rm
   /etc/nginx/sites-enabled/helixchannel && sudo systemctl reload
   nginx`).

The rollback is **non-destructive**: the raw-IP ingress on `:443`
remains valid throughout, and the DNS zone is `example.com` (no other
A-records are affected).

## Pilot consumer wiring

Kilo Code (or any OpenAI-compatible client) configures:

| Field | Value |
|---|---|
| `OPENAI_BASE_URL` | `https://helixchannel.example.com/v1` |
| Bearer token | (existing API key from `op item list --vault <1password-vault>`) |

`curl` smoke from the operator host:

```bash
# 200 + MiniMax-M3 model list confirms the wire is up.
curl -sS https://helixchannel.example.com/v1/models \
  -H "Authorization: Bearer $TOKEN" | jq '.data[].id'

# Streaming chat-completion:
curl -sS https://helixchannel.example.com/v1/chat/completions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "MiniMax-M3",
    "messages": [{"role": "user", "content": "ping"}],
    "stream": true
  }' | head -c 200
```

## Known constraints

- **Lightsail static IP**: `203.0.113.10`. If the operator swaps
  the static IP, the DreamHost A-record MUST be re-pushed.
- **TLS provider**: Let's Encrypt R10/R11 only (the default
  `certbot --nginx` flow). Self-signed fallback is for offline CI
  only; do not ship self-signed certs to pilot consumers.
- **Cipher suite**: TLS 1.2 / 1.3 only. The browser-fingerprint
  does NOT need legacy compat; AES-256-GCM dominates the cipher
  list. CHACHA20-POLY1305 is included for ARM clients.
- **Prometheus alerting** (planned v18714-12, follow-up): add
  `cert_expiry_seconds < 30 * 86400` to the existing
  `llm-cluster-router` Alertmanager rules. Until that ships,
  operators must monitor `certbot renew --dry-run` output.

## Operator handoff

This runbook assumes operator-level access to:

1. The DreamHost item in 1Password `<1password-vault>` (UUID + field
   UUID per `cursor-global-kb/global-memories/credentials-index.md`).
2. SSH access to the Lightsail instance `lightsail-tunnel` at
   `203.0.113.10` (per fleet-path-registry; restored via RustDesk
   CLI or direct LAN/Tailscale when the operator-side hop is
   available).
3. `sudo` on the Lightsail host for `apt-get`, `certbot`,
   `nginx`, and `systemctl`.

The agent role (per `00-p0-no-pushback.mdc`) is responsible for
step 1 (DreamHost API call) and step 4 (binary client
verification). Steps 2 and 3 require operator-level access and are
the only true handoffs in this story.