# opentunnel-aio-relay

Single-binary, self-hosted relay server for the [OpenTunnel](https://github.com/anomalyco/opentunnel)
protocol ("blind TLS tunnels", a privacy-focused ngrok alternative).

It replaces the official Cloudflare deployment (Worker + Durable Objects +
certificate Workflow + external TCP relay) with **one static binary on one VPS**.
The existing API remains compatible with official clients, including tunnel
creation without a server-wide admin token.

## How it works

One process listens on a single TCP port (default 443) and demultiplexes by
TLS SNI, peeking only at the ClientHello:

```
:443 ──peek SNI──┬─ SNI == tunnel.example.com ──▶ terminate TLS locally ──▶ HTTP API + bridge WebSocket
                 └─ SNI == * .tunnel.example.com ──▶ blind passthrough ──▶ bridge WS ──▶ client ──▶ local app
```

- **API branch**: TLS is terminated with an auto-issued certificate for the
  API domain; serves the provisioning API and the bridge WebSocket.
- **Tunnel branch**: bytes are forwarded *encrypted*. TLS is terminated by the
  client on its own machine, exactly like the official service — this server
  never sees plaintext ("blind").

Cloudflare concepts map 1:1:

| Hosted (official) | This server |
|---|---|
| Worker HTTP API | axum router, same paths & shapes |
| Durable Object per tunnel | in-process session + SQLite row |
| DO alarm (renewal timer) | background hourly task |
| Certificate Workflow | async ACME task (RFC 8555, DNS-01) |
| AWS TCP relay | gone — the binary listens on 443 directly |

## Quick start

### 1. DNS

Point these at your VPS (all **DNS only**, not proxied):

```
tunnel.example.com      A    203.0.113.10
*.tunnel.example.com    A    203.0.113.10
```

### 2. Credentials

- **Cloudflare API token** with DNS-edit access to the zone (for ACME DNS-01).
  Certificates come from **Let's Encrypt** by default — no extra account needed.

### 3. Run

```bash
export OT_DOMAIN=tunnel.example.com
export OT_CF_TOKEN=your-cloudflare-token
export OT_CF_ZONE_ID=your-zone-id
# Optional: test against Let's Encrypt staging first
# export OT_ACME_URL=https://acme-staging-v02.api.letsencrypt.org/directory

./opentunnel-relay
# or: ./opentunnel-relay --domain tunnel.example.com --cf-token ... (see --help)
```

On first start it issues a TLS certificate for `tunnel.example.com` via ACME
DNS-01 and stores it in `./data/` next to `relay.db`. No manual cert handling.

### 4. Use it

Point the official client at this relay and create a tunnel as usual:

```bash
export OPENTUNNEL_API=https://tunnel.example.com
opentunnel route add 3000
```

The `POST /api/tunnel` provisioning endpoint intentionally does not require a
server-wide bearer token, so stock official clients work unchanged. Each
created tunnel still has its own bearer token for tunnel-specific API calls.

## Abuse protection

Tunnel creation uses the TCP peer's source IP (not `X-Forwarded-For`) for the
optional allowlist and per-IP sliding-window rate limit. The defaults allow
any source IP, limit each IP to **5 creation attempts per 60 seconds**, and
allow up to **1,000 non-deleted tunnels**. Set an allowlist for a private relay
or trusted client network; IPv4/IPv6 addresses and CIDRs are accepted. Deleted
tunnels no longer count toward the active-tunnel cap.

The source IP is the address seen by the relay's TCP listener. If a TCP proxy
sits in front of the relay, all requests may appear to come from that proxy;
forwarded HTTP headers are deliberately not trusted for access control. Rate
limit state is held in this process's memory and resets on restart; deployments
with multiple relay instances need an upstream shared limiter as well.

## Configuration

All options are flags or `OT_*` environment variables (`--help` for the list):

| Variable | Default | Purpose |
|---|---|---|
| `OT_DOMAIN` | — (required) | Public domain, e.g. `tunnel.example.com` |
| `OT_LISTEN` | `0.0.0.0:443` | TCP listen address |
| `OT_DATA_DIR` | `./data` | SQLite db + API certificate storage |
| `OT_TUNNEL_CREATE_IP_ALLOWLIST` | empty (allow any IP) | Comma-separated IP addresses/CIDRs allowed to create tunnels, e.g. `203.0.113.7/32,2001:db8::/32` |
| `OT_TUNNEL_CREATE_RATE_LIMIT` | `5` | Maximum tunnel-creation attempts per source IP during the rate window |
| `OT_TUNNEL_CREATE_RATE_WINDOW_SECS` | `60` | Sliding-window duration in seconds; must be greater than zero |
| `OT_MAX_ACTIVE_TUNNELS` | `1000` | Maximum number of non-deleted tunnels |
| `OT_CF_TOKEN` / `OT_CF_ZONE_ID` | — (required) | Cloudflare DNS for ACME challenges |
| `OT_ACME_EAB_KID` / `OT_ACME_EAB_HMAC` | — (empty) | Only for CAs that require EAB (e.g. ZeroSSL) |
| `OT_ACME_URL` | Let's Encrypt production | ACME directory; use `https://acme-staging-v02.api.letsencrypt.org/directory` for testing |
| `OT_ACME_EMAIL` | `acme@localhost` | ACME account contact |

## systemd example

```ini
[Unit]
Description=opentunnel-relay
After=network-online.target

[Service]
Type=simple
User=opentunnel
WorkingDirectory=/opt/opentunnel-relay
EnvironmentFile=/opt/opentunnel-relay/secrets.env
ExecStart=/opt/opentunnel-relay/opentunnel-relay
Restart=on-failure
# Keep newly created database, WAL, and key files private.
UMask=0077
# 443 needs a privileged port:
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`secrets.env` holds the `OT_*` variables (mode 600, owned by the service user).
The service data directory should be owned by `opentunnel` and mode 700; the
relay also restricts the SQLite database and API private key to mode 600.

## Certificates

- **Tunnel certificates** (`<id>.tunnel.example.com` + wildcard): issued on
  demand when the client submits its CSR. The client's private key never leaves
  the client's machine — the server only ever sees the CSR.
- **Renewal**: a background task renews certificates expiring within 30 days
  for tunnels seen in the last 90 days, reusing the stored CSR (the key never
  changes). Attaching with a near-expiry certificate also triggers renewal.
- **API certificate**: issued at first startup, reused afterwards, and renewed
  in the background before expiry; new TLS handshakes use the renewed cert.

## Building

```bash
cargo build --release
```

~10 MB static-ish binary (glibc). For a fully static musl build:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

(ring is used as the TLS crypto provider throughout, so musl builds work.)

## Testing

```bash
cargo test
```

- `tests/vectors.rs` — the official spec vectors from
  `anomalyco/opentunnel` (`spec/vectors`): route validation, SNI routing,
  data-frame encoding, control-message round-trips. If these pass, this server
  speaks the exact wire protocol of the official clients.
- `tests/e2e.rs` — full loop over real sockets: TCP ingress → SNI routing →
  API TLS → REST provisioning → bridge WebSocket attach → proxied `open`,
  including half-close response delivery, multiple-bridge isolation, and
  immediate connection shutdown after tunnel deletion.
- Unit tests: ClientHello parser, CSR validation (incl. tampered signatures).

### End-to-end with the official client (CI)

The `integration` job downloads the official `opentunnel` CLI release binary
(tracks upstream `latest` by default — see `OFFICIAL_CLIENT_RELEASE` in the
workflow; pin a version for reproducible runs), verifies it against GitHub's
release-asset SHA-256 digest, starts this relay, and uses the official client
to create a tunnel, attach the bridge WebSocket, and fetch a page through the
SNI-routed TLS connection. This also verifies that stock clients can provision
tunnels without a server-specific admin token. It needs real Let's Encrypt
certificates (the official client only
trusts the bundled Mozilla roots), so it performs live ACME DNS-01 issuance —
2 certificates per run.

Each run uses a unique API subdomain derived from the GitHub run ID, avoiding
repeated identical certificate identifier sets against Let's Encrypt.

One-time setup (repo Settings → Secrets → Actions):

| Secret | Purpose |
|---|---|
| `CI_DOMAIN` | e.g. `ci-relay.example.com` — DNS hosted on Cloudflare; no A record needed |
| `CI_CF_TOKEN` | Cloudflare API token, DNS-edit on that zone |
| `CI_CF_ZONE_ID` | Cloudflare zone ID of the domain |

Without these secrets the job skips itself (forks stay green). To respect
Let's Encrypt's rate limit (50 certs per registered domain per week) it runs
on tag pushes, a daily schedule, and manual dispatch — not on every push.

## Security model

Same as the official service: the relay only ever sees ciphertext. It does
observe metadata (SNI hostnames, client IPs, byte counts). Self-hosting removes
the need to trust a third-party operator at all. Tunnel creation can be
restricted by source IP and is protected by a per-IP rate limit and the active
tunnel cap. The relay also limits concurrent ClientHello inspections to 256,
ClientHello inspection to 64 KiB with a 10-second timeout, API header reads to
15 seconds, and bridge WebSocket messages/frames to 64 KiB. These controls are
defense-in-depth, not a replacement for host firewalling and sensible IP
allowlist configuration on a private relay.

## License

MIT. Protocol types and spec vectors are adapted from
[anomalyco/opentunnel](https://github.com/anomalyco/opentunnel) (MIT).
