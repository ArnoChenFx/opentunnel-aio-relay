# opentunnel-aio-relay

Single-binary, self-hosted relay server for the [OpenTunnel](https://github.com/anomalyco/opentunnel)
protocol ("blind TLS tunnels", a privacy-focused ngrok alternative).

It replaces the official Cloudflare deployment (Worker + Durable Objects +
certificate Workflow + external TCP relay) with **one static binary on one VPS**.
Existing clients — the Rust CLI (`opentunnel`) and the TypeScript SDK — work
unchanged: just point them at your server.

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

```bash
export OPENTUNNEL_API=https://tunnel.example.com
opentunnel route add 3000
# → https://<random>.<tunnel-id>.tunnel.example.com
```

Tip: use a separate client profile (`--profile home` / `OPENTUNNEL_PROFILE`)
so you don't overwrite the tunnel identity you use with the official service.

## Configuration

All options are flags or `OT_*` environment variables (`--help` for the list):

| Variable | Default | Purpose |
|---|---|---|
| `OT_DOMAIN` | — (required) | Public domain, e.g. `tunnel.example.com` |
| `OT_LISTEN` | `0.0.0.0:443` | TCP listen address |
| `OT_DATA_DIR` | `./data` | SQLite db + API certificate storage |
| `OT_CF_TOKEN` / `OT_CF_ZONE_ID` | — (required) | Cloudflare DNS for ACME challenges |
| `OT_ACME_EAB_KID` / `OT_ACME_EAB_HMAC` | — (empty) | Only for CAs that require EAB (e.g. ZeroSSL) |
| `OT_ACME_URL` | Let's Encrypt production | ACME directory; use `https://acme-staging-v02.api.letsencrypt.org/directory` for testing |
| `OT_ACME_EMAIL` | `acme@localhost` | ACME account contact |
| `OT_MAX_CONNECTIONS` | `1024` | Connections open at once on the listener (API, bridge, and visitor sockets). Extra connections are refused at accept. `0` disables |
| `OT_RESERVED_CONNECTIONS` | `64` | Slots within `OT_MAX_CONNECTIONS` that visitor sockets may never take, so API and bridge connections still get in while visitors are at their limit. Must be below `OT_MAX_CONNECTIONS` unless that is `0` |
| `OT_MAX_CONNECTIONS_PER_IP` | `64` | Sockets one source address may hold open at once. IPv6 sources are counted per /64. Extra sockets are refused at accept. `0` disables |
| `OT_STREAM_BUFFER_BYTES` | `2097152` (2 MiB) | Data held for one visitor that has not read it yet. A visitor that falls further behind is reset with `backpressure`. Minimum `65536` |
| `OT_STREAM_IDLE_SECS` | `3600` (1 h) | Seconds a forwarded connection may go without bytes in either direction before it is closed and the bridge is told with `connection_terminated`. `0` disables the limit; raise it for long SSH or WebSocket sessions that stay quiet |
| `OT_MAX_TUNNELS` | `1000` | Live tunnels (not deleted). Creating one past the cap returns `503`. `0` disables |
| `OT_MAX_CERTS_PER_DAY` | `7` | New certificate orders per rolling 24 hours across all tunnels. Renewals are never refused. `0` disables |
| `OT_RATE_LIMIT_PER_HOUR` | `30` | Requests per hour from one source address to tunnel creation and certificate binding. IPv6 sources are counted per /64. `0` disables |
| `OT_CREATE_ALLOW_CIDRS` | — (empty: any source) | Comma-separated IPv4/IPv6 addresses or CIDR ranges allowed to create tunnels and bind certificates |

Fixed limits that are not configurable: the ClientHello and TLS handshake must
finish within 10 s, and each request's headers must arrive within 10 s. A
forwarded connection whose bridge sends nothing within 15 s of the visitor's
ClientHello is reset with `connection_terminated`. Once the first byte arrives
this check stops, and `OT_STREAM_IDLE_SECS` governs quiet streams. A visitor that
accepts no data for 10 s
while relayed data waits for it is reset alone, with `backpressure`. Every API
response except the bridge's WebSocket upgrade carries `Connection: close`. An
ACME order may run for 10 min. Calls to ACME and Cloudflare time out after 10 s
to connect and 30 s in total.

### Buffering for slow visitors

Each forwarded connection has its own buffer for data its visitor has not read
yet. The bridge reader never waits for a visitor, so a visitor that stops
reading cannot delay other connections or the bridge's heartbeats. A connection
whose buffer overflows is reset at once with `backpressure`, and the client is
told in the same step.

The protocol has no per-stream flow control, so the relay cannot pause one
connection without pausing all of them. A visitor that reads more slowly than
the bridge sends, for longer than its buffer holds, is reset. Raise
`OT_STREAM_BUFFER_BYTES` for bulk transfers to slow clients. Worst-case buffer
memory is `OT_MAX_CONNECTIONS` times `OT_STREAM_BUFFER_BYTES`, which is 2 GiB at
the defaults. Size the two together for the host's RAM.

### Connection limits

Every accepted socket counts against the global cap (`OT_MAX_CONNECTIONS`) and
against its source address's share (`OT_MAX_CONNECTIONS_PER_IP`). A socket whose
SNI names a tunnel, a visitor, also takes one of the visitor slots. Those slots
are the global cap minus `OT_RESERVED_CONNECTIONS`, so the reserved slots stay
free for API and bridge connections while visitors are at their limit.

Trade-offs to know:

- Sockets are counted by TCP peer address. Clients behind one NAT or proxy
  share a single share, and a load balancer in front of the relay makes every
  client look like one address. In those setups raise
  `OT_MAX_CONNECTIONS_PER_IP` or set it to `0`.
- A socket that has not sent its ClientHello yet counts only against the global
  and per-address caps. A flood of such sockets from many addresses can fill the
  global pool until the 10 s ClientHello timeout closes them. Filter or
  rate-limit at the network edge if that matters for your deployment.

## Abuse controls

`POST /api/tunnel` needs no credentials, and every tunnel it creates can then
order certificates. An open relay can therefore be used to create tunnels and
order certificates in bulk. The checks below run in this order. Each one is
optional.

1. **Source allowlist** (`OT_CREATE_ALLOW_CIDRS`): other addresses get `403`.
2. **Rate limit** (`OT_RATE_LIMIT_PER_HOUR`): per source address, in fixed
   one-hour windows. Over the limit, the relay answers `429` with `Retry-After`.
3. **Tunnel cap** (`OT_MAX_TUNNELS`): only `DELETE /api/tunnel/{id}` frees a
   slot. Idle tunnels are not reaped automatically.
4. **Certificate budget** (`OT_MAX_CERTS_PER_DAY`): new orders across all
   tunnels in a rolling 24 hours. Renewals always proceed. The default of 7 a
   day keeps a relay under Let's Encrypt's limit of 50 certificates per
   registered domain per week.

Trade-offs to know:

- The allowlist and the rate limit use the TCP peer address. The relay does not
  read `X-Forwarded-For` or similar headers. Behind a NAT or a load balancer,
  all clients share one source address and therefore one budget.
- Rate-limit counters live in memory and reset on restart. The table tracks at
  most 65,536 sources. When it is full, new sources get `429` until old windows
  expire.

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
# One file descriptor per open connection. Keep the limit above
# OT_MAX_CONNECTIONS (default 1024) with headroom; systemd's default soft
# limit can be as low as 1024.
LimitNOFILE=65536
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
- **Failed renewals do not replace the active certificate.** The tunnel keeps
  serving its current certificate until it expires. Failed attempts are retried
  with exponential backoff: 1 h, 2 h, 4 h, 8 h, then every 12 h.
- **Time limit per order**: an ACME order must finish within 10 minutes,
  including DNS propagation. Its DNS TXT records are removed on failure. Orders
  interrupted by a restart are requeued at startup.
- **API certificate**: issued at first startup and reused afterwards, as long
  as it is still valid and covers `OT_DOMAIN`. It is renewed in the background
  before expiry, and new TLS handshakes use the renewed certificate. If renewal
  fails, the still-valid certificate stays in service and a warning is logged.

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

- `tests/vectors.rs` — checks route validation, SNI routing, data-frame
  encoding, and control-message round-trips against the spec vectors copied
  from `anomalyco/opentunnel` (`spec/vectors`). Passing them shows agreement on
  those vectors only. It is not a conformance suite.
- `tests/e2e.rs` — full loop over real sockets: TCP ingress → SNI routing →
  API TLS → REST provisioning → bridge WebSocket attach → proxied `open`,
  including half-close response delivery, multiple-bridge isolation, and
  immediate connection shutdown after tunnel deletion. It also covers the
  provisioning controls, the tunnel and connection caps (global, per address,
  and visitor share), header and idle timeouts, and bridge stall and overflow
  handling.
- Unit tests: ClientHello parser, CSR validation (incl. tampered signatures),
  CIDR parsing and rate limiting, and the database and bridge state machines.
- `.github/scripts/test-fetch-official-client.sh` — offline checks for the CI
  download script: a verified digest succeeds, while a mismatched or missing
  digest fails closed without extracting anything.

### End-to-end with the official client (CI)

The `integration` job downloads the official `opentunnel` CLI from its GitHub
release. `OFFICIAL_CLIENT_RELEASE` selects the release: `latest` (the default)
or a tag such as `v0.4.0` to pin. `.github/scripts/fetch-official-client.sh`
resolves that release through the GitHub API, reads the sha256 digest GitHub
reports for `opentunnel-linux-x64.tar.gz`, and refuses to run the binary unless
the downloaded file matches it. The resolved tag is logged. Upstream publishes
no checksum file, so this API digest is the integrity reference. It guards
against corruption and substitution in transit. It does not guard against a
compromised upstream release, because GitHub serves both the asset and its
digest.

The job then starts this relay and runs a real tunnel: provision via the HTTP
API → attach the bridge WebSocket → fetch a page through the SNI-routed TLS
connection that the client terminates. It needs real Let's Encrypt
certificates (the official client only trusts the bundled Mozilla roots), so
it performs live ACME DNS-01 issuance — 2 certificates per run.

Each run serves its own hostname, `run-<run id>-<attempt>.<CI_DOMAIN>`, so the
certificate names never repeat. Let's Encrypt allows only 5 certificates per
identical name set per week, which a fixed hostname would exhaust after a few
reruns. The script deletes DNS-01 TXT records under that hostname when it
exits, and it deletes `_acme-challenge.run-*` records left by interrupted runs
before it starts. Failures are logged and do not fail the job.

One-time setup (repo Settings → Secrets → Actions):

| Secret | Purpose |
|---|---|
| `CI_DOMAIN` | e.g. `ci-relay.example.com` — DNS hosted on Cloudflare; no A record needed |
| `CI_CF_TOKEN` | Cloudflare API token, DNS-edit on that zone |
| `CI_CF_ZONE_ID` | Cloudflare zone ID of the domain |

Without these secrets the job skips itself (forks stay green). To respect
Let's Encrypt's rate limit (50 certs per registered domain per week) it runs
on tag pushes, a weekly schedule (Mondays), and manual dispatch — not on every
push. The weekly schedule also covers the unit tests and release builds.
The relay's data directory is never cached between runs, so issued keys and
account keys do not end up in the Actions cache.

## Security model

Same as the official service: the relay only ever sees ciphertext. It does
observe metadata (SNI hostnames, client IPs, byte counts). Self-hosting removes
the need to trust a third-party operator at all. Tunnel creation is open by
default, so read [Abuse controls](#abuse-controls) before exposing a relay
publicly.

## License

MIT. Protocol types and spec vectors are adapted from
[anomalyco/opentunnel](https://github.com/anomalyco/opentunnel) (MIT).
