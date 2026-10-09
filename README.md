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
the need to trust a third-party operator at all.

## License

MIT. Protocol types and spec vectors are adapted from
[anomalyco/opentunnel](https://github.com/anomalyco/opentunnel) (MIT).
