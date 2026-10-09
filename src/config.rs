use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

use crate::guard::CidrList;

/// Single-binary self-hosted relay for the OpenTunnel protocol.
///
/// Listens on one TCP port (default 443) and demultiplexes by TLS SNI:
/// - SNI == `domain`            -> terminates TLS locally, serves the HTTP API
/// - SNI == `*.<domain>`        -> blind TCP passthrough to the tunnel's bridge
///   (TLS is terminated by the client; this server never sees plaintext)
#[derive(Debug, Parser, Clone)]
#[command(name = "opentunnel-relay", version)]
pub struct Config {
    /// Public domain served by this relay, e.g. tunnel.example.com.
    /// Tunnel hostnames become <id>.<domain>; the API lives at https://<domain>.
    #[arg(long, env = "OT_DOMAIN")]
    pub domain: String,

    /// TCP listen address. One port serves both the API and tunnel ingress.
    #[arg(long, env = "OT_LISTEN", default_value = "0.0.0.0:443")]
    pub listen: String,

    /// Directory for the SQLite database and the API TLS certificate/key.
    #[arg(long, env = "OT_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Cloudflare API token with DNS edit access to the zone of OT_DOMAIN.
    /// Used for ACME DNS-01 challenges.
    #[arg(long, env = "OT_CF_TOKEN")]
    pub cf_token: String,

    /// Cloudflare zone ID of OT_DOMAIN.
    #[arg(long, env = "OT_CF_ZONE_ID")]
    pub cf_zone_id: String,

    /// ACME external account binding. Only needed for CAs that require it
    /// (e.g. ZeroSSL: dashboard -> Developer). Leave empty for Let's Encrypt.
    #[arg(long, env = "OT_ACME_EAB_KID", default_value = "")]
    pub acme_eab_kid: String,

    #[arg(long, env = "OT_ACME_EAB_HMAC", default_value = "")]
    pub acme_eab_hmac: String,

    /// ACME directory URL. Defaults to Let's Encrypt production.
    /// For testing, use the staging server:
    /// https://acme-staging-v02.api.letsencrypt.org/directory
    #[arg(
        long,
        env = "OT_ACME_URL",
        default_value = "https://acme-v02.api.letsencrypt.org/directory"
    )]
    pub acme_url: String,

    #[arg(long, env = "OT_ACME_EMAIL", default_value = "acme@localhost")]
    pub acme_email: String,

    /// Maximum number of live (not deleted) tunnels. 0 disables the limit.
    #[arg(long, env = "OT_MAX_TUNNELS", default_value_t = 1000)]
    pub max_tunnels: u64,

    /// Maximum new certificate orders per rolling 24 hours, counted across all
    /// tunnels. Renewals are never refused, but they count toward the total so
    /// the figure reflects what Let's Encrypt sees. 0 disables the limit.
    #[arg(long, env = "OT_MAX_CERTS_PER_DAY", default_value_t = 7)]
    pub max_certs_per_day: u64,

    /// Maximum connections open at once on the listener: API requests, bridge
    /// sockets, and visitor sockets together. Excess connections are refused
    /// at accept. 0 disables the limit.
    #[arg(long, env = "OT_MAX_CONNECTIONS", default_value_t = 1024)]
    pub max_connections: usize,

    /// Connection slots that visitors may never take. While visitors are at
    /// their limit, API and bridge connections can still use these slots.
    /// Must be below OT_MAX_CONNECTIONS unless that is 0.
    #[arg(long, env = "OT_RESERVED_CONNECTIONS", default_value_t = 64)]
    pub reserved_connections: usize,

    /// Connections one source address may hold open at once, counting API,
    /// bridge, and visitor sockets. IPv6 sources are counted per /64. Excess
    /// connections are refused at accept. 0 disables the limit.
    #[arg(long, env = "OT_MAX_CONNECTIONS_PER_IP", default_value_t = 64)]
    pub max_connections_per_ip: usize,

    /// Bytes the relay will hold for one visitor that is not reading. A visitor
    /// that falls further behind is reset with `backpressure`; other connections
    /// are unaffected. Worst-case memory is this value times the number of open
    /// connections, so size it with OT_MAX_CONNECTIONS.
    #[arg(long, env = "OT_STREAM_BUFFER_BYTES", default_value_t = 2 * 1024 * 1024)]
    pub stream_buffer_bytes: usize,

    /// Seconds a forwarded connection may go without bytes in either direction
    /// before it is closed. Long-lived sessions such as SSH or WebSockets need
    /// a generous value. 0 disables the limit.
    #[arg(
        long = "stream-idle-secs",
        env = "OT_STREAM_IDLE_SECS",
        default_value = "3600",
        value_parser = parse_seconds
    )]
    pub stream_idle: Duration,

    /// Source addresses allowed to create tunnels and order certificates, as
    /// comma-separated IPv4 or IPv6 addresses or CIDR ranges. Empty allows any
    /// source. Checked before the rate limit.
    #[arg(long, env = "OT_CREATE_ALLOW_CIDRS", default_value = "")]
    pub create_allow_cidrs: CidrList,

    /// Requests per hour from one source address to `POST /api/tunnel` and
    /// `POST /api/tunnel/{id}/certificate`. IPv6 sources are counted per /64.
    /// 0 disables the limit.
    #[arg(long, env = "OT_RATE_LIMIT_PER_HOUR", default_value_t = 30)]
    pub rate_limit_per_hour: u32,

    #[arg(skip)]
    pub timeouts: Timeouts,
}

impl Config {
    /// Puts operator-supplied values into the canonical form the rest of the
    /// server compares against. Run once at startup, before anything serves.
    pub fn normalize(&mut self) -> anyhow::Result<()> {
        self.domain = normalize_domain(&self.domain);
        anyhow::ensure!(!self.domain.is_empty(), "OT_DOMAIN is empty");
        anyhow::ensure!(
            self.stream_buffer_bytes >= MIN_STREAM_BUFFER_BYTES,
            "OT_STREAM_BUFFER_BYTES must be at least {MIN_STREAM_BUFFER_BYTES}"
        );
        anyhow::ensure!(
            self.max_connections == 0 || self.reserved_connections < self.max_connections,
            "OT_RESERVED_CONNECTIONS ({}) must be below OT_MAX_CONNECTIONS ({})",
            self.reserved_connections,
            self.max_connections
        );
        Ok(())
    }
}

/// Two full-size frames: enough for one in flight and one waiting.
const MIN_STREAM_BUFFER_BYTES: usize = 2 * crate::proto::bridge::MAX_PAYLOAD_SIZE;

fn parse_seconds(value: &str) -> Result<Duration, String> {
    value
        .trim()
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("expected a whole number of seconds, got {value:?}"))
}

/// Lowercases a domain and strips surrounding whitespace and trailing dots,
/// so `Tunnel.Example.COM.` and `tunnel.example.com` name the same zone.
pub fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Internal time budgets. Not exposed as flags: they only need to change in tests.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Time a client gets to send its ClientHello, finish the TLS handshake, and
    /// send the headers of each API request.
    pub client_hello: Duration,
    /// How long a visitor may accept no bytes while relayed data waits for it
    /// before that one connection is reset. The bridge reader never waits on a
    /// visitor, so this only bounds how long a stalled connection holds its buffer.
    pub bridge_stall: Duration,
    /// Upper bound for one ACME order, including DNS propagation. A timed-out
    /// order is marked failed and its TXT records are removed. An issuance
    /// still marked in flight after twice this long is taken over.
    pub issuance: Duration,
}

impl Timeouts {
    /// How long an issuance or renewal lease may be held before another
    /// attempt may take it over. Set well above `issuance` so a slow but live
    /// order is never raced.
    pub fn lease(&self) -> Duration {
        self.issuance * 2
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            client_hello: Duration::from_secs(10),
            bridge_stall: Duration::from_secs(10),
            issuance: Duration::from_secs(600),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn domain_is_normalized() {
        assert_eq!(
            normalize_domain("Tunnel.Example.COM."),
            "tunnel.example.com"
        );
        assert_eq!(normalize_domain("  relay.test  "), "relay.test");
        assert_eq!(normalize_domain("relay.test.."), "relay.test");
    }

    fn parse(extra: &[&str]) -> Config {
        let mut args = vec![
            "opentunnel-relay",
            "--domain",
            "relay.test",
            "--cf-token",
            "t",
            "--cf-zone-id",
            "z",
        ];
        args.extend_from_slice(extra);
        Config::try_parse_from(args).unwrap()
    }

    #[test]
    fn stream_idle_is_read_in_seconds_and_zero_disables_it() {
        assert_eq!(parse(&[]).stream_idle, Duration::from_secs(3600));
        assert_eq!(
            parse(&["--stream-idle-secs", "90"]).stream_idle,
            Duration::from_secs(90)
        );
        assert_eq!(
            parse(&["--stream-idle-secs", "0"]).stream_idle,
            Duration::ZERO
        );
        assert!(Config::try_parse_from([
            "opentunnel-relay",
            "--domain",
            "relay.test",
            "--cf-token",
            "t",
            "--cf-zone-id",
            "z",
            "--stream-idle-secs",
            "5m",
        ])
        .is_err());
    }

    #[test]
    fn reserved_connections_must_leave_room_for_visitors() {
        let mut config = parse(&["--max-connections", "64", "--reserved-connections", "64"]);
        assert!(config.normalize().is_err());

        let mut config = parse(&["--max-connections", "64", "--reserved-connections", "63"]);
        assert!(config.normalize().is_ok());

        let mut config = parse(&["--max-connections", "0", "--reserved-connections", "64"]);
        assert!(config.normalize().is_ok());
    }

    #[test]
    fn stream_buffer_has_a_floor() {
        let mut config = parse(&["--stream-buffer-bytes", "1024"]);
        assert!(config.normalize().is_err());
    }

    #[test]
    fn empty_domain_is_rejected() {
        let mut config = Config::try_parse_from([
            "opentunnel-relay",
            "--domain",
            " . ",
            "--cf-token",
            "t",
            "--cf-zone-id",
            "z",
        ])
        .unwrap();
        assert!(config.normalize().is_err());
    }
}
