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

    /// DNS service that publishes the ACME DNS-01 TXT records: `cloudflare` or
    /// `aliyun`. Empty picks `aliyun` when only Alibaba Cloud credentials are
    /// set, and `cloudflare` otherwise.
    #[arg(long, env = "OT_DNS_PROVIDER", default_value = "")]
    pub dns_provider: String,

    /// Cloudflare API token with DNS edit access to the zone of OT_DOMAIN.
    /// Required when the DNS provider is `cloudflare`.
    #[arg(long, env = "OT_CF_TOKEN", default_value = "")]
    pub cf_token: String,

    /// Cloudflare zone ID of OT_DOMAIN. Required when the DNS provider is `cloudflare`.
    #[arg(long, env = "OT_CF_ZONE_ID", default_value = "")]
    pub cf_zone_id: String,

    /// AccessKey ID of an Alibaba Cloud RAM user that may manage TXT records in
    /// the zone of OT_DOMAIN. Required when the DNS provider is `aliyun`.
    #[arg(long, env = "OT_ALIYUN_ACCESS_KEY_ID", default_value = "")]
    pub aliyun_access_key_id: String,

    /// AccessKey secret of OT_ALIYUN_ACCESS_KEY_ID.
    #[arg(long, env = "OT_ALIYUN_ACCESS_KEY_SECRET", default_value = "")]
    pub aliyun_access_key_secret: String,

    /// Registered domain in Alibaba Cloud DNS that contains OT_DOMAIN, such as
    /// example.com. Empty looks the zone up with DescribeDomains.
    #[arg(long, env = "OT_ALIYUN_DOMAIN", default_value = "")]
    pub aliyun_domain: String,

    /// Alibaba Cloud DNS API host. The public endpoint is the default.
    #[arg(
        long,
        env = "OT_ALIYUN_ENDPOINT",
        default_value = "alidns.aliyuncs.com"
    )]
    pub aliyun_endpoint: String,

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

    /// Contact address for the ACME account, used by Let's Encrypt for expiry
    /// notices. Empty registers the account without one. Must look like
    /// `local@domain.example`. Changing it does not update an existing account.
    #[arg(long, env = "OT_ACME_EMAIL", default_value = "")]
    pub acme_email: String,

    /// Seconds to wait for new ACME TXT records to show up through public DNS
    /// resolvers before asking the CA to validate. A miss is logged and does not
    /// fail the order. 0 asks the CA as soon as the records are placed.
    #[arg(
        long = "dns-propagation-secs",
        env = "OT_DNS_PROPAGATION_SECS",
        default_value = "120",
        value_parser = parse_seconds
    )]
    pub dns_propagation: Duration,

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
    #[arg(long, env = "OT_STREAM_BUFFER_BYTES", default_value_t = 512 * 1024)]
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

    /// Maximum lifetime of one proxied visitor connection, even when bytes or
    /// pings keep moving. 0 disables the limit.
    #[arg(
        long = "stream-max-secs",
        env = "OT_STREAM_MAX_SECS",
        default_value = "86400",
        value_parser = parse_seconds
    )]
    pub stream_max_lifetime: Duration,

    /// How long an offline tunnel may stay in the in-memory session cache after
    /// its last bridge detaches. 0 disables eviction.
    #[arg(
        long = "session-cache-idle-secs",
        env = "OT_SESSION_CACHE_IDLE_SECS",
        default_value = "86400",
        value_parser = parse_seconds
    )]
    pub session_cache_idle: Duration,

    /// Deleted tunnels are hard-removed from SQLite after this many days.
    /// 0 disables purge (rows stay as tombstones forever).
    #[arg(long, env = "OT_TUNNEL_TOMBSTONE_DAYS", default_value_t = 30)]
    pub tunnel_tombstone_days: u64,

    /// Maximum ACME orders (initial issuance and renewal) running at once.
    /// 0 means no limit.
    #[arg(long, env = "OT_ACME_CONCURRENCY", default_value_t = 3)]
    pub acme_concurrency: usize,

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

/// The DNS service that publishes ACME DNS-01 TXT records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProviderKind {
    Cloudflare,
    Aliyun,
}

impl DnsProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Aliyun => "aliyun",
        }
    }
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
        self.aliyun_access_key_id = self.aliyun_access_key_id.trim().to_string();
        self.aliyun_access_key_secret = self.aliyun_access_key_secret.trim().to_string();
        self.aliyun_domain = normalize_domain(&self.aliyun_domain);
        self.aliyun_endpoint = normalize_endpoint(&self.aliyun_endpoint)?;
        self.acme_email = self.acme_email.trim().to_string();
        if !self.acme_email.is_empty() {
            validate_acme_email(&self.acme_email)?;
        }
        if self.dns_provider_kind()? == DnsProviderKind::Aliyun && !self.aliyun_domain.is_empty() {
            anyhow::ensure!(
                self.domain == self.aliyun_domain
                    || self.domain.ends_with(&format!(".{}", self.aliyun_domain)),
                "OT_DOMAIN ({}) is not inside OT_ALIYUN_DOMAIN ({})",
                self.domain,
                self.aliyun_domain
            );
        }
        if self.max_connections == 0 {
            tracing::warn!(
                "OT_MAX_CONNECTIONS=0 disables the global connection cap (not a safe default)"
            );
        }
        if self.max_tunnels == 0 {
            tracing::warn!(
                "OT_MAX_TUNNELS=0 disables the live-tunnel cap (not a safe default)"
            );
        }
        if self.rate_limit_per_hour == 0 {
            tracing::warn!(
                "OT_RATE_LIMIT_PER_HOUR=0 disables provisioning rate limiting (not a safe default)"
            );
        }
        Ok(())
    }

    /// The DNS service in use: the one named by OT_DNS_PROVIDER, or else the
    /// one whose credentials are set, with Cloudflare when both are.
    pub fn dns_provider_kind(&self) -> anyhow::Result<DnsProviderKind> {
        let has_cloudflare = !self.cf_token.trim().is_empty() || !self.cf_zone_id.trim().is_empty();
        let has_aliyun = !self.aliyun_access_key_id.trim().is_empty()
            || !self.aliyun_access_key_secret.trim().is_empty();
        let kind = match self.dns_provider.trim().to_ascii_lowercase().as_str() {
            "cloudflare" => DnsProviderKind::Cloudflare,
            "aliyun" => DnsProviderKind::Aliyun,
            "" if has_aliyun && !has_cloudflare => DnsProviderKind::Aliyun,
            "" if !has_cloudflare && !has_aliyun => anyhow::bail!(
                "no DNS credentials are set: set OT_CF_TOKEN and OT_CF_ZONE_ID for Cloudflare, \
                 or OT_ALIYUN_ACCESS_KEY_ID and OT_ALIYUN_ACCESS_KEY_SECRET for Alibaba Cloud DNS"
            ),
            "" => DnsProviderKind::Cloudflare,
            other => {
                anyhow::bail!("OT_DNS_PROVIDER must be `cloudflare` or `aliyun`, got {other:?}")
            }
        };
        let required: [(&str, &String); 2] = match kind {
            DnsProviderKind::Cloudflare => [
                ("OT_CF_TOKEN", &self.cf_token),
                ("OT_CF_ZONE_ID", &self.cf_zone_id),
            ],
            DnsProviderKind::Aliyun => [
                ("OT_ALIYUN_ACCESS_KEY_ID", &self.aliyun_access_key_id),
                (
                    "OT_ALIYUN_ACCESS_KEY_SECRET",
                    &self.aliyun_access_key_secret,
                ),
            ],
        };
        let missing: Vec<&str> = required
            .iter()
            .filter(|(_, value)| value.trim().is_empty())
            .map(|(name, _)| *name)
            .collect();
        anyhow::ensure!(
            missing.is_empty(),
            "the {} DNS provider needs {}",
            kind.as_str(),
            missing.join(" and ")
        );
        Ok(kind)
    }
}

/// Canonical form of the Alibaba Cloud DNS endpoint: a bare host name, which
/// may carry a port.
fn normalize_endpoint(raw: &str) -> anyhow::Result<String> {
    let endpoint = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if endpoint.is_empty() {
        return Ok("alidns.aliyuncs.com".to_string());
    }
    anyhow::ensure!(
        !endpoint.contains("://")
            && !endpoint.contains('/')
            && !endpoint.contains(char::is_whitespace),
        "OT_ALIYUN_ENDPOINT must be a host name such as alidns.aliyuncs.com, got {raw:?}"
    );
    Ok(endpoint)
}

/// Checks an ACME contact address for the shape Let's Encrypt requires: a
/// non-empty local part, then a domain with at least one dot and no empty
/// labels. This is not a full RFC 5322 parse.
fn validate_acme_email(email: &str) -> anyhow::Result<()> {
    let well_formed = !email.chars().any(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
        });
    anyhow::ensure!(
        well_formed,
        "OT_ACME_EMAIL must look like local@domain.example, got {email:?}; \
         leave it empty to register the ACME account without a contact address"
    );
    Ok(())
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
    /// How long a forwarded connection may wait for the first byte from its
    /// bridge after the ClientHello is forwarded. A TLS server answers at once,
    /// so silence this long means the local service is not there. Once a byte
    /// has arrived, only `OT_STREAM_IDLE_SECS` applies.
    pub tls_first_response: Duration,
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
            tls_first_response: Duration::from_secs(15),
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

    #[test]
    fn cloudflare_is_the_default_dns_provider() {
        let config = parse(&["--dns-provider", ""]);
        assert_eq!(
            config.dns_provider_kind().unwrap(),
            DnsProviderKind::Cloudflare
        );
    }

    #[test]
    fn aliyun_is_chosen_when_only_its_credentials_are_set() {
        let config = Config::try_parse_from([
            "opentunnel-relay",
            "--domain",
            "relay.test",
            "--dns-provider",
            "",
            "--cf-token",
            "",
            "--cf-zone-id",
            "",
            "--aliyun-access-key-id",
            "LTAItest",
            "--aliyun-access-key-secret",
            "secret",
        ])
        .unwrap();
        assert_eq!(config.dns_provider_kind().unwrap(), DnsProviderKind::Aliyun);
    }

    #[test]
    fn cloudflare_is_chosen_when_both_providers_have_credentials() {
        let config = Config::try_parse_from([
            "opentunnel-relay",
            "--domain",
            "relay.test",
            "--dns-provider",
            "",
            "--cf-token",
            "t",
            "--cf-zone-id",
            "z",
            "--aliyun-access-key-id",
            "LTAItest",
            "--aliyun-access-key-secret",
            "secret",
        ])
        .unwrap();
        assert_eq!(
            config.dns_provider_kind().unwrap(),
            DnsProviderKind::Cloudflare
        );
    }

    #[test]
    fn an_explicit_provider_wins_and_needs_its_own_credentials() {
        let config = Config::try_parse_from([
            "opentunnel-relay",
            "--domain",
            "relay.test",
            "--dns-provider",
            "ALIYUN",
            "--cf-token",
            "t",
            "--cf-zone-id",
            "z",
            "--aliyun-access-key-id",
            "LTAItest",
            "--aliyun-access-key-secret",
            "secret",
        ])
        .unwrap();
        assert_eq!(config.dns_provider_kind().unwrap(), DnsProviderKind::Aliyun);

        let mut config = Config::try_parse_from([
            "opentunnel-relay",
            "--domain",
            "relay.test",
            "--dns-provider",
            "aliyun",
            "--cf-token",
            "t",
            "--cf-zone-id",
            "z",
            "--aliyun-access-key-id",
            "",
            "--aliyun-access-key-secret",
            "",
        ])
        .unwrap();
        let error = config.normalize().unwrap_err().to_string();
        assert!(error.contains("OT_ALIYUN_ACCESS_KEY_ID"), "{error}");
    }

    #[test]
    fn unknown_provider_and_missing_credentials_are_rejected() {
        let config = parse(&["--dns-provider", "route53"]);
        assert!(config.dns_provider_kind().is_err());

        let config = Config::try_parse_from([
            "opentunnel-relay",
            "--domain",
            "relay.test",
            "--dns-provider",
            "",
            "--cf-token",
            "",
            "--cf-zone-id",
            "",
        ])
        .unwrap();
        let error = config.dns_provider_kind().unwrap_err().to_string();
        assert!(error.contains("OT_CF_TOKEN"), "{error}");
        assert!(error.contains("OT_ALIYUN_ACCESS_KEY_ID"), "{error}");
    }

    #[test]
    fn aliyun_domain_must_contain_the_relay_domain() {
        let with_zone = |domain: &str, zone: &str| {
            Config::try_parse_from([
                "opentunnel-relay",
                "--domain",
                domain,
                "--dns-provider",
                "aliyun",
                "--cf-token",
                "",
                "--cf-zone-id",
                "",
                "--aliyun-access-key-id",
                "LTAItest",
                "--aliyun-access-key-secret",
                "secret",
                "--aliyun-domain",
                zone,
            ])
            .unwrap()
        };
        assert!(with_zone("relay.test", "example.com").normalize().is_err());
        assert!(with_zone("tunnel.example.com", "example.com")
            .normalize()
            .is_ok());
        assert!(with_zone("Tunnel.Example.COM.", "example.com.")
            .normalize()
            .is_ok());
    }

    #[test]
    fn aliyun_endpoint_must_be_a_bare_host() {
        let endpoint_after_normalize = |endpoint: &str| {
            let mut config = Config::try_parse_from([
                "opentunnel-relay",
                "--domain",
                "relay.test",
                "--dns-provider",
                "aliyun",
                "--cf-token",
                "",
                "--cf-zone-id",
                "",
                "--aliyun-access-key-id",
                "LTAItest",
                "--aliyun-access-key-secret",
                "secret",
                "--aliyun-endpoint",
                endpoint,
            ])
            .unwrap();
            config.normalize().map(|()| config.aliyun_endpoint)
        };
        assert_eq!(
            endpoint_after_normalize("Alidns.AliyunCS.com.").unwrap(),
            "alidns.aliyuncs.com"
        );
        assert_eq!(endpoint_after_normalize("").unwrap(), "alidns.aliyuncs.com");
        assert!(endpoint_after_normalize("https://alidns.aliyuncs.com").is_err());
        assert!(endpoint_after_normalize("alidns.aliyuncs.com/path").is_err());
    }

    #[test]
    fn dns_propagation_is_read_in_seconds_and_zero_skips_the_wait() {
        assert_eq!(parse(&[]).dns_propagation, Duration::from_secs(120));
        assert_eq!(
            parse(&["--dns-propagation-secs", "45"]).dns_propagation,
            Duration::from_secs(45)
        );
        assert_eq!(
            parse(&["--dns-propagation-secs", "0"]).dns_propagation,
            Duration::ZERO
        );
    }

    #[test]
    fn acme_email_is_optional_and_empty_by_default() {
        let mut config = parse(&[]);
        assert_eq!(config.acme_email, "");
        assert!(config.normalize().is_ok());
        assert_eq!(config.acme_email, "");
    }

    #[test]
    fn acme_email_must_look_like_an_address_with_a_dotted_domain() {
        for email in [
            "ops@example.com",
            "first.last+acme@mail.example.co.uk",
            "ops@my-host.example.org",
        ] {
            assert!(validate_acme_email(email).is_ok(), "{email}");
        }
        for email in [
            "acme@localhost",
            "ops",
            "@example.com",
            "ops@",
            "ops@example.",
            "ops@.example.com",
            "ops@example..com",
            "ops@exa mple.com",
            "ops@example,com",
            "ops@example.com@example.org",
        ] {
            assert!(validate_acme_email(email).is_err(), "{email}");
        }
    }

    #[test]
    fn acme_email_is_trimmed_and_rejected_at_startup_when_malformed() {
        let mut config = parse(&["--acme-email", "  ops@example.com  "]);
        config.normalize().unwrap();
        assert_eq!(config.acme_email, "ops@example.com");

        let mut config = parse(&["--acme-email", "   "]);
        config.normalize().unwrap();
        assert_eq!(config.acme_email, "");

        let mut config = parse(&["--acme-email", "acme@localhost"]);
        let error = config.normalize().unwrap_err().to_string();
        assert!(error.contains("OT_ACME_EMAIL"), "{error}");
        assert!(error.contains("acme@localhost"), "{error}");
    }
}
