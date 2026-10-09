use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

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

    #[arg(skip)]
    pub timeouts: Timeouts,
}

impl Config {
    /// Puts operator-supplied values into the canonical form the rest of the
    /// server compares against. Run once at startup, before anything serves.
    pub fn normalize(&mut self) -> anyhow::Result<()> {
        self.domain = normalize_domain(&self.domain);
        anyhow::ensure!(!self.domain.is_empty(), "OT_DOMAIN is empty");
        Ok(())
    }
}

/// Lowercases a domain and strips surrounding whitespace and trailing dots,
/// so `Tunnel.Example.COM.` and `tunnel.example.com` name the same zone.
pub fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Internal time budgets. Not exposed as flags: they only need to change in tests.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// How long a full per-connection queue may block the bridge reader before
    /// that one connection is reset. The official client uses the same policy
    /// with a 30 s budget; this relay uses a shorter one because the reader is
    /// shared, so every other stream on the bridge waits while it blocks.
    pub bridge_stall: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            bridge_stall: Duration::from_secs(10),
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
