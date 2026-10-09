use clap::Parser;
use std::{net::IpAddr, path::PathBuf, str::FromStr};

/// An IPv4 or IPv6 network used by the tunnel-creation source-IP allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                self.prefix == 0
                    || u32::from(network) >> (32 - self.prefix)
                        == u32::from(candidate) >> (32 - self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                self.prefix == 0
                    || u128::from(network) >> (128 - self.prefix)
                        == u128::from(candidate) >> (128 - self.prefix)
            }
            _ => false,
        }
    }
}

impl FromStr for IpNetwork {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => {
                let address: IpAddr = address
                    .parse()
                    .map_err(|_| format!("invalid IP network address: {value}"))?;
                let prefix = prefix
                    .parse::<u8>()
                    .map_err(|_| format!("invalid IP network prefix: {value}"))?;
                (address, prefix)
            }
            None => {
                let address: IpAddr = value
                    .parse()
                    .map_err(|_| format!("invalid IP address: {value}"))?;
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                (address, prefix)
            }
        };
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(format!("IP network prefix exceeds {max_prefix}: {value}"));
        }
        Ok(Self { address, prefix })
    }
}

/// Single-binary self-hosted relay for the OpenTunnel protocol.
///
/// Listens on one TCP port (default 443) and demultiplexes by TLS SNI:
/// - SNI == `domain`            -> terminates TLS locally, serves the HTTP API
/// - SNI == `*.<domain>`        -> blind TCP passthrough to the tunnel's bridge
///   (TLS is terminated by the client; this server never sees plaintext)
#[derive(Parser, Clone)]
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

    /// Comma-separated IP addresses or CIDRs allowed to create tunnels; empty allows any IP.
    #[arg(long, env = "OT_TUNNEL_CREATE_IP_ALLOWLIST", value_delimiter = ',')]
    pub tunnel_create_ip_allowlist: Vec<IpNetwork>,

    /// Maximum tunnel-creation attempts per source IP in the configured window.
    #[arg(long, env = "OT_TUNNEL_CREATE_RATE_LIMIT", default_value_t = 5)]
    pub tunnel_create_rate_limit: usize,

    /// Sliding-window duration for tunnel-creation rate limiting.
    #[arg(long, env = "OT_TUNNEL_CREATE_RATE_WINDOW_SECS", default_value_t = 60)]
    pub tunnel_create_rate_window_secs: u64,

    /// Maximum number of non-deleted tunnels.
    #[arg(long, env = "OT_MAX_ACTIVE_TUNNELS", default_value_t = 1000)]
    pub max_active_tunnels: usize,

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_ip_networks_and_matches_only_members() {
        let ipv4: IpNetwork = "192.0.2.0/24".parse().unwrap();
        assert!(ipv4.contains("192.0.2.8".parse().unwrap()));
        assert!(!ipv4.contains("192.0.3.8".parse().unwrap()));
        assert!(!ipv4.contains("2001:db8::1".parse().unwrap()));

        let ipv6: IpNetwork = "2001:db8::/32".parse().unwrap();
        assert!(ipv6.contains("2001:db8::1".parse().unwrap()));
        assert!(!ipv6.contains("2001:db9::1".parse().unwrap()));

        let single: IpNetwork = "127.0.0.1".parse().unwrap();
        assert!(single.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let _ipv6_loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn rejects_invalid_network_prefixes() {
        assert!("192.0.2.1/33".parse::<IpNetwork>().is_err());
        assert!("2001:db8::1/129".parse::<IpNetwork>().is_err());
        assert!("not-an-ip".parse::<IpNetwork>().is_err());
    }
}
