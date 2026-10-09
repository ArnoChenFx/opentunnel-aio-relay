//! Admission controls for the open provisioning API: source allowlist and
//! per-address rate limiting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Upper bound on tracked rate-limit buckets. Beyond it, expired buckets are
/// dropped and, if the table is still full, new sources are refused.
const MAX_TRACKED_SOURCES: usize = 65_536;

/// An IPv4 or IPv6 address range in CIDR notation. A bare address is a
/// single-host range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

fn v4_mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn v6_mask(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                let mask = v4_mask(self.prefix);
                u32::from(network) & mask == u32::from(addr) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                let mask = v6_mask(self.prefix);
                u128::from(network) & mask == u128::from(addr) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address.trim(), Some(prefix.trim())),
            None => (value.trim(), None),
        };
        let ip: IpAddr = address
            .parse()
            .map_err(|_| format!("invalid IP address in {value:?}"))?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max_prefix,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max_prefix)
                .ok_or_else(|| format!("invalid prefix length in {value:?}"))?,
        };
        let network = match ip {
            IpAddr::V4(addr) => IpAddr::V4((u32::from(addr) & v4_mask(prefix)).into()),
            IpAddr::V6(addr) => IpAddr::V6((u128::from(addr) & v6_mask(prefix)).into()),
        };
        Ok(Cidr { network, prefix })
    }
}

/// A comma-separated list of ranges. Blank entries are ignored, so an empty
/// setting, such as an exported but empty environment variable, admits every
/// source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrList(Vec<Cidr>);

impl CidrList {
    /// Whether `ip` may call a restricted endpoint. An empty list admits every source.
    pub fn admits(&self, ip: IpAddr) -> bool {
        self.0.is_empty() || self.0.iter().any(|cidr| cidr.contains(ip))
    }
}

impl FromStr for CidrList {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(Cidr::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map(CidrList)
    }
}

/// Fixed-window request counter per source address. IPv6 sources are grouped
/// by /64 so one host cannot multiply its budget by rotating addresses.
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    started: Instant,
    count: u32,
}

impl RateLimiter {
    /// `limit` requests per hour per source; zero disables limiting.
    pub fn new(limit: u32) -> Self {
        Self::with_window(limit, Duration::from_secs(3600))
    }

    fn with_window(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one request from `ip` at `now`. On refusal, returns how long
    /// until the window resets.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        if self.limit == 0 {
            return Ok(());
        }
        let key = bucket_key(ip);
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if buckets.len() >= MAX_TRACKED_SOURCES && !buckets.contains_key(&key) {
            buckets.retain(|_, bucket| now.duration_since(bucket.started) < self.window);
            if buckets.len() >= MAX_TRACKED_SOURCES {
                return Err(self.window);
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            started: now,
            count: 0,
        });
        if now.duration_since(bucket.started) >= self.window {
            *bucket = Bucket {
                started: now,
                count: 0,
            };
        }
        if bucket.count >= self.limit {
            return Err(self
                .window
                .saturating_sub(now.duration_since(bucket.started)));
        }
        bucket.count += 1;
        Ok(())
    }
}

fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(addr) => {
            let prefix = u128::from(addr) & (u128::MAX << 64);
            IpAddr::V6(prefix.into())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn cidr_matches_ranges_and_single_hosts() {
        let net: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains(ip("10.200.1.2")));
        assert!(!net.contains(ip("11.0.0.1")));

        let host: Cidr = "203.0.113.7".parse().unwrap();
        assert!(host.contains(ip("203.0.113.7")));
        assert!(!host.contains(ip("203.0.113.8")));

        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("198.51.100.1")));

        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")));
        assert!(!v6.contains(ip("2001:db9::1")));
        assert!(!net.contains(ip("2001:db8::1")));
    }

    #[test]
    fn cidr_rejects_malformed_input() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("2001:db8::/129".parse::<Cidr>().is_err());
        assert!("not-an-ip".parse::<Cidr>().is_err());
        assert!("10.0.0.0/".parse::<Cidr>().is_err());
    }

    #[test]
    fn mapped_ipv4_sources_match_ipv4_ranges() {
        let net: Cidr = "127.0.0.0/8".parse().unwrap();
        assert!(net.contains(ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn empty_allowlist_admits_everyone() {
        assert!(CidrList::default().admits(ip("192.0.2.1")));
        assert!("".parse::<CidrList>().unwrap().admits(ip("192.0.2.1")));
        assert!(" , ".parse::<CidrList>().unwrap().admits(ip("192.0.2.1")));
    }

    #[test]
    fn allowlist_admits_listed_ranges_only() {
        let list: CidrList = "192.0.2.0/24, 2001:db8::/32".parse().unwrap();
        assert!(list.admits(ip("192.0.2.9")));
        assert!(list.admits(ip("2001:db8::9")));
        assert!(!list.admits(ip("192.0.3.9")));
        assert!("192.0.2.0/24,bogus".parse::<CidrList>().is_err());
    }

    #[test]
    fn rate_limiter_enforces_budget_per_window() {
        let window = Duration::from_secs(60);
        let limiter = RateLimiter::with_window(2, window);
        let start = Instant::now();
        let source = ip("192.0.2.10");
        assert!(limiter.check(source, start).is_ok());
        assert!(limiter.check(source, start).is_ok());
        let retry = limiter.check(source, start).unwrap_err();
        assert!(retry <= window && retry > Duration::ZERO);
        assert!(limiter.check(ip("192.0.2.11"), start).is_ok());
        assert!(limiter.check(source, start + window).is_ok());
    }

    #[test]
    fn rate_limiter_groups_ipv6_by_slash_64() {
        let limiter = RateLimiter::with_window(1, Duration::from_secs(60));
        let now = Instant::now();
        assert!(limiter.check(ip("2001:db8:1:1::5"), now).is_ok());
        assert!(limiter.check(ip("2001:db8:1:1::6"), now).is_err());
        assert!(limiter.check(ip("2001:db8:1:2::5"), now).is_ok());
    }

    #[test]
    fn zero_limit_disables_rate_limiting() {
        let limiter = RateLimiter::new(0);
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(limiter.check(ip("192.0.2.1"), now).is_ok());
        }
    }
}
