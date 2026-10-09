//! ACME DNS-01 challenge records.
//!
//! A DNS-01 challenge is answered with a TXT record at `_acme-challenge.<name>`.
//! [`DnsProvider`] publishes and removes those records through the DNS service
//! that hosts the zone, and [`wait_for_txt`] confirms that public resolvers can
//! see them before the CA is asked to validate.

mod aliyun;
mod cloudflare;
#[cfg(test)]
pub(crate) mod test_support;

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

use crate::config::{Config, DnsProviderKind};

pub use aliyun::AliyunDns;
pub use cloudflare::CloudflareDns;

/// A boxed future, which keeps [`DnsProvider`] usable as a trait object
/// without the `async-trait` crate.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Publishes and removes the TXT records that answer DNS-01 challenges.
pub trait DnsProvider: Send + Sync {
    /// Creates TXT record `name` (fully qualified) with content `value` and
    /// returns the provider's id for it.
    fn create_txt<'a>(&'a self, name: &'a str, value: &'a str) -> BoxFuture<'a, Result<String>>;

    /// Deletes the record whose id `create_txt` returned. A record that is
    /// already gone counts as deleted.
    fn delete_txt<'a>(&'a self, record_id: &'a str) -> BoxFuture<'a, Result<()>>;
}

/// The provider the configuration selects.
pub fn from_config(config: &Config, http: Client) -> Result<Arc<dyn DnsProvider>> {
    let provider: Arc<dyn DnsProvider> = match config.dns_provider_kind()? {
        DnsProviderKind::Cloudflare => Arc::new(CloudflareDns::new(
            http,
            config.cf_zone_id.clone(),
            config.cf_token.clone(),
        )),
        DnsProviderKind::Aliyun => Arc::new(AliyunDns::new(
            http,
            &config.aliyun_endpoint,
            &config.aliyun_access_key_id,
            &config.aliyun_access_key_secret,
            Some(config.aliyun_domain.as_str()).filter(|domain| !domain.is_empty()),
        )?),
    };
    Ok(provider)
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    rtype: u16,
    data: String,
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

async fn query_doh(http: &Client, url: &str, name: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let res = http
        .get(url)
        .query(&[("name", name), ("type", "TXT")])
        .header("accept", "application/dns-json")
        .send()
        .await;
    let Ok(res) = res else { return out };
    let Ok(res) = res.error_for_status() else {
        return out;
    };
    let Ok(body) = res.json::<DohResponse>().await else {
        return out;
    };
    if body.status != 0 {
        return out;
    }
    for answer in body.answer.unwrap_or_default() {
        if answer.rtype == 16 {
            out.insert(answer.data.trim_matches('"').to_string());
        }
    }
    out
}

/// Public DNS-over-HTTPS resolvers consulted by [`wait_for_txt`]. Alibaba's
/// answers the JSON query format and is reachable from inside China, where
/// `dns.google` is not.
const DOH_RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.alidns.com/resolve",
];

/// Waits until every expected TXT value is visible for `name` via public
/// DNS-over-HTTPS resolvers (or the timeout elapses, like the original).
pub async fn wait_for_txt(
    http: &Client,
    name: &str,
    expected: &HashSet<String>,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let (cf, google, alidns) = tokio::join!(
            query_doh(http, DOH_RESOLVERS[0], name),
            query_doh(http, DOH_RESOLVERS[1], name),
            query_doh(http, DOH_RESOLVERS[2], name),
        );
        if [cf, google, alidns]
            .iter()
            .any(|seen| expected.iter().all(|v| seen.contains(v)))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("DNS TXT records not visible before propagation timeout");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::test_support::serve;

    /// The Alibaba DoH JSON shape (from `https://dns.alidns.com/resolve`)
    /// parses like the Google one `query_doh` was written for.
    #[tokio::test]
    async fn query_doh_reads_alidns_resolve_format() {
        let server = serve(|_| {
            (
                200,
                r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":{"name":"_acme-challenge.example.com.","type":16},"Answer":[{"name":"_acme-challenge.example.com.","TTL":600,"type":16,"data":"\"digest-value\""}]}"#.to_string(),
            )
        })
        .await;
        let http = Client::new();
        let seen = query_doh(
            &http,
            &format!("{}/resolve", server.base_url),
            "_acme-challenge.example.com",
        )
        .await;
        assert!(seen.contains("digest-value"), "{seen:?}");
    }

    #[tokio::test]
    async fn query_doh_ignores_error_status() {
        let server = serve(|_| (200, r#"{"Status":3,"Answer":[]}"#.to_string())).await;
        let http = Client::new();
        let seen = query_doh(&http, &format!("{}/resolve", server.base_url), "x.example.com").await;
        assert!(seen.is_empty(), "{seen:?}");
    }
}
