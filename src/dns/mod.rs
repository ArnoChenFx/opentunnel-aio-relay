//! ACME DNS-01 challenge records.
//!
//! A DNS-01 challenge is answered with a TXT record at `_acme-challenge.<name>`.
//! [`DnsProvider`] publishes and removes those records through the DNS service
//! that hosts the zone. [`wait_for_txt`] asks public DNS-over-HTTPS resolvers
//! whether the records are visible yet. Its answer is advisory: the CA checks
//! from its own resolvers, so a check that times out is logged and does not
//! fail an order by itself.

mod aliyun;
mod cloudflare;
#[cfg(test)]
pub(crate) mod test_support;

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use serde::Deserialize;
use tokio::time::Instant;

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

/// Public DNS-over-HTTPS resolvers the production check asks. Alibaba's
/// answers the JSON query format and is reachable from inside China, where
/// `dns.google` is not.
const DOH_RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.alidns.com/resolve",
];

const TYPE_TXT: u16 = 16;
const RCODE_NOERROR: u16 = 0;

/// How [`wait_for_txt`] looks for TXT records.
#[derive(Clone, Debug)]
pub struct PropagationCheck {
    /// How long to keep asking before giving up. Zero turns the check off.
    pub timeout: Duration,
    /// Pause between two queries to the same resolver.
    pub interval: Duration,
    /// DNS-over-HTTPS endpoints. Any one of them listing every value is enough.
    pub resolvers: Vec<String>,
}

impl PropagationCheck {
    /// The check the relay runs in production: the public resolvers, asked
    /// once a second.
    pub fn public(timeout: Duration) -> Self {
        Self {
            timeout,
            interval: Duration::from_secs(1),
            resolvers: DOH_RESOLVERS
                .iter()
                .map(|resolver| resolver.to_string())
                .collect(),
        }
    }

    /// No waiting: the CA is asked as soon as the records are placed.
    pub fn disabled() -> Self {
        Self {
            timeout: Duration::ZERO,
            interval: Duration::ZERO,
            resolvers: Vec::new(),
        }
    }
}

/// Waits until one of `check.resolvers` lists every value in `expected` for
/// `name`, or until `deadline` passes. The resolvers are polled side by side,
/// so a slow or silent one does not hold back the others. On failure the error
/// says what each resolver last answered.
pub async fn wait_for_txt(
    http: &Client,
    check: &PropagationCheck,
    name: &str,
    expected: &HashSet<String>,
    deadline: Instant,
) -> Result<()> {
    anyhow::ensure!(
        !check.resolvers.is_empty(),
        "no DNS-over-HTTPS resolver is configured"
    );
    let mut polls: FuturesUnordered<_> = check
        .resolvers
        .iter()
        .map(|resolver| poll_resolver(http, resolver, name, expected, deadline, check.interval))
        .collect();
    let mut misses = Vec::new();
    while let Some(outcome) = polls.next().await {
        match outcome {
            Ok(()) => return Ok(()),
            Err(miss) => misses.push(miss),
        }
    }
    anyhow::bail!("{}", misses.join("; "))
}

async fn poll_resolver(
    http: &Client,
    resolver: &str,
    name: &str,
    expected: &HashSet<String>,
    deadline: Instant,
    interval: Duration,
) -> std::result::Result<(), String> {
    let mut last = "no answer before the deadline".to_string();
    while Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, query_doh(http, resolver, name)).await {
            Ok(Ok(seen)) => {
                let missing = expected
                    .iter()
                    .filter(|value| !seen.contains(*value))
                    .count();
                if missing == 0 {
                    return Ok(());
                }
                last = format!(
                    "{} TXT value(s) listed, {missing} of {} expected missing",
                    seen.len(),
                    expected.len()
                );
            }
            Ok(Err(reason)) => last = reason,
            // A query cut off by the deadline keeps the last answer that arrived.
            Err(_elapsed) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(interval.min(remaining)).await;
    }
    Err(format!("{}: {last}", resolver_host(resolver)))
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

/// The TXT values one resolver lists for a name, or why it listed none.
async fn query_doh(
    http: &Client,
    resolver: &str,
    name: &str,
) -> std::result::Result<HashSet<String>, String> {
    let response = http
        .get(resolver)
        .query(&[("name", name), ("type", "TXT")])
        .header("accept", "application/dns-json")
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let body: DohResponse = response
        .json()
        .await
        .map_err(|error| format!("unreadable answer: {error}"))?;
    if body.status != RCODE_NOERROR {
        return Err(rcode_name(body.status));
    }
    Ok(body
        .answer
        .unwrap_or_default()
        .into_iter()
        .filter(|answer| answer.rtype == TYPE_TXT)
        .map(|answer| txt_value(&answer.data))
        .collect())
}

fn rcode_name(status: u16) -> String {
    match status {
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        5 => "REFUSED".to_string(),
        other => format!("DNS status {other}"),
    }
}

/// The value of a TXT record as a DoH `data` field presents it. Cloudflare and
/// Alibaba quote each character string and separate the strings with spaces, so
/// `"abc" "def"` is `abcdef`, and a backslash escapes the next character. Google
/// presents the text without quotes, and that text is taken as it is.
fn txt_value(data: &str) -> String {
    if !data.contains('"') {
        return data.to_string();
    }
    let mut value = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in data.chars() {
        if escaped {
            value.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if quoted || !c.is_whitespace() {
            value.push(c);
        }
    }
    value
}

/// The host of a resolver URL, for error messages.
fn resolver_host(resolver: &str) -> &str {
    let without_scheme = resolver
        .split_once("://")
        .map_or(resolver, |(_, rest)| rest);
    without_scheme.split('/').next().unwrap_or(without_scheme)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::*;
    use crate::dns::test_support::serve;

    const NAME: &str = "_acme-challenge.host.example";

    fn txt_answer(values: &[&str]) -> String {
        let answers: Vec<Value> = values
            .iter()
            .map(|value| {
                json!({"name": format!("{NAME}."), "type": 16, "TTL": 60, "data": format!("\"{value}\"")})
            })
            .collect();
        json!({"Status": 0, "Answer": answers}).to_string()
    }

    fn expected(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn check_of(resolvers: Vec<String>) -> PropagationCheck {
        PropagationCheck {
            timeout: Duration::from_secs(5),
            interval: Duration::from_millis(20),
            resolvers,
        }
    }

    fn in_(after: Duration) -> Instant {
        Instant::now() + after
    }

    fn url_of(server: &crate::dns::test_support::MockServer) -> String {
        format!("{}/resolve", server.base_url)
    }

    /// A resolver that accepts connections and never answers.
    async fn silent_resolver() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        format!("http://{addr}/resolve")
    }

    #[test]
    fn txt_value_joins_the_character_strings_of_a_record() {
        assert_eq!(txt_value(r#""abc""#), "abc");
        assert_eq!(txt_value(r#""abc" "def""#), "abcdef");
        assert_eq!(txt_value(r#""a\"b\\c""#), r#"a"b\c"#);
        assert_eq!(txt_value("plain"), "plain");
    }

    #[test]
    fn txt_value_takes_unquoted_text_as_it_is() {
        assert_eq!(txt_value("v=DMARC1; p=reject"), "v=DMARC1; p=reject");
        assert_eq!(txt_value(r"a\b"), r"a\b");
    }

    #[tokio::test]
    async fn query_doh_reads_google_resolve_format() {
        let server = serve(|_| {
            (
                200,
                r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"_acme-challenge.host.example.","type":16}],"Answer":[{"name":"_acme-challenge.host.example.","type":16,"TTL":60,"data":"one two"}],"Comment":"Response from 216.239.38.10."}"#.to_string(),
            )
        })
        .await;
        let seen = query_doh(&Client::new(), &url_of(&server), NAME)
            .await
            .unwrap();
        assert_eq!(seen, expected(&["one two"]));
    }

    #[tokio::test]
    async fn query_doh_reads_the_txt_answers_for_the_name() {
        let server = serve(|_| {
            (
                200,
                r#"{"Status":0,"Answer":[{"name":"_acme-challenge.host.example.","type":5,"TTL":60,"data":"target.example."},{"name":"_acme-challenge.host.example.","type":16,"TTL":60,"data":"\"one\" \"two\""},{"name":"_acme-challenge.host.example.","type":16,"TTL":60,"data":"\"three\""}]}"#.to_string(),
            )
        })
        .await;
        let seen = query_doh(&Client::new(), &url_of(&server), NAME)
            .await
            .unwrap();
        assert_eq!(seen, expected(&["onetwo", "three"]));

        let requests = server.requests();
        assert_eq!(requests[0].target, format!("/resolve?name={NAME}&type=TXT"));
        assert_eq!(requests[0].header("accept"), Some("application/dns-json"));
    }

    #[tokio::test]
    async fn query_doh_reads_alidns_resolve_format() {
        let server = serve(|_| {
            (
                200,
                r#"{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":{"name":"_acme-challenge.example.com.","type":16},"Answer":[{"name":"_acme-challenge.example.com.","TTL":600,"type":16,"data":"\"digest-value\""}]}"#.to_string(),
            )
        })
        .await;
        let seen = query_doh(
            &Client::new(),
            &url_of(&server),
            "_acme-challenge.example.com",
        )
        .await
        .unwrap();
        assert!(seen.contains("digest-value"), "{seen:?}");
    }

    #[tokio::test]
    async fn query_doh_reports_a_non_success_dns_status_as_an_error() {
        let server = serve(|_| (200, r#"{"Status":3,"Answer":[]}"#.to_string())).await;
        let error = query_doh(&Client::new(), &url_of(&server), NAME)
            .await
            .unwrap_err();
        assert_eq!(error, "NXDOMAIN");
    }

    #[tokio::test]
    async fn one_resolver_that_lists_every_value_is_enough() {
        let partial = serve(|_| (200, txt_answer(&["one"]))).await;
        let complete = serve(|_| (200, txt_answer(&["one", "two"]))).await;
        let check = check_of(vec![url_of(&partial), url_of(&complete)]);
        wait_for_txt(
            &Client::new(),
            &check,
            NAME,
            &expected(&["one", "two"]),
            in_(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_resolver_that_lists_only_some_values_is_not_done() {
        let partial = serve(|_| (200, txt_answer(&["one"]))).await;
        let check = check_of(vec![url_of(&partial)]);
        let error = wait_for_txt(
            &Client::new(),
            &check,
            NAME,
            &expected(&["one", "two"]),
            in_(Duration::from_millis(200)),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("1 of 2 expected missing"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_silent_resolver_does_not_hold_back_one_that_answers() {
        let silent = silent_resolver().await;
        let answering = serve(|_| (200, txt_answer(&["one"]))).await;
        let check = check_of(vec![silent, url_of(&answering)]);
        let started = std::time::Instant::now();
        wait_for_txt(
            &Client::new(),
            &check,
            NAME,
            &expected(&["one"]),
            in_(Duration::from_secs(10)),
        )
        .await
        .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn transient_errors_are_retried_until_a_resolver_answers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let flaky = serve({
            let calls = calls.clone();
            move |_| {
                if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                    (429, "{}".to_string())
                } else {
                    (200, txt_answer(&["one"]))
                }
            }
        })
        .await;
        let check = check_of(vec![url_of(&flaky)]);
        wait_for_txt(
            &Client::new(),
            &check,
            NAME,
            &expected(&["one"]),
            in_(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_timeout_reports_what_each_resolver_last_answered() {
        let failing = serve(|_| (503, String::new())).await;
        let servfail = serve(|_| (200, r#"{"Status":2}"#.to_string())).await;
        let partial = serve(|_| (200, txt_answer(&["one"]))).await;
        let check = check_of(vec![url_of(&failing), url_of(&servfail), url_of(&partial)]);
        let error = wait_for_txt(
            &Client::new(),
            &check,
            NAME,
            &expected(&["one", "two"]),
            in_(Duration::from_millis(200)),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("HTTP 503"), "{error}");
        assert!(error.contains("SERVFAIL"), "{error}");
        assert!(error.contains("1 of 2 expected missing"), "{error}");
    }

    #[tokio::test]
    async fn wait_for_txt_needs_at_least_one_resolver() {
        let check = check_of(Vec::new());
        assert!(wait_for_txt(
            &Client::new(),
            &check,
            NAME,
            &expected(&["one"]),
            in_(Duration::from_secs(1)),
        )
        .await
        .is_err());
    }
}
