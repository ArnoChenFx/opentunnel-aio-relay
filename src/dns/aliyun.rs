//! Alibaba Cloud DNS (alidns, API version 2015-01-09) for ACME DNS-01 records.
//!
//! Each call is an RPC-style POST with an empty body. Parameters travel in the
//! query string, and the request is signed with Alibaba Cloud's V3 scheme
//! (`ACS3-HMAC-SHA256`), which covers the `host` header and the `x-acs-*`
//! headers. The older HMAC-SHA1 scheme is not implemented.

use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::Utc;
use reqwest::{Client, Url};
use serde_json::Value;
use tokio::sync::OnceCell;

use super::{BoxFuture, DnsProvider};

const API_VERSION: &str = "2015-01-09";
const SIGNATURE_ALGORITHM: &str = "ACS3-HMAC-SHA256";
const SIGNED_HEADERS: &str =
    "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";
/// SHA-256 of the empty body that every call sends.
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// The free edition does not accept a TTL below 600 seconds.
const TXT_TTL: &str = "600";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Total attempts for a call refused with a throttling error. Throttled calls
/// are rejected before they take effect, so repeating them is safe.
const MAX_ATTEMPTS: u32 = 3;
const DOMAIN_PAGE_SIZE: &str = "100";
const MAX_DOMAIN_PAGES: u32 = 50;

pub struct AliyunDns {
    http: Client,
    base_url: String,
    /// Host as the server sees it, which is part of the signed headers.
    host: String,
    access_key_id: String,
    access_key_secret: String,
    /// Registered domain configured with OT_ALIYUN_DOMAIN, if any.
    domain: Option<String>,
    /// Registered domains in the account, looked up once when `domain` is unset.
    account_domains: OnceCell<Vec<String>>,
}

impl AliyunDns {
    pub fn new(
        http: Client,
        endpoint: &str,
        access_key_id: &str,
        access_key_secret: &str,
        domain: Option<&str>,
    ) -> Result<Self> {
        Self::with_base_url(
            http,
            format!("https://{endpoint}"),
            access_key_id,
            access_key_secret,
            domain,
        )
    }

    fn with_base_url(
        http: Client,
        base_url: String,
        access_key_id: &str,
        access_key_secret: &str,
        domain: Option<&str>,
    ) -> Result<Self> {
        let url = Url::parse(&base_url)
            .with_context(|| format!("invalid Alibaba Cloud DNS endpoint {base_url:?}"))?;
        let host = match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_string(),
            (None, _) => bail!("Alibaba Cloud DNS endpoint {base_url:?} has no host name"),
        };
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            host,
            access_key_id: access_key_id.to_string(),
            access_key_secret: access_key_secret.to_string(),
            domain: domain.map(str::to_ascii_lowercase),
            account_domains: OnceCell::new(),
        })
    }

    async fn add_txt(&self, name: &str, value: &str) -> Result<String> {
        let name = name.to_ascii_lowercase();
        let zone = self.zone_for(&name).await?;
        let rr = relative_name(&name, &zone);
        let added = self
            .call(
                "AddDomainRecord",
                &[
                    ("DomainName", zone.as_str()),
                    ("RR", rr.as_str()),
                    ("Type", "TXT"),
                    ("Value", value),
                    ("TTL", TXT_TTL),
                ],
            )
            .await;
        match added {
            Ok(body) => body["RecordId"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("AddDomainRecord returned no RecordId")),
            // An identical record left by an earlier attempt is reused, so the
            // order still removes it when it finishes.
            Err(error) if api_code(&error) == Some("DomainRecordDuplicate") => {
                self.find_txt_record(&zone, &rr, value).await?.ok_or(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn remove_record(&self, record_id: &str) -> Result<()> {
        match self
            .call("DeleteDomainRecord", &[("RecordId", record_id)])
            .await
        {
            Ok(_) => Ok(()),
            // The API reports a record that no longer exists as not belonging to the account.
            Err(error)
                if matches!(
                    api_code(&error),
                    Some("DomainRecordNotBelongToUser" | "InvalidRR.NoExist")
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    async fn zone_for(&self, name: &str) -> Result<String> {
        if let Some(domain) = &self.domain {
            ensure!(
                within(name, domain),
                "{name} is outside OT_ALIYUN_DOMAIN ({domain})"
            );
            return Ok(domain.clone());
        }
        let domains = self
            .account_domains
            .get_or_try_init(|| self.list_domains())
            .await?;
        domains
            .iter()
            .filter(|zone| within(name, zone))
            .max_by_key(|zone| zone.len())
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "no domain in this Alibaba Cloud DNS account contains {name}; set OT_ALIYUN_DOMAIN"
                )
            })
    }

    async fn list_domains(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for page in 1..=MAX_DOMAIN_PAGES {
            let page = page.to_string();
            let body = self
                .call(
                    "DescribeDomains",
                    &[
                        ("PageNumber", page.as_str()),
                        ("PageSize", DOMAIN_PAGE_SIZE),
                    ],
                )
                .await?;
            let entries = body["Domains"]["Domain"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            names.extend(
                entries
                    .iter()
                    .filter_map(|entry| entry["DomainName"].as_str())
                    .map(|name| name.trim().to_ascii_lowercase()),
            );
            let total = body["TotalCount"].as_u64().unwrap_or(0);
            if entries.is_empty() || names.len() as u64 >= total {
                return Ok(names);
            }
        }
        bail!(
            "this account has more than {} domains; set OT_ALIYUN_DOMAIN",
            MAX_DOMAIN_PAGES * 100
        )
    }

    async fn find_txt_record(&self, zone: &str, rr: &str, value: &str) -> Result<Option<String>> {
        let body = self
            .call(
                "DescribeDomainRecords",
                &[
                    ("DomainName", zone),
                    ("RRKeyWord", rr),
                    ("TypeKeyWord", "TXT"),
                    ("PageSize", "500"),
                ],
            )
            .await?;
        let records = body["DomainRecords"]["Record"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        Ok(records
            .iter()
            .find(|record| {
                record["RR"].as_str() == Some(rr)
                    && record["Type"].as_str() == Some("TXT")
                    && record["Value"].as_str().map(|v| v.trim_matches('"')) == Some(value)
            })
            .and_then(|record| record["RecordId"].as_str())
            .map(str::to_string))
    }

    /// Calls the API, retrying throttled calls with a growing pause.
    async fn call(&self, action: &str, params: &[(&str, &str)]) -> Result<Value> {
        let mut attempt = 1;
        loop {
            match self.send(action, params).await {
                Err(error)
                    if attempt < MAX_ATTEMPTS
                        && api_code(&error).is_some_and(|code| code.starts_with("Throttling")) =>
                {
                    tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    async fn send(&self, action: &str, params: &[(&str, &str)]) -> Result<Value> {
        let date = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = crate::bridge::random_session_id();
        let envelope = Envelope {
            host: &self.host,
            action,
            version: API_VERSION,
            date: &date,
            nonce: &nonce,
        };
        let mut query_params = params.to_vec();
        query_params.push(("Lang", "en"));
        let signed = sign(
            &envelope,
            &query_params,
            &self.access_key_id,
            &self.access_key_secret,
        );

        let response = self
            .http
            .post(format!("{}/?{}", self.base_url, signed.query))
            .header("accept", "application/json")
            .header("authorization", signed.authorization)
            .header("x-acs-action", action)
            .header("x-acs-version", API_VERSION)
            .header("x-acs-date", date.as_str())
            .header("x-acs-signature-nonce", nonce.as_str())
            .header("x-acs-content-sha256", EMPTY_BODY_SHA256)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|error| anyhow!("{action} request failed: {}", error.without_url()))?;
        let status = response.status();
        let text = response.text().await.map_err(|error| {
            anyhow!(
                "{action} response could not be read: {}",
                error.without_url()
            )
        })?;
        if status.is_success() {
            return serde_json::from_str(&text)
                .map_err(|_| anyhow!("{action} returned a response that is not JSON"));
        }
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Err(ApiError {
            action: action.to_string(),
            status: status.as_u16(),
            code: body["Code"].as_str().unwrap_or("UnknownError").to_string(),
            message: body["Message"]
                .as_str()
                .map_or_else(|| text.chars().take(200).collect(), str::to_string),
        }
        .into())
    }
}

impl DnsProvider for AliyunDns {
    fn create_txt<'a>(&'a self, name: &'a str, value: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(self.add_txt(name, value))
    }

    fn delete_txt<'a>(&'a self, record_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.remove_record(record_id))
    }
}

#[derive(Debug)]
struct ApiError {
    action: String,
    status: u16,
    code: String,
    message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Alibaba Cloud DNS {} failed (HTTP {}): {}: {}",
            self.action, self.status, self.code, self.message
        )
    }
}

impl std::error::Error for ApiError {}

fn api_code(error: &anyhow::Error) -> Option<&str> {
    error.downcast_ref::<ApiError>().map(|e| e.code.as_str())
}

/// Whether `name` is `zone` itself or a name below it.
fn within(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// `name` relative to `zone`, as the API takes it (`@` for the zone itself).
fn relative_name(name: &str, zone: &str) -> String {
    name.strip_suffix(zone)
        .and_then(|rest| rest.strip_suffix('.'))
        .unwrap_or("@")
        .to_string()
}

/// The parts of a request that the signature covers besides its parameters.
struct Envelope<'a> {
    host: &'a str,
    action: &'a str,
    version: &'a str,
    /// `x-acs-date`, UTC as `YYYY-MM-DDTHH:MM:SSZ`.
    date: &'a str,
    /// `x-acs-signature-nonce`, unique per request.
    nonce: &'a str,
}

struct SignedRequest {
    /// Canonical query string. It is sent verbatim, so the server sees exactly
    /// the bytes that were signed.
    query: String,
    authorization: String,
}

/// RFC 3986 percent-encoding as Alibaba Cloud requires it: unreserved
/// characters stay as they are and every other byte becomes `%XX`, so a space
/// is `%20` and `*` is `%2A`.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn canonical_query(params: &[(&str, &str)]) -> String {
    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_request(envelope: &Envelope, query: &str) -> String {
    let Envelope {
        host,
        action,
        version,
        date,
        nonce,
    } = envelope;
    let headers = format!(
        "host:{host}\nx-acs-action:{action}\nx-acs-content-sha256:{EMPTY_BODY_SHA256}\nx-acs-date:{date}\nx-acs-signature-nonce:{nonce}\nx-acs-version:{version}\n"
    );
    format!("POST\n/\n{query}\n{headers}\n{SIGNED_HEADERS}\n{EMPTY_BODY_SHA256}")
}

fn sign(
    envelope: &Envelope,
    params: &[(&str, &str)],
    access_key_id: &str,
    access_key_secret: &str,
) -> SignedRequest {
    let query = canonical_query(params);
    let hashed_request = hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        canonical_request(envelope, &query).as_bytes(),
    ));
    let string_to_sign = format!("{SIGNATURE_ALGORITHM}\n{hashed_request}");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, access_key_secret.as_bytes());
    let signature = hex::encode(ring::hmac::sign(&key, string_to_sign.as_bytes()));
    SignedRequest {
        query,
        authorization: format!(
            "{SIGNATURE_ALGORITHM} Credential={access_key_id},SignedHeaders={SIGNED_HEADERS},Signature={signature}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::dns::test_support::{serve, Recorded};

    const ACCESS_KEY_ID: &str = "LTAItest";
    const ACCESS_KEY_SECRET: &str = "testsecret";

    fn provider(base_url: String, domain: Option<&str>) -> AliyunDns {
        AliyunDns::with_base_url(
            Client::new(),
            base_url,
            ACCESS_KEY_ID,
            ACCESS_KEY_SECRET,
            domain,
        )
        .unwrap()
    }

    fn query_of(request: &Recorded) -> HashMap<String, String> {
        Url::parse(&format!("http://localhost{}", request.target))
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    /// Recomputes the signature from the request the server received, so the
    /// check covers the bytes on the wire rather than what the client intended.
    fn assert_signed(request: &Recorded) {
        let params: Vec<(String, String)> = query_of(request).into_iter().collect();
        let params: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let envelope = Envelope {
            host: request.header("host").unwrap(),
            action: request.header("x-acs-action").unwrap(),
            version: request.header("x-acs-version").unwrap(),
            date: request.header("x-acs-date").unwrap(),
            nonce: request.header("x-acs-signature-nonce").unwrap(),
        };
        let expected = sign(&envelope, &params, ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.target.split_once('?').map(|(_, query)| query),
            Some(expected.query.as_str())
        );
        assert_eq!(
            request.header("authorization"),
            Some(expected.authorization.as_str())
        );
        assert_eq!(
            request.header("x-acs-content-sha256"),
            Some(EMPTY_BODY_SHA256)
        );
    }

    fn respond(request: &Recorded) -> (u16, String) {
        match request.header("x-acs-action") {
            Some("AddDomainRecord") => {
                (200, r#"{"RequestId":"r1","RecordId":"rec-1"}"#.to_string())
            }
            Some("DeleteDomainRecord") => {
                (200, r#"{"RequestId":"r2","RecordId":"rec-1"}"#.to_string())
            }
            _ => (
                400,
                r#"{"Code":"InvalidAction","Message":"unexpected action"}"#.to_string(),
            ),
        }
    }

    #[test]
    fn signs_the_documented_v3_example() {
        let envelope = Envelope {
            host: "ecs.cn-shanghai.aliyuncs.com",
            action: "RunInstances",
            version: "2014-05-26",
            date: "2023-10-26T10:22:32Z",
            nonce: "3156853299f313e23d1673dc12e1703d",
        };
        let params = [
            (
                "ImageId",
                "win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd",
            ),
            ("RegionId", "cn-shanghai"),
        ];
        let query = canonical_query(&params);
        assert_eq!(
            query,
            "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai"
        );
        let hashed = hex::encode(ring::digest::digest(
            &ring::digest::SHA256,
            canonical_request(&envelope, &query).as_bytes(),
        ));
        assert_eq!(
            hashed,
            "7ea06492da5221eba5297e897ce16e55f964061054b7695beedaac1145b1e259"
        );

        let signed = sign(&envelope, &params, "YourAccessKeyId", "YourAccessKeySecret");
        assert_eq!(
            signed.authorization,
            "ACS3-HMAC-SHA256 Credential=YourAccessKeyId,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"
        );
    }

    #[test]
    fn percent_encoding_follows_rfc3986() {
        assert_eq!(percent_encode("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(
            percent_encode("a b*c+d/e=f&g:h"),
            "a%20b%2Ac%2Bd%2Fe%3Df%26g%3Ah"
        );
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn canonical_query_sorts_by_name_and_encodes_values() {
        assert_eq!(
            canonical_query(&[("Value", "x y"), ("Action", "A"), ("RR", "_acme-challenge")]),
            "Action=A&RR=_acme-challenge&Value=x%20y"
        );
    }

    #[test]
    fn record_names_are_relative_to_their_zone() {
        assert!(within("a.example.com", "example.com"));
        assert!(within("example.com", "example.com"));
        assert!(!within("badexample.com", "example.com"));
        assert_eq!(
            relative_name(
                "_acme-challenge.t1.tunnel.example.com",
                "tunnel.example.com"
            ),
            "_acme-challenge.t1"
        );
        assert_eq!(
            relative_name("_acme-challenge.t1.example.com", "example.com"),
            "_acme-challenge.t1"
        );
        assert_eq!(relative_name("example.com", "example.com"), "@");
    }

    #[tokio::test]
    async fn add_and_delete_send_signed_v3_requests() {
        let mock = serve(respond).await;
        let dns = provider(mock.base_url.clone(), Some("example.com"));

        let id = dns
            .create_txt("_acme-challenge.t1.tunnel.example.com", "Wq1-_value")
            .await
            .unwrap();
        assert_eq!(id, "rec-1");
        dns.delete_txt(&id).await.unwrap();

        let requests = mock.requests();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_signed(request);
        }
        assert_eq!(requests[0].header("x-acs-action"), Some("AddDomainRecord"));
        let add = query_of(&requests[0]);
        assert_eq!(add["DomainName"], "example.com");
        assert_eq!(add["RR"], "_acme-challenge.t1.tunnel");
        assert_eq!(add["Type"], "TXT");
        assert_eq!(add["Value"], "Wq1-_value");
        assert_eq!(add["TTL"], "600");
        assert_eq!(add["Lang"], "en");
        assert_eq!(
            requests[1].header("x-acs-action"),
            Some("DeleteDomainRecord")
        );
        assert_eq!(query_of(&requests[1])["RecordId"], "rec-1");
    }

    #[tokio::test]
    async fn zone_is_the_longest_registered_domain_containing_the_name() {
        let mock = serve(|request| match request.header("x-acs-action") {
            Some("DescribeDomains") => (
                200,
                r#"{"TotalCount":3,"Domains":{"Domain":[{"DomainName":"example.com"},{"DomainName":"tunnel.example.com"},{"DomainName":"example.org"}]}}"#
                    .to_string(),
            ),
            _ => respond(request),
        })
        .await;
        let dns = provider(mock.base_url.clone(), None);

        dns.create_txt("_acme-challenge.t1.tunnel.example.com", "v")
            .await
            .unwrap();

        let requests = mock.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].header("x-acs-action"), Some("DescribeDomains"));
        assert_eq!(query_of(&requests[1])["DomainName"], "tunnel.example.com");
        assert_eq!(query_of(&requests[1])["RR"], "_acme-challenge.t1");
    }

    #[tokio::test]
    async fn an_identical_record_from_an_earlier_attempt_is_reused() {
        let mock = serve(|request| match request.header("x-acs-action") {
            Some("AddDomainRecord") => (
                400,
                r#"{"Code":"DomainRecordDuplicate","Message":"The DNS record already exists.","RequestId":"r3"}"#
                    .to_string(),
            ),
            Some("DescribeDomainRecords") => (
                200,
                r#"{"TotalCount":2,"DomainRecords":{"Record":[{"RecordId":"rec-6","RR":"_acme-challenge.t1","Type":"TXT","Value":"other"},{"RecordId":"rec-7","RR":"_acme-challenge.t1","Type":"TXT","Value":"abc"}]}}"#
                    .to_string(),
            ),
            _ => respond(request),
        })
        .await;
        let dns = provider(mock.base_url.clone(), Some("example.com"));

        let id = dns
            .create_txt("_acme-challenge.t1.example.com", "abc")
            .await
            .unwrap();
        assert_eq!(id, "rec-7");

        let requests = mock.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].header("x-acs-action"),
            Some("DescribeDomainRecords")
        );
        assert_eq!(query_of(&requests[1])["RRKeyWord"], "_acme-challenge.t1");
        assert_eq!(query_of(&requests[1])["TypeKeyWord"], "TXT");
    }

    #[tokio::test]
    async fn throttled_calls_are_retried_with_a_fresh_signature() {
        let adds = Arc::new(AtomicUsize::new(0));
        let mock = serve({
            let adds = adds.clone();
            move |request| match request.header("x-acs-action") {
                Some("AddDomainRecord") if adds.fetch_add(1, Ordering::SeqCst) == 0 => (
                    400,
                    r#"{"Code":"Throttling.User","Message":"Request was denied due to user flow control."}"#
                        .to_string(),
                ),
                _ => respond(request),
            }
        })
        .await;
        let dns = provider(mock.base_url.clone(), Some("example.com"));

        let id = dns
            .create_txt("_acme-challenge.t1.example.com", "v")
            .await
            .unwrap();
        assert_eq!(id, "rec-1");

        let requests = mock.requests();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_signed(request);
        }
        assert_ne!(
            requests[0].header("x-acs-signature-nonce"),
            requests[1].header("x-acs-signature-nonce")
        );
    }

    #[tokio::test]
    async fn api_errors_name_the_code_and_never_the_secret() {
        let mock = serve(|_| {
            (
                403,
                r#"{"Code":"Forbidden.RAM","Message":"User not authorized to operate on the specified resource."}"#
                    .to_string(),
            )
        })
        .await;
        let dns = provider(mock.base_url.clone(), Some("example.com"));

        let error = dns
            .create_txt("_acme-challenge.t1.example.com", "v")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("AddDomainRecord"), "{error}");
        assert!(error.contains("Forbidden.RAM"), "{error}");
        assert!(!error.contains(ACCESS_KEY_SECRET), "{error}");
        assert_eq!(mock.requests().len(), 1);
    }

    #[tokio::test]
    async fn deleting_a_record_that_is_already_gone_succeeds() {
        let mock = serve(|_| {
            (
                400,
                r#"{"Code":"DomainRecordNotBelongToUser","Message":"The DNS record does not exist in your account."}"#
                    .to_string(),
            )
        })
        .await;
        let dns = provider(mock.base_url.clone(), Some("example.com"));

        dns.delete_txt("rec-404").await.unwrap();
    }
}
