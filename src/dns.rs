//! Cloudflare DNS API (ACME DNS-01 TXT records) and DNS-over-HTTPS
//! propagation checks. Mirrors the behavior of `certificate-workflow.ts`.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Option<Vec<CfError>>,
}

#[derive(Deserialize)]
struct CfError {
    message: Option<String>,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
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

fn endpoint(zone_id: &str) -> String {
    format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records")
}

/// Creates a TXT record, returning its Cloudflare record id.
pub async fn create_txt(
    http: &Client,
    zone_id: &str,
    token: &str,
    name: &str,
    content: &str,
) -> Result<String> {
    let res = http
        .post(endpoint(zone_id))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": 60,
        }))
        .send()
        .await
        .context("creating DNS TXT record")?;
    let body: CfResponse<DnsRecord> = res.json().await.context("parsing DNS response")?;
    if !body.success {
        let msg = body
            .errors
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| e.message)
            .collect::<Vec<_>>()
            .join(", ");
        bail!("DNS record creation failed: {msg}");
    }
    body.result
        .map(|r| r.id)
        .ok_or_else(|| anyhow!("DNS response had no record id"))
}

/// Deletes a TXT record by id. A record that is already gone counts as deleted.
pub async fn delete_txt(http: &Client, zone_id: &str, token: &str, record_id: &str) -> Result<()> {
    let res = http
        .delete(format!("{}/{}", endpoint(zone_id), record_id))
        .bearer_auth(token)
        .send()
        .await
        .context("deleting DNS TXT record")?;
    let status = res.status();
    if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    bail!("DNS record deletion failed with HTTP {status}");
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
        let cf = query_doh(http, "https://cloudflare-dns.com/dns-query", name).await;
        let google = query_doh(http, "https://dns.google/resolve", name).await;
        if expected.iter().all(|v| cf.contains(v)) || expected.iter().all(|v| google.contains(v)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("DNS TXT records not visible before propagation timeout");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
