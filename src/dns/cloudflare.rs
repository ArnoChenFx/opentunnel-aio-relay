//! Cloudflare DNS API: TXT records in one zone, authenticated with an API token.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Client, StatusCode};
use serde::Deserialize;

use super::{BoxFuture, DnsProvider};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareDns {
    http: Client,
    api_base: String,
    zone_id: String,
    token: String,
}

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

impl CloudflareDns {
    pub fn new(http: Client, zone_id: String, token: String) -> Self {
        Self::with_api_base(http, API_BASE.to_string(), zone_id, token)
    }

    fn with_api_base(http: Client, api_base: String, zone_id: String, token: String) -> Self {
        Self {
            http,
            api_base,
            zone_id,
            token,
        }
    }

    fn records_url(&self) -> String {
        format!("{}/zones/{}/dns_records", self.api_base, self.zone_id)
    }

    async fn add_txt(&self, name: &str, content: &str) -> Result<String> {
        let res = self
            .http
            .post(self.records_url())
            .bearer_auth(&self.token)
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

    async fn remove_txt(&self, record_id: &str) -> Result<()> {
        let res = self
            .http
            .delete(format!("{}/{}", self.records_url(), record_id))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("deleting DNS TXT record")?;
        let status = res.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        bail!("DNS record deletion failed with HTTP {status}");
    }
}

impl DnsProvider for CloudflareDns {
    fn create_txt<'a>(&'a self, name: &'a str, value: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(self.add_txt(name, value))
    }

    fn delete_txt<'a>(&'a self, record_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.remove_txt(record_id))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::dns::test_support::serve;

    #[tokio::test]
    async fn txt_records_are_created_and_deleted_through_the_v4_api() {
        let mock = serve(|request| match request.method.as_str() {
            "POST" => (
                200,
                r#"{"success":true,"result":{"id":"rec-9"}}"#.to_string(),
            ),
            _ if request.target.ends_with("/rec-gone") => (404, "{}".to_string()),
            _ => (200, r#"{"success":true,"result":null}"#.to_string()),
        })
        .await;
        let dns = CloudflareDns::with_api_base(
            Client::new(),
            format!("{}/client/v4", mock.base_url),
            "zone-1".to_string(),
            "token-1".to_string(),
        );

        let id = dns
            .create_txt("_acme-challenge.t1.relay.test", "value-1")
            .await
            .unwrap();
        assert_eq!(id, "rec-9");
        dns.delete_txt(&id).await.unwrap();
        dns.delete_txt("rec-gone").await.unwrap();

        let requests = mock.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].target, "/client/v4/zones/zone-1/dns_records");
        assert_eq!(requests[0].header("authorization"), Some("Bearer token-1"));
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            body,
            json!({
                "type": "TXT",
                "name": "_acme-challenge.t1.relay.test",
                "content": "value-1",
                "ttl": 60,
            })
        );
        assert_eq!(requests[1].method, "DELETE");
        assert_eq!(
            requests[1].target,
            "/client/v4/zones/zone-1/dns_records/rec-9"
        );
        assert_eq!(
            requests[2].target,
            "/client/v4/zones/zone-1/dns_records/rec-gone"
        );
    }

    #[tokio::test]
    async fn api_errors_are_reported_with_cloudflare_messages() {
        let mock = serve(|_| {
            (
                200,
                r#"{"success":false,"errors":[{"message":"Invalid zone"}]}"#.to_string(),
            )
        })
        .await;
        let dns = CloudflareDns::with_api_base(
            Client::new(),
            format!("{}/client/v4", mock.base_url),
            "zone-1".to_string(),
            "token-1".to_string(),
        );

        let error = dns
            .create_txt("_acme-challenge.t1.relay.test", "value-1")
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "DNS record creation failed: Invalid zone"
        );
    }
}
