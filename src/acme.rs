//! ACME client (RFC 8555, DNS-01), with optional external account binding, plus
//! certificate lifecycle management.
//!
//! This replaces the Cloudflare Workflow of the hosted deployment. The flow
//! is the same: DNS-01 challenges via the Cloudflare DNS API, TXT cleanup
//! afterwards, and renewals driven by a background task. The private keys
//! never leave the machines that generated them: tunnel keys stay on the
//! clients (only CSRs are submitted), and the ACME account key is generated
//! once and kept in the local database.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::bridge::random_session_id;
use crate::config::Config;
use crate::db::{CertState, Db};
use crate::state::AppState;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const JOSE_JSON_CONTENT_TYPE: &str = "application/jose+json";

fn b64(data: &[u8]) -> String {
    B64.encode(data)
}
fn b64d(s: &str) -> Result<Vec<u8>> {
    Ok(B64.decode(s)?)
}

pub struct AcmeConfig {
    pub directory_url: String,
    pub email: String,
    pub eab_kid: String,
    pub eab_hmac: String,
    pub cf_token: String,
    pub cf_zone_id: String,
}

impl AcmeConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            directory_url: config.acme_url.clone(),
            email: config.acme_email.clone(),
            eab_kid: config.acme_eab_kid.clone(),
            eab_hmac: config.acme_eab_hmac.clone(),
            cf_token: config.cf_token.clone(),
            cf_zone_id: config.cf_zone_id.clone(),
        }
    }
}

pub struct Issued {
    pub certificate_pem: String,
    pub chain_pem: String,
    pub expiry_rfc3339: String,
}

// ---------------------------------------------------------------------------
// Account key (P-256), persisted so the ACME account is stable across restarts.
// ---------------------------------------------------------------------------

fn ensure_account_key(db: &Db) -> Result<Vec<u8>> {
    if let Some(stored) = db.get_meta("acme_account_key")? {
        return b64d(&stored);
    }
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .map_err(|_| anyhow!("ECDSA key generation failed"))?;
    let der = pkcs8.as_ref().to_vec();
    db.set_meta("acme_account_key", &b64(&der))?;
    Ok(der)
}

/// Returns (x_base64url, y_base64url) of the account public key.
fn public_jwk_coords(pkcs8: &[u8]) -> Result<(String, String)> {
    use ring::signature::KeyPair;
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|_| anyhow!("invalid ACME account key"))?;
    let raw = kp.public_key().as_ref();
    if raw.len() != 65 || raw[0] != 0x04 {
        bail!("unexpected public key encoding");
    }
    Ok((b64(&raw[1..33]), b64(&raw[33..65])))
}

fn public_jwk(x: &str, y: &str) -> Value {
    json!({"kty": "EC", "crv": "P-256", "x": x, "y": y})
}

/// RFC 7638 JWK thumbprint of the account key.
fn thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
    b64(digest.as_ref())
}

// ---------------------------------------------------------------------------
// JWS signing (ES256) and EAB (HS256), per RFC 8555 section 7.3.
// ---------------------------------------------------------------------------

/// Converts an ASN.1 DER ECDSA signature to raw R||S (64 bytes).
fn der_sig_to_raw(der: &[u8]) -> Result<[u8; 64]> {
    let mut pos = 0;
    let take = |pos: &mut usize, n: usize| -> Result<&[u8]> {
        if *pos + n > der.len() {
            bail!("malformed ECDSA signature");
        }
        let s = &der[*pos..*pos + n];
        *pos += n;
        Ok(s)
    };
    if take(&mut pos, 1)?[0] != 0x30 {
        bail!("malformed ECDSA signature");
    }
    let seq_len = take(&mut pos, 1)?[0] as usize;
    if seq_len & 0x80 != 0 || pos + seq_len != der.len() {
        bail!("malformed ECDSA signature");
    }
    let mut out = [0u8; 64];
    for half in out.chunks_mut(32) {
        if take(&mut pos, 1)?[0] != 0x02 {
            bail!("malformed ECDSA signature");
        }
        let len = take(&mut pos, 1)?[0] as usize;
        let mut int = take(&mut pos, len)?;
        // Strip leading zero padding, then left-pad to 32 bytes.
        while int.len() > 1 && int[0] == 0 {
            int = &int[1..];
        }
        if int.len() > 32 {
            bail!("malformed ECDSA signature");
        }
        half[32 - int.len()..].copy_from_slice(int);
    }
    Ok(out)
}

fn jws_parts(pkcs8: &[u8], protected: &Value, payload: &[u8]) -> Result<(String, String, String)> {
    let protected_b64 = b64(serde_json::to_vec(protected)?.as_slice());
    let payload_b64 = b64(payload);
    let message = format!("{protected_b64}.{payload_b64}");
    let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|_| anyhow!("invalid ACME account key"))?;
    let sig = kp
        .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
        .map_err(|_| anyhow!("signing failed"))?;
    let raw = der_sig_to_raw(sig.as_ref())?;
    Ok((protected_b64, payload_b64, b64(&raw)))
}

fn jws_body(pkcs8: &[u8], protected: &Value, payload: &[u8]) -> Result<Value> {
    let (p, pl, s) = jws_parts(pkcs8, protected, payload)?;
    Ok(json!({"protected": p, "payload": pl, "signature": s}))
}

fn jws_http_request(http: &Client, url: &str, body: &Value) -> Result<reqwest::Request> {
    Ok(http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, JOSE_JSON_CONTENT_TYPE)
        .body(serde_json::to_vec(body)?)
        .build()?)
}

/// Builds the externalAccountBinding object (for CAs that require it, e.g. ZeroSSL).
fn external_account_binding(
    eab_kid: &str,
    eab_hmac_b64: &str,
    new_account_url: &str,
    account_jwk: &Value,
) -> Result<Value> {
    let protected_b64 = b64(
        json!({"alg": "HS256", "kid": eab_kid, "url": new_account_url})
            .to_string()
            .as_bytes(),
    );
    let payload_b64 = b64(serde_json::to_vec(account_jwk)?.as_slice());
    let key_bytes = b64d(eab_hmac_b64).context("invalid EAB HMAC key")?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes);
    let tag = ring::hmac::sign(&key, format!("{protected_b64}.{payload_b64}").as_bytes());
    Ok(json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64(tag.as_ref()),
    }))
}

// ---------------------------------------------------------------------------
// Minimal ACME protocol driver.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

struct Acme {
    http: Client,
    dir: Directory,
    cfg: AcmeConfig,
    key_pkcs8: Vec<u8>,
    account_jwk: Value,
    account_url: Option<String>,
}

impl Acme {
    async fn new(http: Client, db: &Db, cfg: AcmeConfig) -> Result<Self> {
        let dir: Directory = http
            .get(&cfg.directory_url)
            .send()
            .await
            .context("fetching ACME directory")?
            .error_for_status()
            .context("ACME directory error")?
            .json()
            .await
            .context("parsing ACME directory")?;
        let key_pkcs8 = ensure_account_key(db)?;
        let (x, y) = public_jwk_coords(&key_pkcs8)?;
        Ok(Self {
            http,
            dir,
            cfg,
            key_pkcs8,
            account_jwk: public_jwk(&x, &y),
            account_url: None,
        })
    }

    async fn nonce(&self) -> Result<String> {
        let res = self
            .http
            .head(&self.dir.new_nonce)
            .send()
            .await
            .context("fetching nonce")?;
        res.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("ACME server did not return a nonce"))
    }

    /// POST with JWS; retries once on badNonce.
    async fn post_jws(
        &self,
        url: &str,
        use_kid: bool,
        payload: &[u8],
    ) -> Result<reqwest::Response> {
        for attempt in 0..2 {
            let nonce = self.nonce().await?;
            let mut protected = json!({"alg": "ES256", "nonce": nonce, "url": url});
            if use_kid {
                protected["kid"] = json!(self.account_url.as_deref().unwrap_or(""));
            } else {
                protected["jwk"] = self.account_jwk.clone();
            }
            let body = jws_body(&self.key_pkcs8, &protected, payload)?;
            let res = self
                .http
                .execute(jws_http_request(&self.http, url, &body)?)
                .await?;
            if res.status().as_u16() == 400 && attempt == 0 {
                let text = res.text().await.unwrap_or_default();
                if text.contains("badNonce") {
                    continue;
                }
                bail!("ACME request failed: {text}");
            }
            return res
                .error_for_status()
                .context("ACME request failed")
                .map_err(|e| anyhow!("{e}"));
        }
        unreachable!()
    }

    /// POST-as-GET (empty JWS payload).
    async fn post_as_get(&self, url: &str) -> Result<Value> {
        let res = self.post_jws(url, true, b"").await?;
        res.json().await.context("parsing ACME response")
    }

    /// Tells the server the DNS record is in place (RFC 8555 section 7.5.1).
    /// The payload must be the JSON object `{}`; an empty payload is
    /// POST-as-GET, which reads the challenge without starting validation.
    async fn signal_challenge_ready(&self, challenge_url: &str) -> Result<()> {
        self.post_jws(challenge_url, true, b"{}").await?;
        Ok(())
    }

    async fn new_account(&mut self) -> Result<()> {
        let mut payload = json!({
            "contact": [format!("mailto:{}", self.cfg.email)],
            "termsOfServiceAgreed": true,
        });
        // External account binding is only sent for CAs that require it
        // (e.g. ZeroSSL). Let's Encrypt does not use EAB.
        if !self.cfg.eab_kid.is_empty() && !self.cfg.eab_hmac.is_empty() {
            let eab = external_account_binding(
                &self.cfg.eab_kid,
                &self.cfg.eab_hmac,
                &self.dir.new_account,
                &self.account_jwk,
            )?;
            payload["externalAccountBinding"] = eab;
        }
        let payload = serde_json::to_vec(&payload)?;
        let res = self
            .post_jws(&self.dir.new_account, false, &payload)
            .await
            .context("creating ACME account")?;
        let url = res
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        self.account_url = url;
        if self.account_url.is_none() {
            bail!("ACME server did not return an account URL");
        }
        Ok(())
    }
}

struct DnsChallenge {
    url: String,
    token: String,
    /// TXT record content.
    key: String,
    /// Base domain the TXT record goes under.
    base: String,
}

/// Issues a certificate for `identifiers` using `csr_pem` (PEM).
/// Calls `on_challenge(token, key)` once DNS-01 challenges are placed, so the
/// caller can expose the `challenge` state while issuance runs.
pub async fn issue(
    http: &Client,
    db: &Db,
    cfg: &AcmeConfig,
    identifiers: &[String],
    csr_pem: &str,
    on_challenge: impl Fn(&str, &str),
) -> Result<Issued> {
    let mut acme = Acme::new(
        http.clone(),
        db,
        AcmeConfig {
            directory_url: cfg.directory_url.clone(),
            email: cfg.email.clone(),
            eab_kid: cfg.eab_kid.clone(),
            eab_hmac: cfg.eab_hmac.clone(),
            cf_token: cfg.cf_token.clone(),
            cf_zone_id: cfg.cf_zone_id.clone(),
        },
    )
    .await?;
    acme.new_account().await?;

    // --- newOrder ---
    let order_ids: Vec<Value> = identifiers
        .iter()
        .map(|d| json!({"type": "dns", "value": d}))
        .collect();
    let new_order_payload = serde_json::to_vec(&json!({"identifiers": order_ids}))?;
    let res = acme
        .post_jws(&acme.dir.new_order.clone(), true, &new_order_payload)
        .await?;
    if res.status().as_u16() != 201 {
        bail!("ACME newOrder failed: {}", res.status());
    }
    let order_url = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("newOrder returned no location"))?
        .to_string();
    let order: Value = res.json().await?;
    let finalize_url = order
        .get("finalize")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("order has no finalize URL"))?
        .to_string();

    // --- authorizations: collect dns-01 challenges ---
    let (x, y) = public_jwk_coords(&acme.key_pkcs8)?;
    let tp = thumbprint(&x, &y);
    let mut challenges: Vec<DnsChallenge> = Vec::new();
    let auth_urls: Vec<String> = order
        .get("authorizations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("order has no authorizations"))?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    for auth_url in &auth_urls {
        let auth: Value = acme.post_as_get(auth_url).await?;
        let challenge = auth
            .get("challenges")
            .and_then(|v| v.as_array())
            .and_then(|cs| {
                cs.iter()
                    .find(|c| c.get("type").and_then(|t| t.as_str()) == Some("dns-01"))
            })
            .ok_or_else(|| anyhow!("ACME server did not offer dns-01"))?;
        let token = challenge
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow!("challenge has no token"))?
            .to_string();
        let url = challenge
            .get("url")
            .and_then(|u| u.as_str())
            .ok_or_else(|| anyhow!("challenge has no url"))?
            .to_string();
        let identifier = auth
            .get("identifier")
            .and_then(|i| i.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let key_auth = format!("{token}.{tp}");
        let digest = ring::digest::digest(&ring::digest::SHA256, key_auth.as_bytes());
        challenges.push(DnsChallenge {
            url,
            token,
            key: b64(digest.as_ref()),
            base: identifier.trim_start_matches("*.").to_string(),
        });
    }
    if let Some(first) = challenges.first() {
        on_challenge(&first.token, &first.key);
    }

    // --- place TXT records ---
    let mut record_ids: Vec<String> = Vec::new();
    let place = async {
        for ch in &challenges {
            let name = format!("_acme-challenge.{}", ch.base);
            let id = crate::dns::create_txt(http, &cfg.cf_zone_id, &cfg.cf_token, &name, &ch.key)
                .await?;
            record_ids.push(id);
        }
        anyhow::Ok(())
    };
    let place_result = place.await;
    let cleanup = async {
        for id in &record_ids {
            let _ = crate::dns::delete_txt(http, &cfg.cf_zone_id, &cfg.cf_token, id).await;
        }
    };

    let run = async {
        place_result?;
        // --- wait for propagation, then trigger validation ---
        for ch in &challenges {
            let name = format!("_acme-challenge.{}", ch.base);
            let mut expected = HashSet::new();
            expected.insert(ch.key.clone());
            crate::dns::wait_for_txt(http, &name, &expected, Duration::from_secs(60)).await?;
        }
        for ch in &challenges {
            acme.signal_challenge_ready(&ch.url).await?;
        }
        for auth_url in &auth_urls {
            let mut auth: Value = acme.post_as_get(auth_url).await?;
            for _ in 0..30 {
                if auth.get("status").and_then(|s| s.as_str()) != Some("pending") {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                auth = acme.post_as_get(auth_url).await?;
            }
            if auth.get("status").and_then(|s| s.as_str()) != Some("valid") {
                bail!("ACME authorization ended in {:?}", auth.get("status"));
            }
        }

        // --- finalize with the CSR ---
        let csr_der = pem_to_der(csr_pem, "CERTIFICATE REQUEST")?;
        let finalize_payload = serde_json::to_vec(&json!({"csr": b64(&csr_der)}))?;
        let res = acme
            .post_jws(&finalize_url, true, &finalize_payload)
            .await?;
        let mut order: Value = res.json().await?;
        for _ in 0..30 {
            if order.get("status").and_then(|s| s.as_str()) != Some("processing") {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            order = acme.post_as_get(&order_url).await?;
        }
        let cert_url = order
            .get("certificate")
            .and_then(|c| c.as_str())
            .filter(|_| order.get("status").and_then(|s| s.as_str()) == Some("valid"))
            .ok_or_else(|| anyhow!("ACME order ended in {:?}", order.get("status")))?;
        let res = acme.post_jws(cert_url, true, b"").await?;
        let chain_pem = res.text().await.context("downloading certificate")?;
        anyhow::Ok(chain_pem)
    };

    let chain_pem = match run.await {
        Ok(pem) => pem,
        Err(e) => {
            cleanup.await;
            return Err(e);
        }
    };
    cleanup.await;

    let blocks = split_pem_chain(&chain_pem);
    let certificate_pem = blocks.first().cloned().unwrap_or_default();
    if certificate_pem.is_empty() {
        bail!("ACME response did not contain a certificate");
    }
    let chain = blocks[1..].join("\n");
    let expiry_rfc3339 = cert_expiry_pem(&certificate_pem)?;
    Ok(Issued {
        certificate_pem,
        chain_pem: chain,
        expiry_rfc3339,
    })
}

fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    use x509_parser::prelude::parse_x509_pem;
    let (_rem, parsed) = parse_x509_pem(pem.as_bytes()).map_err(|_| anyhow!("invalid PEM"))?;
    if parsed.label != label {
        bail!("expected PEM label {label}");
    }
    Ok(parsed.contents)
}

fn split_pem_chain(chain: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in chain.lines() {
        current.push_str(line);
        current.push('\n');
        if line.contains("END CERTIFICATE") {
            blocks.push(current.clone());
            current.clear();
        }
    }
    if !current.trim().is_empty() {
        blocks.push(current);
    }
    blocks
}

pub fn cert_expiry_pem(cert_pem: &str) -> Result<String> {
    use x509_parser::prelude::*;
    let (_rem, pem) =
        parse_x509_pem(cert_pem.as_bytes()).map_err(|_| anyhow!("invalid certificate PEM"))?;
    let (_, cert) =
        X509Certificate::from_der(&pem.contents).map_err(|_| anyhow!("invalid certificate DER"))?;
    let ts = cert.validity().not_after.timestamp();
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .ok_or_else(|| anyhow!("invalid certificate expiry"))
}

// ---------------------------------------------------------------------------
// Lifecycle: issuance tasks, renewals, API certificate bootstrap.
// ---------------------------------------------------------------------------

/// Derives the ACME identifiers from a stored CSR: its DNS SANs, falling
/// back to the CN when there are none (mirrors the original server).
fn identifiers_from_csr(csr_pem: &str) -> Result<Vec<String>> {
    use x509_parser::prelude::*;
    let (_rem, pem) = parse_x509_pem(csr_pem.as_bytes()).map_err(|_| anyhow!("bad CSR PEM"))?;
    let (_, csr) =
        X509CertificationRequest::from_der(&pem.contents).map_err(|_| anyhow!("bad CSR DER"))?;
    let cn = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|a| std::str::from_utf8(a.as_slice()).ok())
        .ok_or_else(|| anyhow!("CSR has no CN"))?
        .to_string();
    let mut ids: Vec<String> = Vec::new();
    if let Some(extensions) = csr.requested_extensions() {
        for ext in extensions {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => ids.push(dns.to_string()),
                        _ => bail!("unsupported non-DNS SAN in CSR"),
                    }
                }
            }
        }
    }
    if ids.is_empty() {
        ids.push(cn);
    }
    let mut seen = std::collections::HashSet::new();
    ids.retain(|n| seen.insert(n.clone()));
    Ok(ids)
}

pub fn spawn_issuance(state: Arc<AppState>, tunnel_id: String, cert_id: String) {
    tokio::spawn(async move {
        match issue_for_tunnel(&state, &tunnel_id, &cert_id).await {
            Ok(()) => tracing::info!(tunnel = %tunnel_id, cert = %cert_id, "certificate ready"),
            Err(e) => {
                tracing::error!(tunnel = %tunnel_id, cert = %cert_id, error = %e, "issuance failed")
            }
        }
    });
}

async fn issue_for_tunnel(state: &AppState, tunnel_id: &str, cert_id: &str) -> Result<()> {
    let fail = |reason: &str| {
        let _ = state.db.set_failed(cert_id, reason);
    };
    let record = state
        .db
        .get_tunnel(tunnel_id)?
        .filter(|r| r.deleted_at.is_none())
        .ok_or_else(|| anyhow!("tunnel gone"))?;
    if record.cert_id.as_deref() != Some(cert_id) {
        return Ok(()); // superseded by a newer issuance
    }
    let issuance = async {
        let csr_pem = record
            .csr_pem
            .clone()
            .ok_or_else(|| anyhow!("no CSR stored"))?;
        let identifiers = identifiers_from_csr(&csr_pem)?;
        let cfg = AcmeConfig::from_config(&state.config);
        issue(
            &state.http,
            &state.db,
            &cfg,
            &identifiers,
            &csr_pem,
            |token, key| {
                let _ = state.db.set_challenge(cert_id, token, key);
            },
        )
        .await
    }
    .await;
    let issued = match issuance {
        Ok(issued) => issued,
        Err(e) => {
            fail(&e.to_string());
            return Err(e);
        }
    };
    if let Err(e) = state.db.set_ready(
        cert_id,
        &issued.certificate_pem,
        &issued.chain_pem,
        &issued.expiry_rfc3339,
    ) {
        fail(&e.to_string());
        return Err(e.into());
    }
    if let Some(session) = state.sessions.get_or_load(&state.db, tunnel_id).await? {
        session
            .cert_ready
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

/// Hourly scan: renew certificates expiring within 30 days for tunnels that
/// were connected in the last 90 days. The stored CSR is reused, so the key
/// never changes and the server never sees it.
pub async fn renewal_loop(state: Arc<AppState>) {
    const RENEW_BEFORE_SECS: i64 = 30 * 24 * 3600;
    const ACTIVE_WINDOW_SECS: i64 = 90 * 24 * 3600;
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let now = chrono::Utc::now().timestamp();
        let candidates =
            match state
                .db
                .renewal_candidates(RENEW_BEFORE_SECS, ACTIVE_WINDOW_SECS, now)
            {
                Ok(list) => list,
                Err(e) => {
                    tracing::error!(error = %e, "renewal scan failed");
                    continue;
                }
            };
        for record in candidates {
            // Skip if an issuance is already in flight.
            let fresh = match state.db.get_tunnel(&record.id) {
                Ok(Some(r))
                    if matches!(r.cert_state, CertState::Ready | CertState::Failed)
                        && r.cert_pem.is_some() =>
                {
                    r
                }
                _ => continue,
            };
            let csr = match fresh.csr_pem {
                Some(csr) => csr,
                None => continue,
            };
            let cert_id = format!("cert_{}", random_session_id());
            if state
                .db
                .try_begin_issuance(&record.id, &cert_id, &csr)
                .unwrap_or(false)
            {
                tracing::info!(tunnel = %record.id, "starting certificate renewal");
                spawn_issuance(state.clone(), record.id.clone(), cert_id);
            }
        }
    }
}

/// Ensures the API domain has a TLS certificate, issuing one via ACME DNS-01
/// on first run (or when it expires within 30 days). Stored as PEM files next
/// to the database.
pub async fn ensure_api_cert(
    config: &Config,
    db: &Db,
    http: &Client,
) -> Result<Arc<rustls::ServerConfig>> {
    let dir = &config.data_dir;
    let cert_path = dir.join("api-cert.pem");
    let key_path = dir.join("api-key.pem");

    let load = || -> Result<Arc<rustls::ServerConfig>> {
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        restrict_private_file(&key_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        build_server_config(&cert_pem, &key_pem)
    };

    if let Ok(cfg) = load() {
        if let Ok(cert_pem) = std::fs::read_to_string(&cert_path) {
            if let Ok(expiry) = cert_expiry_pem(&cert_pem) {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&expiry) {
                    if dt.timestamp() - chrono::Utc::now().timestamp() > 30 * 24 * 3600 {
                        tracing::info!("using existing API certificate");
                        return Ok(cfg);
                    }
                }
            }
        }
    }

    tracing::info!(domain = %config.domain, "issuing API certificate via ACME DNS-01");
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| anyhow!("key generation failed: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![config.domain.clone()])
        .map_err(|e| anyhow!("certificate params: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.domain.clone());
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| anyhow!("CSR build failed: {e}"))?;
    let csr_pem = csr.pem().map_err(|e| anyhow!("CSR PEM failed: {e}"))?;
    let key_pem = key_pair.serialize_pem();

    let cfg = AcmeConfig::from_config(config);
    let issued = issue(
        http,
        db,
        &cfg,
        std::slice::from_ref(&config.domain),
        &csr_pem,
        |_, _| {},
    )
    .await?;
    let fullchain = if issued.chain_pem.is_empty() {
        issued.certificate_pem.clone()
    } else {
        format!("{}\n{}", issued.certificate_pem, issued.chain_pem)
    };
    std::fs::write(&cert_path, &fullchain)?;
    write_private_file(&key_path, key_pem.as_bytes())?;
    tracing::info!("API certificate issued");
    build_server_config(&fullchain, &key_pem)
}

/// Periodically rechecks the API certificate and renews it within 30 days of
/// expiry. The replacement config is swapped only after issuance succeeds, so
/// existing connections remain intact and new handshakes use the new cert.
pub async fn api_certificate_renewal_loop(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        match ensure_api_cert(&state.config, &state.db, &state.http).await {
            Ok(config) => {
                *state.api_tls.write().await = config;
            }
            Err(error) => {
                tracing::error!(error = %error, "API certificate renewal check failed");
            }
        }
    }
}

fn restrict_private_file(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    restrict_private_file(path)
}

fn build_server_config(cert_pem: &str, key_pem: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| anyhow!("invalid certificate PEM"))?;
    if certs.is_empty() {
        bail!("no certificates in PEM");
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|_| anyhow!("invalid key PEM"))?
        .ok_or_else(|| anyhow!("no private key in PEM"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("TLS config: {e}"))?;
    Ok(Arc::new(config))
}

/// Called when a bridge attaches: renew now if the certificate is within 30
/// days of expiry (covers tunnels that went idle and came back).
pub async fn maybe_renew_on_attach(state: Arc<AppState>, tunnel_id: &str) {
    let record = match state.db.get_tunnel(tunnel_id) {
        Ok(Some(r))
            if r.deleted_at.is_none()
                && matches!(r.cert_state, CertState::Ready | CertState::Failed)
                && r.cert_pem.is_some() =>
        {
            r
        }
        _ => return,
    };
    let expiring = record
        .cert_expiry
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp() - chrono::Utc::now().timestamp() < 30 * 24 * 3600)
        .unwrap_or(false);
    if !expiring {
        return;
    }
    let csr = match record.csr_pem {
        Some(csr) => csr,
        None => return,
    };
    let cert_id = format!("cert_{}", random_session_id());
    if state
        .db
        .try_begin_issuance(tunnel_id, &cert_id, &csr)
        .unwrap_or(false)
    {
        tracing::info!(tunnel = %tunnel_id, "renewing certificate on attach");
        spawn_issuance(state, tunnel_id.to_string(), cert_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap()
        .as_ref()
        .to_vec()
    }

    #[test]
    fn post_as_get_jws_payload_is_empty() {
        let body = jws_body(&test_key(), &json!({"alg": "ES256"}), b"").unwrap();
        assert_eq!(body["payload"], "");
    }

    #[tokio::test]
    async fn challenge_ready_signal_posts_json_object_not_post_as_get() {
        use axum::{extract::State, routing::get, routing::post, Router};

        #[derive(Clone, Default)]
        struct Seen(Arc<std::sync::Mutex<Vec<String>>>);

        async fn nonce() -> ([(&'static str, &'static str); 1], &'static str) {
            ([("replay-nonce", "test-nonce")], "")
        }
        async fn record(State(seen): State<Seen>, body: String) -> axum::Json<Value> {
            seen.0.lock().unwrap().push(body);
            axum::Json(json!({"type": "dns-01", "status": "pending"}))
        }

        let seen = Seen::default();
        let app = Router::new()
            .route("/nonce", get(nonce))
            .route("/challenge", post(record))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let acme = Acme {
            http: Client::new(),
            dir: Directory {
                new_nonce: format!("{base}/nonce"),
                new_account: format!("{base}/new-account"),
                new_order: format!("{base}/new-order"),
            },
            cfg: AcmeConfig {
                directory_url: String::new(),
                email: String::new(),
                eab_kid: String::new(),
                eab_hmac: String::new(),
                cf_token: String::new(),
                cf_zone_id: String::new(),
            },
            key_pkcs8: test_key(),
            account_jwk: json!({}),
            account_url: Some(format!("{base}/account/1")),
        };
        let challenge = format!("{base}/challenge");
        acme.signal_challenge_ready(&challenge).await.unwrap();
        acme.post_as_get(&challenge).await.unwrap();

        let payloads: Vec<Vec<u8>> = seen
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|raw| {
                let envelope: Value = serde_json::from_str(raw).unwrap();
                b64d(envelope["payload"].as_str().unwrap()).unwrap()
            })
            .collect();
        assert_eq!(payloads, vec![b"{}".to_vec(), Vec::new()]);
    }

    #[test]
    fn acme_jws_requests_use_jose_json_content_type() {
        let body = json!({"protected": "p", "payload": "", "signature": "s"});
        let request =
            jws_http_request(&Client::new(), "https://acme.test/new-account", &body).unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            JOSE_JSON_CONTENT_TYPE
        );
        assert_eq!(
            serde_json::from_slice::<Value>(request.body().unwrap().as_bytes().unwrap()).unwrap(),
            body
        );
    }

    #[tokio::test]
    async fn new_account_retries_bad_nonce_with_a_fresh_nonce() {
        use axum::body::Bytes;
        use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
        use axum::response::IntoResponse;
        use axum::routing::{head, post};
        use axum::Router;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let nonce_count = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
        let nonce_route = {
            let nonce_count = nonce_count.clone();
            head(move || {
                let nonce_count = nonce_count.clone();
                async move {
                    let nonce = nonce_count.fetch_add(1, Ordering::SeqCst);
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        "replay-nonce",
                        HeaderValue::from_str(&format!("nonce-{nonce}")).unwrap(),
                    );
                    (headers, "")
                }
            })
        };
        let account_route = {
            let attempts = attempts.clone();
            let received = received.clone();
            post(move |body: Bytes| {
                let attempts = attempts.clone();
                let received = received.clone();
                async move {
                    received
                        .lock()
                        .await
                        .push(serde_json::from_slice(&body).unwrap());
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            StatusCode::BAD_REQUEST,
                            r#"{"type":"urn:ietf:params:acme:error:badNonce"}"#,
                        )
                            .into_response()
                    } else {
                        let mut response = StatusCode::CREATED.into_response();
                        response.headers_mut().insert(
                            header::LOCATION,
                            HeaderValue::from_static("https://acme.test/account/123"),
                        );
                        response
                    }
                }
            })
        };
        let app = Router::new()
            .route("/nonce", nonce_route)
            .route("/account", account_route);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let key_pkcs8 = test_key();
        let (x, y) = public_jwk_coords(&key_pkcs8).unwrap();
        let mut acme = Acme {
            http: Client::new(),
            dir: Directory {
                new_nonce: format!("{base}/nonce"),
                new_account: format!("{base}/account"),
                new_order: format!("{base}/order"),
            },
            cfg: AcmeConfig {
                directory_url: base,
                email: "test@example.invalid".into(),
                eab_kid: String::new(),
                eab_hmac: String::new(),
                cf_token: String::new(),
                cf_zone_id: String::new(),
            },
            key_pkcs8,
            account_jwk: public_jwk(&x, &y),
            account_url: None,
        };

        let result = acme.new_account().await;
        server.abort();
        result.unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(nonce_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            acme.account_url.as_deref(),
            Some("https://acme.test/account/123")
        );
        let received = received.lock().await;
        assert_eq!(received.len(), 2);
        for (index, body) in received.iter().enumerate() {
            let protected = B64.decode(body["protected"].as_str().unwrap()).unwrap();
            let protected: Value = serde_json::from_slice(&protected).unwrap();
            assert_eq!(protected["nonce"], format!("nonce-{index}"));
            assert!(protected.get("jwk").is_some());
        }
    }

    #[test]
    fn identifier_extraction_rejects_non_dns_sans() {
        let hostname = "abc123.relay.test";
        let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        assert!(identifiers_from_csr(&csr)
            .unwrap_err()
            .to_string()
            .contains("non-DNS SAN"));
    }
}
