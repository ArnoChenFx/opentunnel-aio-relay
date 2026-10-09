//! HTTP API: provisioning, certificates, and the bridge WebSocket.
//! Paths and shapes follow `docs/protocol.md` so existing clients work unchanged.

use std::sync::Arc;

use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use crate::bridge::{self, hash_token, random_token, random_tunnel_id, token_matches};
use crate::db::{CertState, Db};
use crate::error::{Error, Result};
use crate::proto::api::{
    ApiError, BindCertificateRequest, CertificateInfo, CertificateState, CreateTunnelResponse,
    TunnelInfo, TunnelState,
};
use crate::state::{now_rfc3339, AppState};

const MAX_BRIDGE_WS_MESSAGE_SIZE: usize = 64 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/tunnel", post(create_tunnel))
        .route("/api/tunnel/{id}", get(get_tunnel).delete(delete_tunnel))
        .route(
            "/api/tunnel/{id}/certificate",
            post(bind_certificate).get(get_certificate),
        )
        .route("/api/tunnel/{id}/connect", get(connect_bridge))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|t| t.to_string())
}

fn authed_record(db: &Db, id: &str, headers: &HeaderMap) -> Result<crate::db::TunnelRecord> {
    let token =
        bearer_token(headers).ok_or_else(|| Error::Unauthorized("missing bearer token".into()))?;
    let record = db
        .get_tunnel(id)?
        .filter(|r| r.deleted_at.is_none())
        .ok_or_else(|| Error::TunnelNotFound {
            tunnel_id: id.to_string(),
        })?;
    if !token_matches(&token, &record.token_hash) {
        return Err(Error::Unauthorized("bad token".into()));
    }
    Ok(record)
}

fn tunnel_info(record: &crate::db::TunnelRecord) -> TunnelInfo {
    TunnelInfo {
        id: record.id.clone(),
        hostname: record.hostname.clone(),
        state: if record.state == "online" {
            TunnelState::Online
        } else {
            TunnelState::Offline
        },
        certificate_id: record.cert_id.clone(),
    }
}

fn certificate_info(record: &crate::db::TunnelRecord) -> Result<CertificateInfo> {
    let no_certificate = || Error::CertificateNotFound {
        tunnel_id: record.id.clone(),
    };
    let id = record.cert_id.clone().ok_or_else(no_certificate)?;
    let state = match record.cert_state {
        CertState::None => return Err(no_certificate()),
        CertState::Challenge => CertificateState::Challenge {
            token: record.challenge_token.clone().unwrap_or_default(),
            key: record.challenge_key.clone().unwrap_or_default(),
        },
        CertState::Issuing => CertificateState::Issuing,
        CertState::Ready => CertificateState::Ready {
            certificate: record.cert_pem.clone().unwrap_or_default(),
            chain: record.chain_pem.clone().unwrap_or_default(),
            expiry: record.cert_expiry.clone().unwrap_or_default(),
        },
        CertState::Failed => CertificateState::Failed {
            reason: record.fail_reason.clone().unwrap_or_default(),
        },
    };
    Ok(CertificateInfo { id, state })
}

async fn create_tunnel(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse> {
    let domain = state.config.domain.to_lowercase();
    // Retry on the (unlikely) id collision.
    for _ in 0..5 {
        let id = random_tunnel_id();
        let hostname = format!("{id}.{domain}");
        let token = random_token();
        let created =
            state
                .db
                .create_tunnel(&id, &hostname, &hash_token(&token), &now_rfc3339())?;
        if !created {
            continue;
        }
        let record = state.db.get_tunnel(&id)?.expect("just created");
        let body = CreateTunnelResponse {
            tunnel: tunnel_info(&record),
            token,
        };
        return Ok((StatusCode::CREATED, Json(body)));
    }
    Err(Error::Unavailable("could not allocate tunnel id".into()))
}

async fn get_tunnel(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    let record = authed_record(&state.db, &id, &headers)?;
    Ok(Json(tunnel_info(&record)))
}

async fn get_certificate(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    let record = authed_record(&state.db, &id, &headers)?;
    Ok(Json(certificate_info(&record)?))
}

async fn bind_certificate(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<BindCertificateRequest>,
) -> Result<impl IntoResponse> {
    let record = authed_record(&state.db, &id, &headers)?;
    let (request_hostname, identifiers) = validate_csr(&body.csr, &record.hostname)?;

    // Repeated submissions of the same CSR must not enqueue duplicate orders
    // while issuance is active or after success. A failed attempt is retryable.
    if record.cert_id.is_some()
        && record.csr_pem.as_deref() == Some(body.csr.as_str())
        && record.cert_state != CertState::Failed
    {
        return Ok((StatusCode::ACCEPTED, Json(certificate_info(&record)?)));
    }
    if matches!(record.cert_state, CertState::Challenge | CertState::Issuing) {
        return Err(Error::CertificateInProgress {
            tunnel_id: record.id.clone(),
        });
    }

    let cert_id = format!("cert_{}", bridge::random_session_id());
    let claimed = state
        .db
        .try_begin_issuance(&record.id, &cert_id, &body.csr)?;
    if !claimed {
        let latest = state
            .db
            .get_tunnel(&record.id)?
            .filter(|r| r.deleted_at.is_none())
            .ok_or_else(|| Error::TunnelNotFound {
                tunnel_id: record.id.clone(),
            })?;
        if latest.cert_id.is_some() && latest.csr_pem.as_deref() == Some(body.csr.as_str()) {
            return Ok((StatusCode::ACCEPTED, Json(certificate_info(&latest)?)));
        }
        return Err(Error::CertificateInProgress {
            tunnel_id: record.id.clone(),
        });
    }
    tracing::info!(tunnel = %record.id, cert = %cert_id, hostname = %request_hostname, identifiers = ?identifiers, "certificate issuance started");
    crate::acme::spawn_issuance(state.clone(), record.id.clone(), cert_id.clone());

    let record = state.db.get_tunnel(&record.id)?.expect("exists");
    Ok((StatusCode::ACCEPTED, Json(certificate_info(&record)?)))
}

/// Validates the CSR: signature, CN == hostname, SANs ⊆ {hostname, *.<hostname>}.
/// Returns (CN, identifiers).
fn validate_csr(csr_pem: &str, hostname: &str) -> Result<(String, Vec<String>)> {
    use x509_parser::prelude::*;

    let (_rem, pem) = parse_x509_pem(csr_pem.as_bytes())
        .map_err(|_| Error::BadRequest("failed to parse CSR PEM".into()))?;
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|_| Error::BadRequest("failed to parse CSR DER".into()))?;

    csr.verify_signature()
        .map_err(|_| Error::BadRequest("CSR signature is invalid".into()))?;

    let cn = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|attr| std::str::from_utf8(attr.as_slice()).ok())
        .ok_or_else(|| Error::BadRequest("CSR has no CN".into()))?
        .to_string();
    if cn != hostname {
        return Err(Error::BadRequest(format!(
            "CSR CN {cn:?} does not match tunnel hostname {hostname:?}"
        )));
    }

    let mut identifiers: Vec<String> = Vec::new();
    if let Some(extensions) = csr.requested_extensions() {
        for ext in extensions {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => identifiers.push(dns.to_string()),
                        _ => {
                            return Err(Error::BadRequest(
                                "CSR contains an unsupported non-DNS SAN".into(),
                            ));
                        }
                    }
                }
            }
        }
    }
    if identifiers.is_empty() {
        identifiers.push(cn.clone());
    }
    // Deduplicate, preserve order.
    let mut seen = std::collections::HashSet::new();
    identifiers.retain(|n| seen.insert(n.clone()));

    for name in &identifiers {
        if name != hostname && *name != format!("*.{hostname}") {
            return Err(Error::BadRequest(format!(
                "CSR SAN {name:?} is not allowed for this tunnel"
            )));
        }
    }
    Ok((cn, identifiers))
}

async fn delete_tunnel(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    let record = authed_record(&state.db, &id, &headers)?;
    state.db.delete_tunnel(&record.id, &now_rfc3339())?;
    // The persistent tombstone prevents a concurrent lookup from recreating
    // the session while its live bridges and channels are being shut down.
    state.sessions.remove(&record.id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn connect_bridge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    // The bridge requires the `opentunnel` WebSocket subprotocol.
    let protocols = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let offered: Vec<&str> = protocols.split(',').map(|s| s.trim()).collect();
    if !offered.contains(&crate::proto::bridge::WEBSOCKET_SUBPROTOCOL) {
        return Err(Error::BadRequest(
            "expected opentunnel WebSocket subprotocol".into(),
        ));
    }
    // Echo the subprotocol: the Rust client (tokio-tungstenite) rejects the
    // handshake if the server does not confirm the requested protocol.
    Ok(ws
        .max_message_size(MAX_BRIDGE_WS_MESSAGE_SIZE)
        .max_frame_size(MAX_BRIDGE_WS_MESSAGE_SIZE)
        .protocols([crate::proto::bridge::WEBSOCKET_SUBPROTOCOL])
        .on_upgrade(move |socket: WebSocket| async move {
            bridge::run_bridge(state, id, socket).await;
        }))
}

/// JSON error shape used by a few non-axum paths.
#[allow(dead_code)]
pub fn api_error_json(tag: &str, message: &str) -> String {
    serde_json::to_string(&ApiError {
        tag: tag.to_string(),
        message: message.to_string(),
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_csr(cn: &str, sans: &[&str]) -> String {
        let sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let params = rcgen::CertificateParams::new(sans).unwrap();
        let mut params = params;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    fn make_csr_with_extra_san(hostname: &str, extra: rcgen::SanType) -> String {
        let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]).unwrap();
        params.subject_alt_names.push(extra);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    #[test]
    fn csr_accepts_valid_request() {
        let csr = make_csr(
            "abc123.relay.test",
            &["abc123.relay.test", "*.abc123.relay.test"],
        );
        let (cn, ids) = validate_csr(&csr, "abc123.relay.test").unwrap();
        assert_eq!(cn, "abc123.relay.test");
        assert_eq!(
            ids,
            vec![
                "abc123.relay.test".to_string(),
                "*.abc123.relay.test".to_string()
            ]
        );
    }

    #[test]
    fn csr_rejects_wrong_cn() {
        let csr = make_csr("evil.test", &["evil.test"]);
        assert!(validate_csr(&csr, "abc123.relay.test").is_err());
    }

    #[test]
    fn csr_rejects_extra_san() {
        let csr = make_csr("abc123.relay.test", &["abc123.relay.test", "other.test"]);
        assert!(validate_csr(&csr, "abc123.relay.test").is_err());
    }

    #[test]
    fn csr_rejects_ip_san() {
        let csr = make_csr_with_extra_san(
            "abc123.relay.test",
            rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
        );
        let error = validate_csr(&csr, "abc123.relay.test").unwrap_err();
        assert!(error.to_string().contains("non-DNS SAN"));
    }

    #[test]
    fn csr_rejects_uri_san() {
        let uri = rcgen::Ia5String::try_from("spiffe://relay.test/client").unwrap();
        let csr = make_csr_with_extra_san("abc123.relay.test", rcgen::SanType::URI(uri));
        let error = validate_csr(&csr, "abc123.relay.test").unwrap_err();
        assert!(error.to_string().contains("non-DNS SAN"));
    }

    #[test]
    fn csr_rejects_tampered_signature() {
        let mut csr = make_csr("abc123.relay.test", &["abc123.relay.test"]);
        // Flip one base64 char in the middle of the body: still valid
        // base64/PEM and structurally parseable, but the signature no longer
        // verifies.
        let body_start = csr.find("MII").unwrap();
        let body_end = csr.find("-----END").unwrap();
        let idx = body_start + (body_end - body_start) * 2 / 3;
        let replacement = if &csr[idx..idx + 1] == "A" { "B" } else { "A" };
        csr.replace_range(idx..idx + 1, replacement);
        let err = validate_csr(&csr, "abc123.relay.test").unwrap_err();
        assert!(err.to_string().contains("signature"), "got: {err}");
    }
}
