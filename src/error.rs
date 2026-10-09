//! Errors returned by the HTTP API. Tags and statuses follow the official
//! protocol (`packages/protocol/src/api/errors.ts`) so clients can branch on
//! them exactly as they do against the hosted service. The official client
//! keys its certificate polling on `CertificateInProgressError`, so a generic
//! conflict tag would make it fail where it should wait.

use std::time::Duration;

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("tunnel not found")]
    TunnelNotFound { tunnel_id: String },
    #[error("no certificate")]
    CertificateNotFound { tunnel_id: String },
    #[error("certificate issuance in progress")]
    CertificateInProgress { tunnel_id: String },
    #[error("service unavailable: {0}")]
    Unavailable(String),
    #[error("{message}")]
    RateLimited {
        message: String,
        retry_after: Duration,
    },
    #[error("{0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    #[serde(rename = "_tag")]
    tag: &'static str,
    message: &'a str,
    #[serde(rename = "tunnelID", skip_serializing_if = "Option::is_none")]
    tunnel_id: Option<&'a str>,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, tag, message) = match &self {
            Error::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                "InvalidRequestError",
                message.clone(),
            ),
            Error::Unauthorized(message) => (
                StatusCode::UNAUTHORIZED,
                "UnauthorizedError",
                message.clone(),
            ),
            Error::TunnelNotFound { .. } => (
                StatusCode::NOT_FOUND,
                "TunnelNotFoundError",
                self.to_string(),
            ),
            Error::CertificateNotFound { .. } => (
                StatusCode::NOT_FOUND,
                "CertificateNotFoundError",
                self.to_string(),
            ),
            Error::CertificateInProgress { .. } => (
                StatusCode::CONFLICT,
                "CertificateInProgressError",
                self.to_string(),
            ),
            Error::Unavailable(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailableError",
                message.clone(),
            ),
            Error::RateLimited { message, .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimitedError",
                message.clone(),
            ),
            Error::Db(_) | Error::Io(_) | Error::Json(_) | Error::Internal(_) => {
                tracing::error!(error = %self, "internal error while serving request");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "internal server error".to_string(),
                )
            }
        };
        let tunnel_id = match &self {
            Error::TunnelNotFound { tunnel_id }
            | Error::CertificateNotFound { tunnel_id }
            | Error::CertificateInProgress { tunnel_id } => Some(tunnel_id.as_str()),
            _ => None,
        };
        let body = ErrorBody {
            tag,
            message: &message,
            tunnel_id,
        };
        let mut response = (status, Json(body)).into_response();
        if let Error::RateLimited { retry_after, .. } = &self {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(retry_after.as_secs().max(1)),
            );
        }
        response
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn render(error: Error) -> (StatusCode, serde_json::Value) {
        let response = error.into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn certificate_in_progress_uses_official_tag_and_tunnel_id() {
        let (status, body) = render(Error::CertificateInProgress {
            tunnel_id: "t1".into(),
        })
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["_tag"], "CertificateInProgressError");
        assert_eq!(body["tunnelID"], "t1");
    }

    #[tokio::test]
    async fn missing_tunnel_uses_official_tag() {
        let (status, body) = render(Error::TunnelNotFound {
            tunnel_id: "t2".into(),
        })
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["_tag"], "TunnelNotFoundError");
        assert_eq!(body["tunnelID"], "t2");
    }

    #[tokio::test]
    async fn rate_limited_responses_carry_retry_after() {
        let response = Error::RateLimited {
            message: "slow down".into(),
            retry_after: Duration::from_secs(90),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "90");
    }

    #[tokio::test]
    async fn internal_details_are_not_returned_to_clients() {
        let (status, body) =
            render(Error::Internal("/var/lib/relay/relay.db is locked".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["_tag"], "InternalError");
        assert_eq!(body["message"], "internal server error");
        assert!(body.get("tunnelID").is_none());
    }
}
