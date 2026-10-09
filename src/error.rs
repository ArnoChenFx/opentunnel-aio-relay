use axum::{Json, http::StatusCode, response::IntoResponse};
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
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("service unavailable: {0}")]
    Unavailable(String),
    #[error("{0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    #[serde(rename = "_tag")]
    tag: &'static str,
    message: String,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, tag) = match &self {
            Error::BadRequest(_) => (StatusCode::BAD_REQUEST, "InvalidRequest"),
            Error::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            Error::NotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
            Error::Conflict(_) => (StatusCode::CONFLICT, "Conflict"),
            Error::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
        };
        let body = ErrorBody {
            tag,
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
