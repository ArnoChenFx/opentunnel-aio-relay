//! Shared application state.

use std::sync::Arc;

use crate::bridge::SessionManager;
use crate::config::Config;
use crate::db::Db;

pub struct AppState {
    pub config: Config,
    pub db: Arc<Db>,
    pub sessions: SessionManager,
    /// TLS server config for the API domain (SNI == config.domain).
    /// Built at startup from the auto-issued API certificate.
    pub api_tls: Arc<rustls::ServerConfig>,
    pub http: reqwest::Client,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
