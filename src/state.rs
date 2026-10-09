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
    /// Swapped after background certificate renewal for new handshakes.
    pub api_tls: Arc<tokio::sync::RwLock<Arc<rustls::ServerConfig>>>,
    pub http: reqwest::Client,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
