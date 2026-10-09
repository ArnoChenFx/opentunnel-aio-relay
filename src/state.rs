//! Shared application state.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::bridge::SessionManager;
use crate::config::{Config, IpNetwork};
use crate::db::Db;
use crate::error::{Error, Result};

const MAX_TRACKED_CREATION_IPS: usize = 4096;

pub struct TunnelCreationPolicy {
    allowlist: Vec<IpNetwork>,
    rate_limit: usize,
    rate_window: Duration,
    max_active_tunnels: usize,
    attempts: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl TunnelCreationPolicy {
    pub fn new(config: &Config) -> Self {
        Self {
            allowlist: config.tunnel_create_ip_allowlist.clone(),
            rate_limit: config.tunnel_create_rate_limit,
            rate_window: Duration::from_secs(config.tunnel_create_rate_window_secs),
            max_active_tunnels: config.max_active_tunnels,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    pub fn max_active_tunnels(&self) -> usize {
        self.max_active_tunnels
    }

    pub fn check_source_ip(&self, source_ip: IpAddr) -> Result<()> {
        if !self.allowlist.is_empty()
            && !self
                .allowlist
                .iter()
                .any(|network| network.contains(source_ip))
        {
            return Err(Error::Forbidden(
                "source IP is not allowed to create tunnels".into(),
            ));
        }

        let now = Instant::now();
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|error| Error::Internal(format!("rate limiter lock failed: {error}")))?;

        for timestamps in attempts.values_mut() {
            while timestamps
                .front()
                .is_some_and(|timestamp| now.duration_since(*timestamp) >= self.rate_window)
            {
                timestamps.pop_front();
            }
        }
        attempts.retain(|_, timestamps| !timestamps.is_empty());

        if !attempts.contains_key(&source_ip) && attempts.len() >= MAX_TRACKED_CREATION_IPS {
            return Err(Error::RateLimited(
                "tunnel creation rate limiter is at capacity; try again later".into(),
            ));
        }

        let timestamps = attempts.entry(source_ip).or_default();
        if timestamps.len() >= self.rate_limit {
            return Err(Error::RateLimited(format!(
                "tunnel creation rate limit exceeded; retry after {} seconds",
                self.rate_window.as_secs()
            )));
        }
        timestamps.push_back(now);
        Ok(())
    }
}

pub struct AppState {
    pub config: Config,
    pub db: Arc<Db>,
    pub sessions: SessionManager,
    pub tunnel_creation_policy: TunnelCreationPolicy,
    /// TLS server config for the API domain (SNI == config.domain).
    /// Swapped after background certificate renewal for new handshakes.
    pub api_tls: Arc<tokio::sync::RwLock<Arc<rustls::ServerConfig>>>,
    pub http: reqwest::Client,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
