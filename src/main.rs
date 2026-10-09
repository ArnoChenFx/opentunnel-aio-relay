//! opentunnel-relay: single-binary self-hosted relay for the OpenTunnel protocol.
//!
//! Replaces the Cloudflare deployment (Worker + Durable Objects + Workflows +
//! external TCP relay) with one process on one VPS:
//!
//! - TCP 443 accepts everything and demultiplexes by TLS SNI:
//!   `domain` itself is terminated locally and serves the HTTP API;
//!   `*.<domain>` is forwarded as opaque encrypted bytes to the tunnel's
//!   bridge WebSocket (blind TLS: this server never sees plaintext).
//! - Tunnels, token hashes, CSRs and certificates persist in SQLite.
//! - Certificates are issued/renewed via ACME DNS-01 (Let's Encrypt by default).
//!
//! Existing clients (the Rust CLI/SDK) work unchanged: point them at this
//! server with `OPENTUNNEL_API=https://<domain>`.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use opentunnel_relay::{
    acme, api, bridge::SessionManager, config::Config, db::Db, guard::RateLimiter, ingress,
    state::AppState,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut config = Config::parse();
    config.normalize()?;
    // rustls uses the process-wide default provider; make it ring explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    std::fs::create_dir_all(&config.data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let db = Arc::new(Db::open(&config.data_dir.join("relay.db"))?);
    let http = reqwest::Client::builder()
        .user_agent("opentunnel-relay/0.1.0")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;

    // The API certificate must exist before we can serve anything on 443.
    // Issued via ACME DNS-01 on first run; reused afterwards.
    let api_tls = Arc::new(tokio::sync::RwLock::new(
        acme::ensure_api_cert(&config, &db, &http).await?,
    ));

    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        sessions: SessionManager::default(),
        api_tls,
        http,
        limiter: RateLimiter::new(config.rate_limit_per_hour),
    });
    let router = api::router(state.clone());

    let resumed = acme::resume_interrupted_issuances(&state).await?;
    if resumed > 0 {
        tracing::info!(
            resumed,
            "resumed certificate issuances interrupted by the previous run"
        );
    }

    // Background certificate renewals.
    tokio::spawn(acme::renewal_loop(state.clone()));
    tokio::spawn(acme::api_certificate_renewal_loop(state.clone()));

    tracing::info!(
        domain = %config.domain,
        data_dir = %config.data_dir.display(),
        "opentunnel-relay starting"
    );
    ingress::run(state, router).await
}
