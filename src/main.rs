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

use tokio::sync::Semaphore;

use clap::{CommandFactory, Parser};
use opentunnel_relay::{
    acme, api,
    bridge::SessionManager,
    config::Config,
    db::{self, Db},
    guard::RateLimiter,
    ingress, inspect,
    state::{now_rfc3339, AppState},
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = Config::parse();
    if let Some(command) = config.command.take() {
        return inspect::run(command, &config);
    }
    if config.domain.trim().is_empty() {
        Config::command()
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "the following required argument was not provided: --domain <DOMAIN>",
            )
            .exit();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    config.normalize()?;
    tracing::info!(
        dns_provider = config.dns_provider_kind()?.as_str(),
        "ACME DNS-01 challenges will use this DNS provider"
    );
    // rustls uses the process-wide default provider; make it ring explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    std::fs::create_dir_all(&config.data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let db = Arc::new(Db::open(&config.data_dir.join(db::DATABASE_FILE))?);
    db.set_meta(db::META_STARTED_AT, &now_rfc3339()).await?;
    tokio::spawn(heartbeat(db.clone()));
    let http = reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;

    // The API certificate must exist before we can serve anything on 443.
    // Issued via ACME DNS-01 on first run; reused afterwards.
    let api_tls = Arc::new(tokio::sync::RwLock::new(
        acme::ensure_api_cert(&config, &db, &http).await?,
    ));

    let acme_jobs = Arc::new(if config.acme_concurrency == 0 {
        Semaphore::new(Semaphore::MAX_PERMITS)
    } else {
        Semaphore::new(config.acme_concurrency)
    });
    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        sessions: SessionManager::default(),
        api_tls,
        http,
        limiter: RateLimiter::new(config.rate_limit_per_hour),
        acme_jobs,
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
    if !config.session_cache_idle.is_zero() {
        let cache_state = state.clone();
        let idle = config.session_cache_idle;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                let evicted = cache_state.sessions.evict_idle(idle).await;
                if evicted > 0 {
                    tracing::debug!(evicted, "evicted idle tunnel sessions from memory");
                }
            }
        });
    }

    tracing::info!(
        domain = %config.domain,
        data_dir = %config.data_dir.display(),
        "opentunnel-relay starting"
    );
    ingress::run(state, router).await
}

/// Keeps the database heartbeat fresh so `status` can tell a running relay from
/// one that has stopped.
async fn heartbeat(db: Arc<Db>) {
    loop {
        if let Err(e) = db.set_meta(db::META_HEARTBEAT_AT, &now_rfc3339()).await {
            tracing::warn!(error = %e, "could not record relay heartbeat");
        }
        tokio::time::sleep(Duration::from_secs(db::HEARTBEAT_INTERVAL_SECS)).await;
    }
}
