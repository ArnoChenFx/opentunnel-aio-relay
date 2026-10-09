//! SQLite persistence. One row per tunnel holds the identity, token hash,
//! certificate state, and CSR. Renewal bookkeeping sits beside the active
//! certificate so a failing renewal never changes what clients are served.
//!
//! One connection sits behind a std mutex. Every call runs on the blocking
//! pool, so async workers never wait on disk I/O, and each closure is atomic
//! with respect to the others because it holds the mutex for its whole body.
//! Timestamps used for scheduling are unix milliseconds; `created_at` and
//! `deleted_at` stay RFC 3339 strings as the protocol exposes them.

use std::fs::OpenOptions;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::error::{Error, Result};

/// Length of the rolling window the daily certificate budget counts over.
pub const ISSUANCE_WINDOW_MS: i64 = 24 * 3600 * 1000;
const HOUR_MS: i64 = 3600 * 1000;

/// Certificate lifecycle state, mirroring the protocol's CertificateState.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertState {
    None,
    Challenge,
    Issuing,
    Ready,
    Failed,
}

impl CertState {
    pub fn as_str(self) -> &'static str {
        match self {
            CertState::None => "none",
            CertState::Challenge => "challenge",
            CertState::Issuing => "issuing",
            CertState::Ready => "ready",
            CertState::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "challenge" => CertState::Challenge,
            "issuing" => CertState::Issuing,
            "ready" => CertState::Ready,
            "failed" => CertState::Failed,
            _ => CertState::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelRecord {
    pub id: String,
    pub hostname: String,
    pub token_hash: String,
    pub state: String, // "offline" | "online"
    pub deleted_at: Option<String>,
    pub cert_id: Option<String>,
    pub cert_state: CertState,
    pub cert_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub cert_expiry: Option<String>, // RFC3339
    pub challenge_token: Option<String>,
    pub challenge_key: Option<String>,
    pub fail_reason: Option<String>,
    pub csr_pem: Option<String>,
    pub created_at: String,
    pub last_connected_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    Created,
    IdTaken,
    LimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    Claimed,
    Busy,
    NotFound,
    /// The daily order budget is spent. `retry_after_ms` is when the oldest
    /// counted order leaves the window and frees a slot.
    DailyLimit {
        retry_after_ms: i64,
    },
}

/// Delay before the next renewal attempt after `attempts` consecutive failures:
/// one hour, doubling, capped at twelve hours.
pub fn renewal_backoff_ms(attempts: u32) -> i64 {
    let shift = attempts.saturating_sub(1).min(16);
    (HOUR_MS << shift).min(12 * HOUR_MS)
}

const RECORD_COLUMNS: &str = "id, hostname, token_hash, state, deleted_at, cert_id, cert_state,
    cert_pem, chain_pem, cert_expiry, challenge_token, challenge_key,
    fail_reason, csr_pem, created_at, last_connected_at";

/// Ordered schema migrations. The index + 1 is the `user_version` they produce.
/// Databases created before versioning have user_version 0 and tables that
/// already exist, so version 1 is a no-op for them and version 2 adds columns.
const MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS tunnels (
         id TEXT PRIMARY KEY,
         hostname TEXT NOT NULL UNIQUE,
         token_hash TEXT NOT NULL,
         state TEXT NOT NULL DEFAULT 'offline',
         deleted_at TEXT,
         cert_id TEXT,
         cert_state TEXT NOT NULL DEFAULT 'none',
         cert_pem TEXT,
         chain_pem TEXT,
         cert_expiry TEXT,
         challenge_token TEXT,
         challenge_key TEXT,
         fail_reason TEXT,
         csr_pem TEXT,
         created_at TEXT NOT NULL,
         last_connected_at TEXT
     );
     CREATE TABLE IF NOT EXISTS meta (
         key TEXT PRIMARY KEY,
         value TEXT NOT NULL
     );",
    "ALTER TABLE tunnels ADD COLUMN cert_started_at INTEGER;
     ALTER TABLE tunnels ADD COLUMN renewal_id TEXT;
     ALTER TABLE tunnels ADD COLUMN renewal_started_at INTEGER;
     ALTER TABLE tunnels ADD COLUMN renewal_attempts INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE tunnels ADD COLUMN renewal_next_at INTEGER;
     ALTER TABLE tunnels ADD COLUMN renewal_error TEXT;
     CREATE TABLE IF NOT EXISTS issuances (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         tunnel_id TEXT NOT NULL,
         kind TEXT NOT NULL,
         created_at INTEGER NOT NULL
     );
     CREATE INDEX IF NOT EXISTS issuances_created_at ON issuances (created_at);",
];

pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        // SQLite otherwise creates databases according to the process umask.
        // The database also contains the ACME account key and tunnel metadata.
        secure_database_file(path)?;
        let mut conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        migrate(&mut conn)?;
        // No bridge survives a process restart; do not expose stale online
        // status from the previous process lifetime.
        conn.execute(
            "UPDATE tunnels SET state = 'offline' WHERE state != 'offline'",
            [],
        )?;
        secure_database_file(path)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    async fn run<T, F>(&self, work: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            work(&mut guard)
        })
        .await
        .map_err(|e| Error::Internal(format!("database task failed: {e}")))?
    }

    /// Inserts a tunnel unless the id is taken or `max_tunnels` live tunnels
    /// already exist. The count and insert run under one lock, so concurrent
    /// creations cannot both pass the limit.
    pub async fn create_tunnel(
        &self,
        id: &str,
        hostname: &str,
        token_hash: &str,
        now: &str,
        max_tunnels: u64,
    ) -> Result<CreateOutcome> {
        let (id, hostname, token_hash, now) = (
            id.to_owned(),
            hostname.to_owned(),
            token_hash.to_owned(),
            now.to_owned(),
        );
        self.run(move |conn| {
            if max_tunnels > 0 {
                let live: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM tunnels WHERE deleted_at IS NULL",
                    [],
                    |row| row.get(0),
                )?;
                if u64::try_from(live).unwrap_or(0) >= max_tunnels {
                    return Ok(CreateOutcome::LimitReached);
                }
            }
            let rows = conn.execute(
                "INSERT OR IGNORE INTO tunnels (id, hostname, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![id, hostname, token_hash, now],
            )?;
            Ok(if rows == 1 {
                CreateOutcome::Created
            } else {
                CreateOutcome::IdTaken
            })
        })
        .await
    }

    pub async fn get_tunnel(&self, id: &str) -> Result<Option<TunnelRecord>> {
        let id = id.to_owned();
        self.run(move |conn| load_record(conn, &id)).await
    }

    pub async fn set_online(&self, id: &str, online: bool, now: &str) -> Result<()> {
        let (id, now) = (id.to_owned(), now.to_owned());
        self.run(move |conn| {
            if online {
                conn.execute(
                    "UPDATE tunnels SET state = 'online', last_connected_at = ?1 WHERE id = ?2",
                    params![now, id],
                )?;
            } else {
                conn.execute(
                    "UPDATE tunnels SET state = 'offline' WHERE id = ?1",
                    params![id],
                )?;
            }
            Ok(())
        })
        .await
    }

    /// Starts an initial issuance for `csr_pem`. Refused when the tunnel is
    /// gone, when another issuance is in flight and not stale, or when the
    /// daily order budget is spent. The claim and its ledger entry are written
    /// together, so the budget cannot be overrun by concurrent requests.
    pub async fn claim_issuance(
        &self,
        id: &str,
        cert_id: &str,
        csr_pem: &str,
        now_ms: i64,
        stale_after_ms: i64,
        daily_limit: u64,
    ) -> Result<Claim> {
        let (id, cert_id, csr_pem) = (id.to_owned(), cert_id.to_owned(), csr_pem.to_owned());
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let current: Option<(Option<String>, String, Option<i64>)> = tx
                .query_row(
                    "SELECT deleted_at, cert_state, cert_started_at FROM tunnels WHERE id = ?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((deleted_at, cert_state, started_at)) = current else {
                return Ok(Claim::NotFound);
            };
            if deleted_at.is_some() {
                return Ok(Claim::NotFound);
            }
            let in_flight = matches!(cert_state.as_str(), "challenge" | "issuing");
            let stale = started_at.is_none_or(|started| started < now_ms - stale_after_ms);
            if in_flight && !stale {
                return Ok(Claim::Busy);
            }
            if daily_limit > 0 {
                let window_start = now_ms - ISSUANCE_WINDOW_MS;
                if issuances_since(&tx, window_start)? >= daily_limit {
                    let oldest: Option<i64> = tx.query_row(
                        "SELECT MIN(created_at) FROM issuances WHERE created_at > ?1",
                        params![window_start],
                        |row| row.get(0),
                    )?;
                    let retry_after_ms =
                        oldest.map_or(HOUR_MS, |t| t + ISSUANCE_WINDOW_MS - now_ms);
                    return Ok(Claim::DailyLimit {
                        retry_after_ms: retry_after_ms.max(60_000),
                    });
                }
            }
            tx.execute(
                "UPDATE tunnels SET cert_id = ?1, cert_state = 'issuing', csr_pem = ?2,
                     cert_started_at = ?3, challenge_token = NULL, challenge_key = NULL,
                     fail_reason = NULL, renewal_id = NULL, renewal_started_at = NULL,
                     renewal_next_at = NULL, renewal_attempts = 0, renewal_error = NULL
                 WHERE id = ?4",
                params![cert_id, csr_pem, now_ms, id],
            )?;
            record_issuance(&tx, &id, "order", now_ms)?;
            tx.commit()?;
            Ok(Claim::Claimed)
        })
        .await
    }

    pub async fn set_challenge(&self, cert_id: &str, token: &str, key: &str) -> Result<()> {
        let (cert_id, token, key) = (cert_id.to_owned(), token.to_owned(), key.to_owned());
        self.run(move |conn| {
            conn.execute(
                "UPDATE tunnels SET cert_state = 'challenge', challenge_token = ?1, challenge_key = ?2
                 WHERE cert_id = ?3 AND cert_state IN ('issuing', 'challenge')",
                params![token, key, cert_id],
            )?;
            Ok(())
        })
        .await
    }

    /// Makes the issued certificate the active one. Returns false if the
    /// issuance was superseded or the tunnel was deleted meanwhile.
    pub async fn set_ready(
        &self,
        cert_id: &str,
        cert_pem: &str,
        chain_pem: &str,
        expiry: &str,
    ) -> Result<bool> {
        let (cert_id, cert_pem, chain_pem, expiry) = (
            cert_id.to_owned(),
            cert_pem.to_owned(),
            chain_pem.to_owned(),
            expiry.to_owned(),
        );
        self.run(move |conn| {
            let rows = conn.execute(
                "UPDATE tunnels SET cert_state = 'ready', cert_pem = ?1, chain_pem = ?2,
                     cert_expiry = ?3, fail_reason = NULL, challenge_token = NULL, challenge_key = NULL
                 WHERE cert_id = ?4 AND cert_state IN ('issuing', 'challenge') AND deleted_at IS NULL",
                params![cert_pem, chain_pem, expiry, cert_id],
            )?;
            Ok(rows == 1)
        })
        .await
    }

    pub async fn set_failed(&self, cert_id: &str, reason: &str) -> Result<bool> {
        let (cert_id, reason) = (cert_id.to_owned(), reason.to_owned());
        self.run(move |conn| {
            let rows = conn.execute(
                "UPDATE tunnels SET cert_state = 'failed', fail_reason = ?1, challenge_token = NULL, challenge_key = NULL
                 WHERE cert_id = ?2 AND cert_state IN ('issuing', 'challenge')",
                params![reason, cert_id],
            )?;
            Ok(rows == 1)
        })
        .await
    }

    /// Re-arms issuances that were in flight when the previous process stopped
    /// and drops renewal leases held by it. Returns `(tunnel_id, cert_id)` for
    /// each issuance to resume. The stored CSR makes the resumed order
    /// identical to the interrupted one.
    pub async fn requeue_interrupted(&self, now_ms: i64) -> Result<Vec<(String, String)>> {
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let pending: Vec<(String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT id, cert_id FROM tunnels
                     WHERE deleted_at IS NULL AND cert_state IN ('challenge', 'issuing') AND cert_id IS NOT NULL",
                )?;
                let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (tunnel_id, _) in &pending {
                tx.execute(
                    "UPDATE tunnels SET cert_state = 'issuing', challenge_token = NULL,
                         challenge_key = NULL, cert_started_at = ?1 WHERE id = ?2",
                    params![now_ms, tunnel_id],
                )?;
                record_issuance(&tx, tunnel_id, "requeue", now_ms)?;
            }
            tx.execute(
                "UPDATE tunnels SET renewal_id = NULL, renewal_started_at = NULL WHERE renewal_id IS NOT NULL",
                [],
            )?;
            tx.commit()?;
            Ok(pending)
        })
        .await
    }

    /// Ready tunnels with a stored CSR whose renewal is neither leased nor in
    /// backoff. The caller applies expiry and activity policy.
    pub async fn renewal_candidates(
        &self,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Vec<TunnelRecord>> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {RECORD_COLUMNS} FROM tunnels
                 WHERE deleted_at IS NULL
                   AND cert_state = 'ready'
                   AND csr_pem IS NOT NULL
                   AND cert_expiry IS NOT NULL
                   AND (renewal_id IS NULL OR renewal_started_at IS NULL OR renewal_started_at <= ?1)
                   AND (renewal_next_at IS NULL OR renewal_next_at <= ?2)"
            ))?;
            let rows = stmt.query_map(params![now_ms - lease_ms, now_ms], row_to_record)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Takes the renewal lease for a tunnel. Renewals are never refused by the
    /// daily budget, but they are recorded in it.
    pub async fn claim_renewal(
        &self,
        id: &str,
        renewal_id: &str,
        csr_pem: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<bool> {
        let (id, renewal_id, csr_pem) = (id.to_owned(), renewal_id.to_owned(), csr_pem.to_owned());
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let rows = tx.execute(
                "UPDATE tunnels SET renewal_id = ?1, renewal_started_at = ?2
                 WHERE id = ?3 AND deleted_at IS NULL AND cert_state = 'ready' AND csr_pem = ?4
                   AND (renewal_id IS NULL OR renewal_started_at IS NULL OR renewal_started_at <= ?5)
                   AND (renewal_next_at IS NULL OR renewal_next_at <= ?2)",
                params![renewal_id, now_ms, id, csr_pem, now_ms - lease_ms],
            )?;
            if rows == 1 {
                record_issuance(&tx, &id, "renewal", now_ms)?;
            }
            tx.commit()?;
            Ok(rows == 1)
        })
        .await
    }

    /// Swaps in the renewed certificate. Only the holder of the current lease
    /// for the same CSR may do so; anything else is a superseded attempt.
    pub async fn complete_renewal(
        &self,
        id: &str,
        renewal_id: &str,
        csr_pem: &str,
        cert_pem: &str,
        chain_pem: &str,
        expiry: &str,
    ) -> Result<bool> {
        let (id, renewal_id, csr_pem) = (id.to_owned(), renewal_id.to_owned(), csr_pem.to_owned());
        let (cert_pem, chain_pem, expiry) =
            (cert_pem.to_owned(), chain_pem.to_owned(), expiry.to_owned());
        self.run(move |conn| {
            let rows = conn.execute(
                "UPDATE tunnels SET cert_pem = ?1, chain_pem = ?2, cert_expiry = ?3,
                     renewal_id = NULL, renewal_started_at = NULL, renewal_attempts = 0,
                     renewal_next_at = NULL, renewal_error = NULL
                 WHERE id = ?4 AND renewal_id = ?5 AND csr_pem = ?6 AND cert_state = 'ready' AND deleted_at IS NULL",
                params![cert_pem, chain_pem, expiry, id, renewal_id, csr_pem],
            )?;
            Ok(rows == 1)
        })
        .await
    }

    /// Releases a failed renewal's lease and schedules the next attempt.
    /// Returns the time of that attempt, or `None` if the lease was not held.
    /// The active certificate is untouched.
    pub async fn fail_renewal(
        &self,
        id: &str,
        renewal_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<Option<i64>> {
        let (id, renewal_id, reason) = (id.to_owned(), renewal_id.to_owned(), reason.to_owned());
        self.run(move |conn| {
            let tx = conn.transaction()?;
            let attempts: Option<i64> = tx
                .query_row(
                    "SELECT renewal_attempts FROM tunnels WHERE id = ?1 AND renewal_id = ?2",
                    params![id, renewal_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(attempts) = attempts else {
                return Ok(None);
            };
            let attempts = u32::try_from(attempts.saturating_add(1)).unwrap_or(u32::MAX);
            let next_at = now_ms + renewal_backoff_ms(attempts);
            tx.execute(
                "UPDATE tunnels SET renewal_id = NULL, renewal_started_at = NULL,
                     renewal_attempts = ?1, renewal_next_at = ?2, renewal_error = ?3
                 WHERE id = ?4 AND renewal_id = ?5",
                params![i64::from(attempts), next_at, reason, id, renewal_id],
            )?;
            tx.commit()?;
            Ok(Some(next_at))
        })
        .await
    }

    pub async fn delete_tunnel(&self, id: &str, now: &str) -> Result<bool> {
        let (id, now) = (id.to_owned(), now.to_owned());
        self.run(move |conn| {
            let rows = conn.execute(
                "UPDATE tunnels SET deleted_at = ?1, state = 'offline', renewal_id = NULL, renewal_started_at = NULL
                 WHERE id = ?2 AND deleted_at IS NULL",
                params![now, id],
            )?;
            Ok(rows == 1)
        })
        .await
    }

    pub async fn prune_issuances(&self, before_ms: i64) -> Result<()> {
        self.run(move |conn| {
            conn.execute(
                "DELETE FROM issuances WHERE created_at < ?1",
                params![before_ms],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_owned();
        self.run(move |conn| {
            let value = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(value)
        })
        .await
    }

    /// Returns the stored value for `key`, storing `candidate` first if the
    /// key is absent. Used for the ACME account key, which must be created once
    /// even when several issuances start together.
    pub async fn get_or_insert_meta(&self, key: &str, candidate: String) -> Result<String> {
        let key = key.to_owned();
        self.run(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, candidate],
            )?;
            let value = conn.query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )?;
            Ok(value)
        })
        .await
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let current: usize = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (index, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", index + 1))?;
        tx.commit()?;
    }
    Ok(())
}

fn load_record(conn: &Connection, id: &str) -> Result<Option<TunnelRecord>> {
    let record = conn
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM tunnels WHERE id = ?1"),
            params![id],
            row_to_record,
        )
        .optional()?;
    Ok(record)
}

fn record_issuance(
    conn: &Connection,
    tunnel_id: &str,
    kind: &str,
    now_ms: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO issuances (tunnel_id, kind, created_at) VALUES (?1, ?2, ?3)",
        params![tunnel_id, kind, now_ms],
    )?;
    Ok(())
}

fn issuances_since(conn: &Transaction<'_>, since_ms: i64) -> rusqlite::Result<u64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM issuances WHERE created_at > ?1",
        params![since_ms],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(count).unwrap_or(0))
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<TunnelRecord> {
    let cert_state: String = row.get(6)?;
    Ok(TunnelRecord {
        id: row.get(0)?,
        hostname: row.get(1)?,
        token_hash: row.get(2)?,
        state: row.get(3)?,
        deleted_at: row.get(4)?,
        cert_id: row.get(5)?,
        cert_state: CertState::parse(&cert_state),
        cert_pem: row.get(7)?,
        chain_pem: row.get(8)?,
        cert_expiry: row.get(9)?,
        challenge_token: row.get(10)?,
        challenge_key: row.get(11)?,
        fail_reason: row.get(12)?,
        csr_pem: row.get(13)?,
        created_at: row.get(14)?,
        last_connected_at: row.get(15)?,
    })
}

fn secure_database_file(path: &Path) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(options.open(path)?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn temp_db_path(name: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ot-relay-{name}-{}-{nonce}.sqlite",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const LEASE: i64 = 30 * 60 * 1000;
    const STALE: i64 = 20 * 60 * 1000;

    async fn open_with_tunnel(name: &str, tunnel: &str) -> (Db, std::path::PathBuf) {
        let path = temp_db_path(name);
        let db = Db::open(&path).unwrap();
        assert_eq!(
            db.create_tunnel(tunnel, &format!("{tunnel}.relay.test"), "hash", "now", 0)
                .await
                .unwrap(),
            CreateOutcome::Created
        );
        (db, path)
    }

    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        for suffix in ["-wal", "-shm"] {
            let name = format!("{}{suffix}", path.file_name().unwrap().to_string_lossy());
            let _ = std::fs::remove_file(path.with_file_name(name));
        }
    }

    #[tokio::test]
    async fn issuance_claim_is_atomic_and_database_is_private() {
        let (db, path) = open_with_tunnel("claim", "t1").await;
        assert_eq!(
            db.claim_issuance("t1", "cert1", "csr", NOW, STALE, 0)
                .await
                .unwrap(),
            Claim::Claimed
        );
        assert_eq!(
            db.claim_issuance("t1", "cert2", "csr", NOW, STALE, 0)
                .await
                .unwrap(),
            Claim::Busy
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn stale_issuance_can_be_taken_over() {
        let (db, path) = open_with_tunnel("stale", "t1").await;
        db.claim_issuance("t1", "cert1", "csr", NOW, STALE, 0)
            .await
            .unwrap();
        let later = NOW + STALE + 1;
        assert_eq!(
            db.claim_issuance("t1", "cert2", "csr2", later, STALE, 0)
                .await
                .unwrap(),
            Claim::Claimed
        );
        assert_eq!(
            db.get_tunnel("t1")
                .await
                .unwrap()
                .unwrap()
                .cert_id
                .as_deref(),
            Some("cert2")
        );
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn daily_budget_refuses_new_orders_but_renewals_still_run() {
        let (db, path) = open_with_tunnel("budget", "t1").await;
        assert_eq!(
            db.create_tunnel("t2", "t2.relay.test", "hash", "now", 0)
                .await
                .unwrap(),
            CreateOutcome::Created
        );
        assert_eq!(
            db.claim_issuance("t1", "cert1", "csr1", NOW, STALE, 1)
                .await
                .unwrap(),
            Claim::Claimed
        );
        assert!(matches!(
            db.claim_issuance("t2", "cert2", "csr2", NOW, STALE, 1).await.unwrap(),
            Claim::DailyLimit { retry_after_ms } if retry_after_ms == ISSUANCE_WINDOW_MS
        ));
        db.set_ready("cert1", "PEM", "CHAIN", "2099-01-01T00:00:00Z")
            .await
            .unwrap();
        assert!(db
            .claim_renewal("t1", "renew1", "csr1", NOW, LEASE)
            .await
            .unwrap());
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn renewal_lease_blocks_second_claim_until_it_expires() {
        let (db, path) = open_with_tunnel("lease", "t1").await;
        db.claim_issuance("t1", "cert1", "csr1", NOW, STALE, 0)
            .await
            .unwrap();
        db.set_ready("cert1", "PEM", "CHAIN", "2099-01-01T00:00:00Z")
            .await
            .unwrap();

        assert!(db
            .claim_renewal("t1", "renew1", "csr1", NOW, LEASE)
            .await
            .unwrap());
        assert!(!db
            .claim_renewal("t1", "renew2", "csr1", NOW + 1, LEASE)
            .await
            .unwrap());
        assert!(db
            .claim_renewal("t1", "renew2", "csr1", NOW + LEASE + 1, LEASE)
            .await
            .unwrap());
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn failed_renewal_keeps_active_certificate_and_backs_off() {
        let (db, path) = open_with_tunnel("backoff", "t1").await;
        db.claim_issuance("t1", "cert1", "csr1", NOW, STALE, 0)
            .await
            .unwrap();
        db.set_ready("cert1", "ACTIVE", "CHAIN", "2099-01-01T00:00:00Z")
            .await
            .unwrap();
        db.claim_renewal("t1", "renew1", "csr1", NOW, LEASE)
            .await
            .unwrap();

        let next = db
            .fail_renewal("t1", "renew1", "acme down", NOW + 5)
            .await
            .unwrap()
            .expect("lease was held");
        assert_eq!(next, NOW + 5 + HOUR_MS);

        let record = db.get_tunnel("t1").await.unwrap().unwrap();
        assert_eq!(record.cert_state, CertState::Ready);
        assert_eq!(record.cert_pem.as_deref(), Some("ACTIVE"));

        assert!(db
            .renewal_candidates(NOW + 6, LEASE)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(db.renewal_candidates(next, LEASE).await.unwrap().len(), 1);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn superseded_renewal_cannot_overwrite_certificate() {
        let (db, path) = open_with_tunnel("supersede", "t1").await;
        db.claim_issuance("t1", "cert1", "csr1", NOW, STALE, 0)
            .await
            .unwrap();
        db.set_ready("cert1", "ACTIVE", "CHAIN", "2099-01-01T00:00:00Z")
            .await
            .unwrap();
        db.claim_renewal("t1", "renew1", "csr1", NOW, LEASE)
            .await
            .unwrap();

        assert!(!db
            .complete_renewal("t1", "stale", "csr1", "OLD", "", "2100-01-01T00:00:00Z")
            .await
            .unwrap());
        assert!(db
            .complete_renewal(
                "t1",
                "renew1",
                "csr1",
                "NEW",
                "CHAIN",
                "2100-01-01T00:00:00Z"
            )
            .await
            .unwrap());
        let record = db.get_tunnel("t1").await.unwrap().unwrap();
        assert_eq!(record.cert_pem.as_deref(), Some("NEW"));
        assert_eq!(record.cert_expiry.as_deref(), Some("2100-01-01T00:00:00Z"));
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn requeue_resumes_interrupted_issuance_and_drops_leases() {
        let (db, path) = open_with_tunnel("requeue", "t1").await;
        db.claim_issuance("t1", "cert1", "csr1", NOW, STALE, 0)
            .await
            .unwrap();
        let resumed = db.requeue_interrupted(NOW + 1).await.unwrap();
        assert_eq!(resumed, vec![("t1".to_string(), "cert1".to_string())]);
        assert_eq!(
            db.get_tunnel("t1").await.unwrap().unwrap().cert_state,
            CertState::Issuing
        );
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn tunnel_cap_is_enforced_by_the_insert() {
        let path = temp_db_path("cap");
        let db = Db::open(&path).unwrap();
        assert_eq!(
            db.create_tunnel("a", "a.relay.test", "h", "now", 1)
                .await
                .unwrap(),
            CreateOutcome::Created
        );
        assert_eq!(
            db.create_tunnel("b", "b.relay.test", "h", "now", 1)
                .await
                .unwrap(),
            CreateOutcome::LimitReached
        );
        drop(db);
        cleanup(&path);
    }

    #[test]
    fn renewal_backoff_doubles_and_caps_at_twelve_hours() {
        assert_eq!(renewal_backoff_ms(1), HOUR_MS);
        assert_eq!(renewal_backoff_ms(2), 2 * HOUR_MS);
        assert_eq!(renewal_backoff_ms(4), 8 * HOUR_MS);
        assert_eq!(renewal_backoff_ms(5), 12 * HOUR_MS);
        assert_eq!(renewal_backoff_ms(500), 12 * HOUR_MS);
    }

    #[tokio::test]
    async fn database_created_before_versioning_is_migrated() {
        let path = temp_db_path("legacy");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE tunnels (
                     id TEXT PRIMARY KEY, hostname TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL,
                     state TEXT NOT NULL DEFAULT 'offline', deleted_at TEXT, cert_id TEXT,
                     cert_state TEXT NOT NULL DEFAULT 'none', cert_pem TEXT, chain_pem TEXT,
                     cert_expiry TEXT, challenge_token TEXT, challenge_key TEXT, fail_reason TEXT,
                     csr_pem TEXT, created_at TEXT NOT NULL, last_connected_at TEXT
                 );
                 INSERT INTO tunnels (id, hostname, token_hash, created_at)
                     VALUES ('old', 'old.relay.test', 'h', 'then');",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(
            db.get_tunnel("old").await.unwrap().unwrap().hostname,
            "old.relay.test"
        );
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn reopening_clears_online_state_left_by_a_previous_process() {
        let (db, path) = open_with_tunnel("reopen", "t1").await;
        db.set_online("t1", true, "now").await.unwrap();
        assert_eq!(db.get_tunnel("t1").await.unwrap().unwrap().state, "online");
        drop(db);

        let reopened = Db::open(&path).unwrap();
        assert_eq!(
            reopened.get_tunnel("t1").await.unwrap().unwrap().state,
            "offline"
        );
        drop(reopened);
        cleanup(&path);
    }
}
