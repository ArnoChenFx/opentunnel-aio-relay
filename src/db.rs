//! SQLite persistence. Replaces the Durable Object storage of the
//! Cloudflare deployment: one row per tunnel holds the metadata the DO kept
//! in `ctx.storage` (identity, token hash, certificate state, CSR).

use rusqlite::{params, Connection, OptionalExtension};
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};

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
    pub cert_retry_count: u32,
    pub cert_retry_after: Option<i64>,
    pub csr_pem: Option<String>,
    pub created_at: String,
    pub last_connected_at: Option<String>,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Runs a synchronous SQLite operation on Tokio's blocking pool.
    pub async fn call<T, F>(db: Arc<Self>, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Db) -> Result<T> + Send + 'static,
    {
        tokio::task::spawn_blocking(move || operation(&db))
            .await
            .map_err(|error| Error::Internal(format!("database worker failed: {error}")))?
    }

    pub fn open(path: &Path) -> Result<Self> {
        // SQLite otherwise creates databases according to the process umask.
        // The database also contains the ACME account key and tunnel metadata.
        secure_database_file(path)?;
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS tunnels (
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
                 cert_retry_count INTEGER NOT NULL DEFAULT 0,
                 cert_retry_after INTEGER,
                 csr_pem TEXT,
                 created_at TEXT NOT NULL,
                 last_connected_at TEXT
             );
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );",
        )?;
        ensure_column(
            &conn,
            "cert_retry_count",
            "cert_retry_count INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(&conn, "cert_retry_after", "cert_retry_after INTEGER")?;
        // No bridge survives a process restart; do not expose stale online
        // status from the previous process lifetime.
        conn.execute(
            "UPDATE tunnels SET state = 'offline' WHERE state != 'offline'",
            [],
        )?;
        // Challenge work is process-local; requeue it from the persisted CSR.
        conn.execute(
            "UPDATE tunnels SET cert_state = 'issuing', challenge_token = NULL,
                 challenge_key = NULL WHERE cert_state = 'challenge'",
            [],
        )?;
        secure_database_file(path)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|e| Error::Internal(e.to_string()))
    }

    pub fn create_tunnel(
        &self,
        id: &str,
        hostname: &str,
        token_hash: &str,
        now: &str,
    ) -> Result<bool> {
        let conn = self.lock()?;
        let rows = conn.execute(
            "INSERT OR IGNORE INTO tunnels (id, hostname, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, hostname, token_hash, now],
        )?;
        Ok(rows == 1)
    }

    pub fn get_tunnel(&self, id: &str) -> Result<Option<TunnelRecord>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, hostname, token_hash, state, deleted_at, cert_id, cert_state,
                    cert_pem, chain_pem, cert_expiry, challenge_token, challenge_key,
                    fail_reason, cert_retry_count, cert_retry_after, csr_pem, created_at, last_connected_at
             FROM tunnels WHERE id = ?1",
            params![id],
            row_to_record,
        )
        .optional()
        .map_err(Error::from)
    }

    pub fn set_online(&self, id: &str, online: bool, now: &str) -> Result<()> {
        let conn = self.lock()?;
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
    }

    pub fn touch_connected(&self, id: &str, now: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE tunnels SET last_connected_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    /// Starts (or restarts) issuance for the given CSR. Returns the cert id.
    pub fn begin_issuance(&self, id: &str, cert_id: &str, csr_pem: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE tunnels SET cert_id = ?1, cert_state = 'issuing', csr_pem = ?2,
                 challenge_token = NULL, challenge_key = NULL, fail_reason = NULL,
                 cert_retry_count = CASE WHEN csr_pem IS NOT ?2 THEN 0 ELSE cert_retry_count END,
                 cert_retry_after = CASE WHEN csr_pem IS NOT ?2 THEN NULL ELSE cert_retry_after END
             WHERE id = ?3",
            params![cert_id, csr_pem, id],
        )?;
        Ok(())
    }

    /// Atomically claims a certificate issuance unless one is already active.
    /// Returns `false` if the tunnel was deleted, missing, or another request
    /// already moved it into the challenge/issuing state.
    pub fn try_begin_issuance(&self, id: &str, cert_id: &str, csr_pem: &str) -> Result<bool> {
        let conn = self.lock()?;
        let rows = conn.execute(
            "UPDATE tunnels SET cert_id = ?1, cert_state = 'issuing', csr_pem = ?2,
                 challenge_token = NULL, challenge_key = NULL, fail_reason = NULL,
                 cert_retry_count = CASE WHEN csr_pem IS NOT ?2 THEN 0 ELSE cert_retry_count END,
                 cert_retry_after = CASE WHEN csr_pem IS NOT ?2 THEN NULL ELSE cert_retry_after END
             WHERE id = ?3 AND deleted_at IS NULL
               AND cert_state NOT IN ('challenge', 'issuing')
               AND (csr_pem IS NOT ?2 OR cert_retry_after IS NULL OR cert_retry_after <= unixepoch())",
            params![cert_id, csr_pem, id],
        )?;
        Ok(rows == 1)
    }

    pub fn set_challenge(&self, cert_id: &str, token: &str, key: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE tunnels SET cert_state = 'challenge', challenge_token = ?1, challenge_key = ?2
             WHERE cert_id = ?3",
            params![token, key, cert_id],
        )?;
        Ok(())
    }

    pub fn set_ready(
        &self,
        cert_id: &str,
        cert_pem: &str,
        chain_pem: &str,
        expiry: &str,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE tunnels SET cert_state = 'ready', cert_pem = ?1, chain_pem = ?2,
                 cert_expiry = ?3, fail_reason = NULL, cert_retry_count = 0,
                 cert_retry_after = NULL WHERE cert_id = ?4",
            params![cert_pem, chain_pem, expiry, cert_id],
        )?;
        Ok(())
    }

    pub fn set_failed(&self, cert_id: &str, reason: &str) -> Result<()> {
        let conn = self.lock()?;
        let previous_count: Option<i64> = conn
            .query_row(
                "SELECT cert_retry_count FROM tunnels WHERE cert_id = ?1",
                params![cert_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(previous_count) = previous_count else {
            return Ok(());
        };
        let retry_count = previous_count.saturating_add(1).max(1);
        let exponent = (retry_count - 1).min(11) as u32;
        let backoff_secs = (60_i64 * (1_i64 << exponent)).min(24 * 60 * 60);
        let retry_after = chrono::Utc::now().timestamp().saturating_add(backoff_secs);
        conn.execute(
            "UPDATE tunnels SET cert_state = 'failed', fail_reason = ?1,
                 cert_retry_count = ?2, cert_retry_after = ?3 WHERE cert_id = ?4",
            params![reason, retry_count, retry_after, cert_id],
        )?;
        Ok(())
    }

    pub fn get_by_cert_id(&self, cert_id: &str) -> Result<Option<TunnelRecord>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, hostname, token_hash, state, deleted_at, cert_id, cert_state,
                    cert_pem, chain_pem, cert_expiry, challenge_token, challenge_key,
                    fail_reason, cert_retry_count, cert_retry_after, csr_pem, created_at, last_connected_at
             FROM tunnels WHERE cert_id = ?1",
            params![cert_id],
            row_to_record,
        )
        .optional()
        .map_err(Error::from)
    }

    /// Returns non-deleted certificate requests that were active at shutdown.
    pub fn pending_issuances(&self) -> Result<Vec<TunnelRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, hostname, token_hash, state, deleted_at, cert_id, cert_state,
                    cert_pem, chain_pem, cert_expiry, challenge_token, challenge_key,
                    fail_reason, cert_retry_count, cert_retry_after, csr_pem, created_at, last_connected_at
             FROM tunnels
             WHERE deleted_at IS NULL AND cert_state IN ('challenge', 'issuing')
               AND cert_id IS NOT NULL AND csr_pem IS NOT NULL",
        )?;
        let rows = stmt.query_map([], row_to_record)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::from)
    }

    /// Tunnels whose certificate expires within `within_secs` and that were
    /// connected in the last `active_within_secs` (or are online now).
    pub fn renewal_candidates(
        &self,
        within_secs: i64,
        active_within_secs: i64,
        now_secs: i64,
    ) -> Result<Vec<TunnelRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, hostname, token_hash, state, deleted_at, cert_id, cert_state,
                    cert_pem, chain_pem, cert_expiry, challenge_token, challenge_key,
                    fail_reason, cert_retry_count, cert_retry_after, csr_pem, created_at, last_connected_at
             FROM tunnels
             WHERE deleted_at IS NULL
               AND cert_state IN ('ready', 'failed')
               AND cert_pem IS NOT NULL
               AND cert_expiry IS NOT NULL
               AND csr_pem IS NOT NULL
               AND (cert_retry_after IS NULL OR cert_retry_after <= ?1)",
        )?;
        let rows = stmt.query_map(params![now_secs], row_to_record)?;
        let mut out = Vec::new();
        for row in rows {
            let record = row?;
            let expiry_secs = record
                .cert_expiry
                .as_deref()
                .and_then(parse_rfc3339_secs)
                .unwrap_or(i64::MAX);
            if expiry_secs - now_secs > within_secs {
                continue;
            }
            let active = record.state == "online"
                || record
                    .last_connected_at
                    .as_deref()
                    .and_then(parse_rfc3339_secs)
                    .map(|t| now_secs - t < active_within_secs)
                    .unwrap_or(false);
            if active {
                out.push(record);
            }
        }
        Ok(out)
    }

    pub fn delete_tunnel(&self, id: &str, now: &str) -> Result<bool> {
        let conn = self.lock()?;
        let rows = conn.execute(
            "UPDATE tunnels SET deleted_at = ?1, state = 'offline' WHERE id = ?2 AND deleted_at IS NULL",
            params![now, id],
        )?;
        Ok(rows == 1)
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(Error::from)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

fn ensure_column(conn: &Connection, name: &str, declaration: &str) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(tunnels)")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|column| column == name) {
        conn.execute_batch(&format!("ALTER TABLE tunnels ADD COLUMN {declaration}"))?;
    }
    Ok(())
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
        cert_retry_count: row.get::<_, i64>(13)?.max(0) as u32,
        cert_retry_after: row.get(14)?,
        csr_pem: row.get(15)?,
        created_at: row.get(16)?,
        last_connected_at: row.get(17)?,
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

fn parse_rfc3339_secs(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ot-relay-db-{}-{nonce}.sqlite", std::process::id()))
    }

    #[test]
    fn issuance_claim_is_atomic_and_database_is_private() {
        let path = test_path();
        let db = Db::open(&path).unwrap();
        assert!(db
            .create_tunnel("t1", "t1.example.test", "hash", "now")
            .unwrap());
        assert!(db.try_begin_issuance("t1", "cert1", "csr").unwrap());
        assert!(!db.try_begin_issuance("t1", "cert2", "csr").unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_file_name(format!(
            "{}-wal",
            path.file_name().unwrap().to_string_lossy()
        )));
        let _ = std::fs::remove_file(path.with_file_name(format!(
            "{}-shm",
            path.file_name().unwrap().to_string_lossy()
        )));
    }

    #[test]
    fn failed_renewal_is_scanned_and_stale_online_state_is_cleared_on_reopen() {
        let path = test_path();
        let db = Db::open(&path).unwrap();
        let now = chrono::Utc::now();
        let now_text = now.to_rfc3339();
        let expiry = (now + chrono::Duration::days(10)).to_rfc3339();
        db.create_tunnel("t1", "t1.example.test", "hash", &now_text)
            .unwrap();
        db.begin_issuance("t1", "cert1", "same-csr").unwrap();
        db.set_ready("cert1", "CERT", "CHAIN", &expiry).unwrap();
        db.set_online("t1", true, &now_text).unwrap();
        db.set_failed("cert1", "temporary CA outage").unwrap();

        let failed = db.get_tunnel("t1").unwrap().unwrap();
        assert_eq!(failed.cert_retry_count, 1);
        assert!(failed.cert_retry_after.unwrap() > now.timestamp());
        assert!(!db.try_begin_issuance("t1", "cert2", "same-csr").unwrap());
        assert!(db
            .renewal_candidates(30 * 24 * 3600, 90 * 24 * 3600, now.timestamp())
            .unwrap()
            .is_empty());

        // Simulate the backoff expiring, then verify renewal scanning resumes.
        db.lock()
            .unwrap()
            .execute(
                "UPDATE tunnels SET cert_retry_after = ?1 WHERE id = 't1'",
                params![now.timestamp() - 1],
            )
            .unwrap();
        let candidates = db
            .renewal_candidates(30 * 24 * 3600, 90 * 24 * 3600, now.timestamp())
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].cert_state, CertState::Failed);
        assert!(db.try_begin_issuance("t1", "cert2", "new-csr").unwrap());
        drop(db);

        let reopened = Db::open(&path).unwrap();
        assert_eq!(reopened.get_tunnel("t1").unwrap().unwrap().state, "offline");

        drop(reopened);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_file_name(format!(
            "{}-wal",
            path.file_name().unwrap().to_string_lossy()
        )));
        let _ = std::fs::remove_file(path.with_file_name(format!(
            "{}-shm",
            path.file_name().unwrap().to_string_lossy()
        )));
    }

    #[test]
    fn interrupted_challenge_is_requeued_after_restart() {
        let path = test_path();
        let db = Db::open(&path).unwrap();
        db.create_tunnel("t1", "t1.example.test", "hash", "now")
            .unwrap();
        db.begin_issuance("t1", "cert1", "stored-csr").unwrap();
        db.set_challenge("cert1", "old-token", "old-key").unwrap();
        drop(db);

        let reopened = Db::open(&path).unwrap();
        let pending = reopened.pending_issuances().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].cert_state, CertState::Issuing);
        assert_eq!(pending[0].cert_id.as_deref(), Some("cert1"));
        assert_eq!(pending[0].csr_pem.as_deref(), Some("stored-csr"));
        assert!(pending[0].challenge_token.is_none());
        drop(reopened);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_file_name(format!(
            "{}-wal",
            path.file_name().unwrap().to_string_lossy()
        )));
        let _ = std::fs::remove_file(path.with_file_name(format!(
            "{}-shm",
            path.file_name().unwrap().to_string_lossy()
        )));
    }
}
