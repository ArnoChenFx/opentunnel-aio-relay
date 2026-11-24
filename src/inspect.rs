//! Read-only operator views over the relay database, behind the `status`,
//! `tunnels`, `tunnel <id>` and `issuances` subcommands.
//!
//! The serving relay is the only writer. These views read the rows it keeps
//! and change nothing, so they run safely beside a live relay. Live bridge
//! connections exist only in memory and are not reported here. A tunnel counts
//! as online only while the relay's heartbeat is fresh, because a stopped relay
//! leaves its last recorded states behind.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::acme::{expires_within, RENEW_BEFORE_SECS};
use crate::config::{Command, Config};
use crate::db::{
    self, CertState, HEARTBEAT_STALE_MS, ISSUANCE_WINDOW_MS, META_HEARTBEAT_AT, META_STARTED_AT,
};
use crate::state::now_millis;

/// Recent certificate activity shown for one tunnel.
const ACTIVITY_LIMIT: i64 = 20;

/// Limits shown next to the counts they cap. Zero means unlimited, as it does
/// for the environment variables these come from.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_tunnels: u64,
    pub max_certs_per_day: u64,
}

impl From<&Config> for Limits {
    fn from(config: &Config) -> Self {
        Self {
            max_tunnels: config.max_tunnels,
            max_certs_per_day: config.max_certs_per_day,
        }
    }
}

pub fn run(command: Command, config: &Config) -> Result<()> {
    let path = config.data_dir.join(db::DATABASE_FILE);
    if !path.is_file() {
        bail!(
            "no relay database at {}; set --data-dir or OT_DATA_DIR to the relay's data directory",
            path.display()
        );
    }
    let mut conn =
        db::open_read_only(&path).with_context(|| format!("cannot open {}", path.display()))?;
    check_schema(&conn, &path)?;
    let tx = conn.transaction()?;
    let now = now_millis();
    let limits = Limits::from(config);

    match command {
        Command::Status { json } => {
            let status = status_view(&tx, &path.display().to_string(), limits, now)?;
            emit(json, &status, || render_status(&status))
        }
        Command::Tunnels { all, json } => {
            let relay = relay_state(&tx, now)?;
            let rows = tunnel_rows(&tx, relay.state == RelayState::Running, all)?;
            emit(json, &rows, || render_tunnels(relay.state, &rows))
        }
        Command::Tunnel { id, json } => {
            let relay = relay_state(&tx, now)?;
            let detail = tunnel_detail(&tx, &id, relay.state == RelayState::Running)?
                .with_context(|| format!("no tunnel with id {id}"))?;
            emit(json, &detail, || render_tunnel(relay.state, &detail))
        }
        Command::Issuances { limit, json } => {
            let rows = issuance_rows(&tx, limit)?;
            emit(json, &rows, || render_issuances(&rows))
        }
    }
}

fn check_schema(conn: &Connection, path: &Path) -> Result<()> {
    let found =
        db::schema_version(conn).with_context(|| format!("cannot read {}", path.display()))?;
    let expected = db::SCHEMA_VERSION;
    if found == expected {
        Ok(())
    } else if found == 0 {
        bail!(
            "{} has no relay schema yet; start the relay once to create it",
            path.display()
        )
    } else if found < expected {
        bail!(
            "{} is at schema v{found}, but this build expects v{expected}; start the relay once to migrate it",
            path.display()
        )
    } else {
        bail!(
            "{} is at schema v{found}, newer than this build (v{expected}); use a newer opentunnel-relay",
            path.display()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayState {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Relay {
    pub state: RelayState,
    pub started_at: Option<String>,
    pub heartbeat_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub database: String,
    pub schema_version: usize,
    pub relay: Relay,
    pub tunnels: TunnelCounts,
    pub certificates: CertificateCounts,
    pub budget: Budget,
}

#[derive(Debug, Serialize)]
pub struct TunnelCounts {
    pub live: u64,
    pub online: u64,
    pub offline: u64,
    pub deleted: u64,
    pub limit: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct CertificateCounts {
    pub none: u64,
    pub challenge: u64,
    pub issuing: u64,
    pub ready: u64,
    pub failed: u64,
    pub expiring_soon: u64,
    pub renewals_failing: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Budget {
    pub limit: u64,
    pub used: u64,
    pub orders: u64,
    pub renewals: u64,
    pub requeues: u64,
    pub next_order_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TunnelRow {
    pub id: String,
    pub hostname: String,
    pub state: &'static str,
    pub certificate_state: &'static str,
    pub certificate_expires_at: Option<String>,
    pub last_connected_at: Option<String>,
    pub created_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TunnelDetail {
    pub id: String,
    pub hostname: String,
    pub state: &'static str,
    pub created_at: String,
    pub last_connected_at: Option<String>,
    pub deleted_at: Option<String>,
    pub certificate: CertificateDetail,
    pub renewal: RenewalDetail,
    pub recent_activity: Vec<Activity>,
}

#[derive(Debug, Serialize)]
pub struct CertificateDetail {
    pub id: Option<String>,
    pub state: &'static str,
    pub expires_at: Option<String>,
    pub order_started_at: Option<String>,
    pub failure: Option<String>,
    pub renewable: bool,
}

#[derive(Debug, Serialize)]
pub struct RenewalDetail {
    pub failed_attempts: u32,
    pub next_attempt_at: Option<String>,
    pub running_since: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Activity {
    pub at: String,
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct IssuanceRow {
    pub at: String,
    pub kind: String,
    pub tunnel_id: String,
    pub hostname: Option<String>,
}

fn status_view(conn: &Connection, database: &str, limits: Limits, now: i64) -> Result<Status> {
    let relay = relay_state(conn, now)?;
    let running = relay.state == RelayState::Running;

    let (live, recorded_online, deleted): (i64, i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(deleted_at IS NULL), 0),
                COALESCE(SUM(deleted_at IS NULL AND state = 'online'), 0),
                COALESCE(SUM(deleted_at IS NOT NULL), 0)
         FROM tunnels",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let live = count(live);
    let online = if running { count(recorded_online) } else { 0 };
    let tunnels = TunnelCounts {
        live,
        online,
        offline: live.saturating_sub(online),
        deleted: count(deleted),
        limit: limits.max_tunnels,
    };

    let mut certificates = CertificateCounts::default();
    let mut stmt = conn.prepare(
        "SELECT cert_state, COUNT(*) FROM tunnels WHERE deleted_at IS NULL GROUP BY cert_state",
    )?;
    let by_state = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (state, n) in by_state {
        let n = count(n);
        match CertState::parse(&state) {
            CertState::None => certificates.none += n,
            CertState::Challenge => certificates.challenge += n,
            CertState::Issuing => certificates.issuing += n,
            CertState::Ready => certificates.ready += n,
            CertState::Failed => certificates.failed += n,
        }
    }
    let mut stmt = conn.prepare(
        "SELECT cert_expiry FROM tunnels
         WHERE deleted_at IS NULL AND cert_state = 'ready' AND cert_expiry IS NOT NULL",
    )?;
    let expiries = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let now_secs = now / 1000;
    certificates.expiring_soon = count_u64(
        expiries
            .iter()
            .filter(|expiry| expires_within(Some(expiry.as_str()), now_secs, RENEW_BEFORE_SECS))
            .count(),
    );
    certificates.renewals_failing = count(conn.query_row(
        "SELECT COUNT(*) FROM tunnels WHERE deleted_at IS NULL AND renewal_error IS NOT NULL",
        [],
        |row| row.get(0),
    )?);

    let window_start = now - ISSUANCE_WINDOW_MS;
    let mut budget = Budget {
        limit: limits.max_certs_per_day,
        used: count(conn.query_row(
            "SELECT COUNT(*) FROM issuances WHERE created_at > ?1",
            params![window_start],
            |row| row.get(0),
        )?),
        ..Budget::default()
    };
    let mut stmt =
        conn.prepare("SELECT kind, COUNT(*) FROM issuances WHERE created_at > ?1 GROUP BY kind")?;
    let by_kind = stmt
        .query_map(params![window_start], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (kind, n) in by_kind {
        match kind.as_str() {
            "order" => budget.orders += count(n),
            "renewal" => budget.renewals += count(n),
            "requeue" => budget.requeues += count(n),
            _ => {}
        }
    }
    if budget.limit > 0 && budget.used >= budget.limit {
        // A new order is accepted once the count drops below the limit. Entries
        // leave the window oldest first, so that takes `used - limit + 1` of them.
        let skip = i64::try_from(budget.used - budget.limit).unwrap_or(i64::MAX);
        let freeing: Option<i64> = conn
            .query_row(
                "SELECT created_at FROM issuances WHERE created_at > ?1
                 ORDER BY created_at LIMIT 1 OFFSET ?2",
                params![window_start, skip],
                |row| row.get(0),
            )
            .optional()?;
        budget.next_order_at = freeing.map(|created| millis_time(created + ISSUANCE_WINDOW_MS));
    }

    Ok(Status {
        database: database.to_string(),
        schema_version: db::SCHEMA_VERSION,
        relay,
        tunnels,
        certificates,
        budget,
    })
}

fn relay_state(conn: &Connection, now: i64) -> Result<Relay> {
    let started_at = meta(conn, META_STARTED_AT)?;
    let heartbeat_at = meta(conn, META_HEARTBEAT_AT)?;
    let state = match heartbeat_at.as_deref().and_then(parse_millis) {
        None => RelayState::Unknown,
        Some(beat) if now - beat <= HEARTBEAT_STALE_MS => RelayState::Running,
        Some(_) => RelayState::Stopped,
    };
    Ok(Relay {
        state,
        started_at: started_at.as_deref().map(display_time),
        heartbeat_at: heartbeat_at.as_deref().map(display_time),
    })
}

fn meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?)
}

fn tunnel_state(deleted: bool, recorded_online: bool, relay_running: bool) -> &'static str {
    if deleted {
        "deleted"
    } else if recorded_online && relay_running {
        "online"
    } else {
        "offline"
    }
}

fn tunnel_rows(
    conn: &Connection,
    relay_running: bool,
    include_deleted: bool,
) -> Result<Vec<TunnelRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, hostname, state, deleted_at, cert_state, cert_expiry, last_connected_at, created_at
         FROM tunnels
         WHERE ?1 OR deleted_at IS NULL
         ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map(params![include_deleted], |row| {
        let recorded: String = row.get(2)?;
        let deleted_at: Option<String> = row.get(3)?;
        Ok(TunnelRow {
            id: row.get(0)?,
            hostname: row.get(1)?,
            state: tunnel_state(deleted_at.is_some(), recorded == "online", relay_running),
            certificate_state: CertState::parse(&row.get::<_, String>(4)?).as_str(),
            certificate_expires_at: row
                .get::<_, Option<String>>(5)?
                .as_deref()
                .map(display_time),
            last_connected_at: row
                .get::<_, Option<String>>(6)?
                .as_deref()
                .map(display_time),
            created_at: display_time(&row.get::<_, String>(7)?),
            deleted_at: deleted_at.as_deref().map(display_time),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn tunnel_detail(conn: &Connection, id: &str, relay_running: bool) -> Result<Option<TunnelDetail>> {
    let detail = conn
        .query_row(
            "SELECT id, hostname, state, deleted_at, cert_id, cert_state, cert_expiry, cert_started_at,
                    fail_reason, csr_pem IS NOT NULL, created_at, last_connected_at,
                    renewal_started_at, renewal_attempts, renewal_next_at, renewal_error
             FROM tunnels WHERE id = ?1",
            params![id],
            |row| {
                let recorded: String = row.get(2)?;
                let deleted_at: Option<String> = row.get(3)?;
                let cert_state = CertState::parse(&row.get::<_, String>(5)?);
                let in_flight = matches!(cert_state, CertState::Challenge | CertState::Issuing);
                let order_started_at: Option<i64> = row.get(7)?;
                let attempts: i64 = row.get(13)?;
                Ok(TunnelDetail {
                    id: row.get(0)?,
                    hostname: row.get(1)?,
                    state: tunnel_state(deleted_at.is_some(), recorded == "online", relay_running),
                    created_at: display_time(&row.get::<_, String>(10)?),
                    last_connected_at: row
                        .get::<_, Option<String>>(11)?
                        .as_deref()
                        .map(display_time),
                    deleted_at: deleted_at.as_deref().map(display_time),
                    certificate: CertificateDetail {
                        id: row.get(4)?,
                        state: cert_state.as_str(),
                        expires_at: row
                            .get::<_, Option<String>>(6)?
                            .as_deref()
                            .map(display_time),
                        order_started_at: if in_flight {
                            order_started_at.map(millis_time)
                        } else {
                            None
                        },
                        failure: row.get(8)?,
                        renewable: row.get(9)?,
                    },
                    renewal: RenewalDetail {
                        failed_attempts: u32::try_from(attempts).unwrap_or(0),
                        next_attempt_at: row.get::<_, Option<i64>>(14)?.map(millis_time),
                        running_since: row.get::<_, Option<i64>>(12)?.map(millis_time),
                        last_error: row.get(15)?,
                    },
                    recent_activity: Vec::new(),
                })
            },
        )
        .optional()?;
    let Some(mut detail) = detail else {
        return Ok(None);
    };
    detail.recent_activity = recent_activity(conn, id)?;
    Ok(Some(detail))
}

fn recent_activity(conn: &Connection, tunnel_id: &str) -> Result<Vec<Activity>> {
    let mut stmt = conn.prepare(
        "SELECT created_at, kind FROM issuances WHERE tunnel_id = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![tunnel_id, ACTIVITY_LIMIT], |row| {
        Ok(Activity {
            at: millis_time(row.get(0)?),
            kind: row.get(1)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn issuance_rows(conn: &Connection, limit: usize) -> Result<Vec<IssuanceRow>> {
    let mut stmt = conn.prepare(
        "SELECT i.created_at, i.kind, i.tunnel_id, t.hostname
         FROM issuances i LEFT JOIN tunnels t ON t.id = i.tunnel_id
         ORDER BY i.id DESC
         LIMIT ?1",
    )?;
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows = stmt.query_map(params![limit], |row| {
        Ok(IssuanceRow {
            at: millis_time(row.get(0)?),
            kind: row.get(1)?,
            tunnel_id: row.get(2)?,
            hostname: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn emit<T: Serialize>(json: bool, value: &T, text: impl FnOnce() -> String) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        print!("{}", text());
    }
    Ok(())
}

fn render_status(status: &Status) -> String {
    let mut out = String::new();
    field(&mut out, "Relay", &relay_text(&status.relay));
    field(
        &mut out,
        "Database",
        &format!("{} (schema v{})", status.database, status.schema_version),
    );
    field(&mut out, "Tunnels", &tunnels_text(&status.tunnels));
    field(
        &mut out,
        "Certificates",
        &format!(
            "ready {}, failed {}, none {}, issuing {}, challenge {}",
            status.certificates.ready,
            status.certificates.failed,
            status.certificates.none,
            status.certificates.issuing,
            status.certificates.challenge,
        ),
    );
    field(
        &mut out,
        "Expiring",
        &format!(
            "{} within {} days",
            status.certificates.expiring_soon,
            RENEW_BEFORE_SECS / 86_400
        ),
    );
    field(
        &mut out,
        "Renewals",
        &format!("{} failing", status.certificates.renewals_failing),
    );
    field(&mut out, "Budget", &budget_text(&status.budget));
    let next = match &status.budget.next_order_at {
        Some(time) => format!("after {time}"),
        None => "accepted now".to_string(),
    };
    field(&mut out, "Next order", &next);
    out
}

fn relay_text(relay: &Relay) -> String {
    match relay.state {
        RelayState::Running => format!(
            "running (started {}, heartbeat {})",
            or_dash(relay.started_at.as_deref()),
            or_dash(relay.heartbeat_at.as_deref())
        ),
        RelayState::Stopped => format!(
            "stopped (last heartbeat {})",
            or_dash(relay.heartbeat_at.as_deref())
        ),
        RelayState::Unknown => "unknown (no heartbeat recorded)".to_string(),
    }
}

fn tunnels_text(counts: &TunnelCounts) -> String {
    let limit = if counts.limit == 0 {
        "no limit".to_string()
    } else {
        format!("limit {}", counts.limit)
    };
    format!(
        "{} live ({limit}), {} online, {} offline, {} deleted",
        counts.live, counts.online, counts.offline, counts.deleted
    )
}

fn budget_text(budget: &Budget) -> String {
    let breakdown = format!(
        "orders {}, renewals {}, requeues {}",
        budget.orders, budget.renewals, budget.requeues
    );
    if budget.limit == 0 {
        format!(
            "{} used in the last 24 hours, no limit ({breakdown})",
            budget.used
        )
    } else {
        format!(
            "{} of {} used in the last 24 hours ({breakdown})",
            budget.used, budget.limit
        )
    }
}

fn render_tunnels(relay: RelayState, rows: &[TunnelRow]) -> String {
    let mut out = String::new();
    if let Some(note) = relay_note(relay) {
        let _ = writeln!(out, "{note}");
    }
    if rows.is_empty() {
        out.push_str("no tunnels\n");
        return out;
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.id.clone(),
                row.hostname.clone(),
                row.state.to_string(),
                row.certificate_state.to_string(),
                or_dash(row.certificate_expires_at.as_deref()).to_string(),
                or_dash(row.last_connected_at.as_deref()).to_string(),
            ]
        })
        .collect();
    out.push_str(&table(
        &[
            "ID",
            "HOSTNAME",
            "STATE",
            "CERTIFICATE",
            "EXPIRES",
            "LAST CONNECTED",
        ],
        &cells,
    ));
    out
}

fn render_tunnel(relay: RelayState, tunnel: &TunnelDetail) -> String {
    let mut out = String::new();
    if let Some(note) = relay_note(relay) {
        let _ = writeln!(out, "{note}");
        out.push('\n');
    }
    field(&mut out, "Tunnel", &tunnel.id);
    field(&mut out, "Hostname", &tunnel.hostname);
    field(&mut out, "State", tunnel.state);
    field(&mut out, "Created", &tunnel.created_at);
    field(
        &mut out,
        "Last connected",
        or_dash(tunnel.last_connected_at.as_deref()),
    );
    if let Some(deleted) = tunnel.deleted_at.as_deref() {
        field(&mut out, "Deleted", deleted);
    }

    let cert = &tunnel.certificate;
    out.push('\n');
    field(&mut out, "Certificate", cert.state);
    field(&mut out, "Certificate id", or_dash(cert.id.as_deref()));
    field(&mut out, "Expires", or_dash(cert.expires_at.as_deref()));
    field(
        &mut out,
        "Renewable",
        if cert.renewable {
            "yes"
        } else {
            "no, no CSR is stored"
        },
    );
    if let Some(started) = cert.order_started_at.as_deref() {
        field(&mut out, "Order started", started);
    }
    if let Some(failure) = cert.failure.as_deref() {
        field(&mut out, "Failure", failure);
    }

    let renewal = &tunnel.renewal;
    out.push('\n');
    field(&mut out, "Renewal", &renewal_text(renewal));
    if let Some(since) = renewal.running_since.as_deref() {
        field(&mut out, "Running since", since);
    }
    if let Some(error) = renewal.last_error.as_deref() {
        field(&mut out, "Last error", error);
    }

    out.push_str("\nCertificate activity (last 24 hours)\n");
    if tunnel.recent_activity.is_empty() {
        out.push_str("  none\n");
    }
    for entry in &tunnel.recent_activity {
        let _ = writeln!(out, "  {}  {}", entry.at, entry.kind);
    }
    out
}

fn renewal_text(renewal: &RenewalDetail) -> String {
    match (renewal.failed_attempts, renewal.next_attempt_at.as_deref()) {
        (0, _) => "none pending".to_string(),
        (failed, Some(next)) => format!("{failed} failed attempt(s), next attempt at {next}"),
        (failed, None) => format!("{failed} failed attempt(s)"),
    }
}

fn render_issuances(rows: &[IssuanceRow]) -> String {
    if rows.is_empty() {
        return "no certificate orders, renewals, or requeues recorded\n".to_string();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.at.clone(),
                row.kind.clone(),
                row.tunnel_id.clone(),
                or_dash(row.hostname.as_deref()).to_string(),
            ]
        })
        .collect();
    table(&["TIME", "KIND", "TUNNEL", "HOSTNAME"], &cells)
}

fn relay_note(relay: RelayState) -> Option<&'static str> {
    match relay {
        RelayState::Running => None,
        RelayState::Stopped | RelayState::Unknown => {
            Some("note: the relay is not running, so no tunnel is shown as online")
        }
    }
}

fn field(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{label:<15}{value}");
}

fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .fold(header.chars().count(), usize::max)
        })
        .collect();
    let mut out = String::new();
    let mut write_row = |cells: Vec<&str>| {
        let last = cells.len() - 1;
        for (index, (cell, width)) in cells.iter().zip(&widths).enumerate() {
            if index == last {
                let _ = writeln!(out, "{cell}");
            } else {
                let _ = write!(out, "{cell:<width$}  ", width = *width);
            }
        }
    };
    write_row(headers.to_vec());
    for row in rows {
        write_row(row.iter().map(String::as_str).collect());
    }
    out
}

fn or_dash(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn count(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn count_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn parse_millis(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|time| time.timestamp_millis())
}

/// Shows a stored RFC 3339 timestamp at whole-second precision in UTC.
fn display_time(text: &str) -> String {
    DateTime::parse_from_rfc3339(text).map_or_else(
        |_| text.to_string(),
        |time| {
            time.with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        },
    )
}

/// Shows a unix-millisecond timestamp, as the scheduling columns store them.
fn millis_time(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms).map_or_else(
        || ms.to_string(),
        |time| time.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{temp_db_path, Claim, CreateOutcome, Db};
    use clap::Parser;

    const NOW: i64 = 1_800_000_000_000;
    const STALE: i64 = 20 * 60 * 1000;
    const LEASE: i64 = 30 * 60 * 1000;
    const LIMITS: Limits = Limits {
        max_tunnels: 10,
        max_certs_per_day: 7,
    };

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        for suffix in ["-wal", "-shm"] {
            let name = format!("{}{suffix}", path.file_name().unwrap().to_string_lossy());
            let _ = std::fs::remove_file(path.with_file_name(name));
        }
    }

    /// Four tunnels: t1 online with a ready certificate that expires in five
    /// days and a failing renewal; t2 with a failed order; t3 deleted; t4 never
    /// ordered. Issuance rows: t1 order (1 h ago), t2 order (2 h ago), t1
    /// renewal (30 min ago).
    async fn fixture(name: &str) -> (Db, std::path::PathBuf) {
        let path = temp_db_path(name);
        let db = Db::open(&path).unwrap();
        for (id, host) in [
            ("t1", "t1.relay.test"),
            ("t2", "t2.relay.test"),
            ("t3", "t3.relay.test"),
            ("t4", "t4.relay.test"),
        ] {
            assert_eq!(
                db.create_tunnel(id, host, "SECRET-TOKEN-HASH", "2027-01-01T00:00:00.000Z", 0)
                    .await
                    .unwrap(),
                CreateOutcome::Created
            );
        }
        assert_eq!(
            db.claim_issuance("t1", "cert1", "SECRET-CSR", NOW - 3_600_000, STALE, 0)
                .await
                .unwrap(),
            Claim::Claimed
        );
        db.set_ready(
            "cert1",
            "SECRET-CERT-PEM",
            "SECRET-CHAIN-PEM",
            "2027-01-20T08:00:00Z",
        )
        .await
        .unwrap();
        db.set_online("t1", true, "2027-01-15T07:59:00Z")
            .await
            .unwrap();
        assert_eq!(
            db.claim_issuance("t2", "cert2", "csr2", NOW - 7_200_000, STALE, 0)
                .await
                .unwrap(),
            Claim::Claimed
        );
        db.set_failed("cert2", "dns record not visible")
            .await
            .unwrap();
        assert!(db
            .claim_renewal("t1", "renew1", "SECRET-CSR", NOW - 1_800_000, LEASE)
            .await
            .unwrap());
        db.fail_renewal("t1", "renew1", "acme down", NOW - 1_200_000)
            .await
            .unwrap();
        db.delete_tunnel("t3", "2027-01-02T00:00:00.000Z")
            .await
            .unwrap();
        (db, path)
    }

    fn ids(rows: &[TunnelRow]) -> Vec<&str> {
        rows.iter().map(|row| row.id.as_str()).collect()
    }

    #[tokio::test]
    async fn status_counts_tunnels_certificates_and_budget() {
        let (db, path) = fixture("status").await;
        db.set_meta(META_HEARTBEAT_AT, "2027-01-15T07:59:30Z")
            .await
            .unwrap();
        let conn = db::open_read_only(&path).unwrap();

        let status = status_view(&conn, "relay.db", LIMITS, NOW).unwrap();
        assert_eq!(status.relay.state, RelayState::Running);
        assert_eq!(status.tunnels.live, 3);
        assert_eq!(status.tunnels.online, 1);
        assert_eq!(status.tunnels.offline, 2);
        assert_eq!(status.tunnels.deleted, 1);
        assert_eq!(status.certificates.ready, 1);
        assert_eq!(status.certificates.failed, 1);
        assert_eq!(status.certificates.none, 1);
        assert_eq!(status.certificates.expiring_soon, 1);
        assert_eq!(status.certificates.renewals_failing, 1);
        assert_eq!(status.budget.used, 3);
        assert_eq!(status.budget.orders, 2);
        assert_eq!(status.budget.renewals, 1);
        assert_eq!(status.budget.requeues, 0);
        assert_eq!(status.budget.next_order_at, None);

        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn a_stopped_relay_shows_no_tunnel_online() {
        let (db, path) = fixture("stopped").await;
        db.set_meta(META_HEARTBEAT_AT, "2027-01-15T06:00:00Z")
            .await
            .unwrap();
        let conn = db::open_read_only(&path).unwrap();

        let status = status_view(&conn, "relay.db", LIMITS, NOW).unwrap();
        assert_eq!(status.relay.state, RelayState::Stopped);
        assert_eq!(status.tunnels.online, 0);
        assert_eq!(status.tunnels.offline, 3);

        let rows = tunnel_rows(&conn, false, false).unwrap();
        assert!(rows.iter().all(|row| row.state == "offline"));

        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn a_database_without_a_heartbeat_reports_the_relay_as_unknown() {
        let (db, path) = fixture("unknown").await;
        let conn = db::open_read_only(&path).unwrap();
        let status = status_view(&conn, "relay.db", LIMITS, NOW).unwrap();
        assert_eq!(status.relay.state, RelayState::Unknown);
        assert_eq!(status.tunnels.online, 0);
        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn a_spent_budget_names_when_the_next_order_is_accepted() {
        let (db, path) = fixture("budget").await;
        let conn = db::open_read_only(&path).unwrap();

        // Oldest first: t2 order (2 h ago), t1 order (1 h ago), t1 renewal.
        let at_limit = Limits {
            max_tunnels: 0,
            max_certs_per_day: 3,
        };
        let status = status_view(&conn, "relay.db", at_limit, NOW).unwrap();
        assert_eq!(
            status.budget.next_order_at.as_deref(),
            Some(millis_time(NOW - 7_200_000 + ISSUANCE_WINDOW_MS).as_str())
        );

        // Used 3 of 2: the t2 order and then the t1 order must leave the window.
        let over_limit = Limits {
            max_tunnels: 0,
            max_certs_per_day: 2,
        };
        let status = status_view(&conn, "relay.db", over_limit, NOW).unwrap();
        assert_eq!(
            status.budget.next_order_at.as_deref(),
            Some(millis_time(NOW - 3_600_000 + ISSUANCE_WINDOW_MS).as_str())
        );

        let unlimited = Limits {
            max_tunnels: 0,
            max_certs_per_day: 0,
        };
        let status = status_view(&conn, "relay.db", unlimited, NOW).unwrap();
        assert_eq!(status.budget.next_order_at, None);
        assert_eq!(status.budget.limit, 0);

        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn tunnel_listing_hides_deleted_tunnels_unless_asked() {
        let (db, path) = fixture("listing").await;
        let conn = db::open_read_only(&path).unwrap();

        let live = tunnel_rows(&conn, true, false).unwrap();
        assert_eq!(ids(&live), ["t1", "t2", "t4"]);
        assert_eq!(live[0].state, "online");
        assert_eq!(live[1].state, "offline");

        let all = tunnel_rows(&conn, true, true).unwrap();
        assert_eq!(ids(&all), ["t1", "t2", "t3", "t4"]);
        assert_eq!(all[2].state, "deleted");
        assert!(all[2].deleted_at.is_some());

        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn tunnel_detail_reports_renewal_and_activity_without_secrets() {
        let (db, path) = fixture("detail").await;
        db.set_meta(META_HEARTBEAT_AT, "2027-01-15T07:59:30Z")
            .await
            .unwrap();
        let conn = db::open_read_only(&path).unwrap();

        let detail = tunnel_detail(&conn, "t1", true)
            .unwrap()
            .expect("t1 exists");
        assert_eq!(detail.state, "online");
        assert_eq!(detail.certificate.id.as_deref(), Some("cert1"));
        assert_eq!(detail.certificate.state, "ready");
        assert!(detail.certificate.renewable);
        assert_eq!(detail.certificate.order_started_at, None);
        assert_eq!(detail.renewal.failed_attempts, 1);
        assert_eq!(detail.renewal.last_error.as_deref(), Some("acme down"));
        assert!(detail.renewal.next_attempt_at.is_some());
        let kinds: Vec<&str> = detail
            .recent_activity
            .iter()
            .map(|entry| entry.kind.as_str())
            .collect();
        assert_eq!(kinds, ["renewal", "order"]);

        let json = serde_json::to_string(&detail).unwrap();
        for secret in [
            "SECRET-TOKEN-HASH",
            "SECRET-CSR",
            "SECRET-CERT-PEM",
            "SECRET-CHAIN-PEM",
        ] {
            assert!(!json.contains(secret), "{secret} leaked into {json}");
        }

        let failed = tunnel_detail(&conn, "t2", true)
            .unwrap()
            .expect("t2 exists");
        assert_eq!(failed.certificate.state, "failed");
        assert_eq!(
            failed.certificate.failure.as_deref(),
            Some("dns record not visible")
        );
        assert_eq!(failed.certificate.order_started_at, None);

        assert!(tunnel_detail(&conn, "missing", true).unwrap().is_none());

        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn issuances_list_newest_first_with_hostnames() {
        let (db, path) = fixture("issuances").await;
        let conn = db::open_read_only(&path).unwrap();

        let rows = issuance_rows(&conn, 10).unwrap();
        let kinds: Vec<&str> = rows.iter().map(|row| row.kind.as_str()).collect();
        assert_eq!(kinds, ["renewal", "order", "order"]);
        assert_eq!(rows[0].hostname.as_deref(), Some("t1.relay.test"));
        assert_eq!(rows[1].tunnel_id, "t2");

        assert_eq!(issuance_rows(&conn, 1).unwrap().len(), 1);

        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[tokio::test]
    async fn status_text_names_the_relay_and_the_budget() {
        let (db, path) = fixture("text").await;
        db.set_meta(META_HEARTBEAT_AT, "2027-01-15T07:59:30Z")
            .await
            .unwrap();
        let conn = db::open_read_only(&path).unwrap();
        let status = status_view(&conn, "relay.db", LIMITS, NOW).unwrap();

        let text = render_status(&status);
        assert!(text.starts_with("Relay"), "{text}");
        assert!(text.contains("running"), "{text}");
        assert!(
            text.contains("3 of 7 used in the last 24 hours (orders 2, renewals 1, requeues 0)"),
            "{text}"
        );
        assert!(text.contains("accepted now"), "{text}");

        drop(conn);
        drop(db);
        cleanup(&path);
    }

    #[test]
    fn a_missing_database_is_reported_and_not_created() {
        let dir = std::env::temp_dir().join(format!(
            "ot-relay-inspect-missing-{}-{}",
            std::process::id(),
            NOW
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = Config::try_parse_from([
            "opentunnel-relay",
            "status",
            "--data-dir",
            dir.to_str().unwrap(),
        ])
        .unwrap();
        let command = config.command.clone().expect("subcommand parsed");

        let error = run(command, &config).unwrap_err().to_string();
        assert!(error.contains("no relay database"), "{error}");
        assert!(!dir.join(db::DATABASE_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn schema_must_match_this_build() {
        let path = temp_db_path("schema");
        let conn = Connection::open(&path).unwrap();
        let error = check_schema(&conn, &path).unwrap_err().to_string();
        assert!(error.contains("no relay schema"), "{error}");

        let newer = i64::try_from(db::SCHEMA_VERSION + 1).unwrap();
        conn.pragma_update(None, "user_version", newer).unwrap();
        let error = check_schema(&conn, &path).unwrap_err().to_string();
        assert!(error.contains("newer than this build"), "{error}");

        drop(conn);
        cleanup(&path);
    }
}
