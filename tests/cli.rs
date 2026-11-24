//! Runs the `opentunnel-relay` binary's operator subcommands against databases
//! written through the library, the way a serving relay writes them.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use opentunnel_relay::{
    db::{self, Claim, Db, META_HEARTBEAT_AT},
    state::{now_millis, now_rfc3339},
};
use rusqlite::Connection;

const SECRETS: [&str; 4] = [
    "SECRET-TOKEN-HASH",
    "SECRET-CSR",
    "SECRET-CERT-PEM",
    "SECRET-CHAIN-PEM",
];

fn data_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ot-relay-cli-{name}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_relay(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_opentunnel-relay"))
        .args(args)
        .env_remove("OT_DOMAIN")
        .env_remove("OT_DATA_DIR")
        .output()
        .expect("the relay binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A database shaped like a relay that has served one tunnel: a ready
/// certificate, and the tunnel is online as far as the database knows.
async fn seeded_database(dir: &Path) -> Db {
    let db = Db::open(&dir.join(db::DATABASE_FILE)).unwrap();
    db.create_tunnel(
        "t1",
        "t1.relay.test",
        "SECRET-TOKEN-HASH",
        "2027-01-01T00:00:00.000Z",
        0,
    )
    .await
    .unwrap();
    let now = now_millis();
    assert_eq!(
        db.claim_issuance("t1", "cert1", "SECRET-CSR", now, 60_000, 0)
            .await
            .unwrap(),
        Claim::Claimed
    );
    db.set_ready(
        "cert1",
        "SECRET-CERT-PEM",
        "SECRET-CHAIN-PEM",
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    db.set_online("t1", true, &now_rfc3339()).await.unwrap();
    db
}

#[tokio::test]
async fn status_reads_a_serving_relay_and_leaves_its_state_alone() {
    let dir = data_dir("serving");
    let db = seeded_database(&dir).await;
    db.set_meta(META_HEARTBEAT_AT, &now_rfc3339())
        .await
        .unwrap();
    let dir_arg = dir.to_str().unwrap();

    let output = run_relay(&["status", "--json", "--data-dir", dir_arg]);
    assert!(output.status.success(), "{}", stderr(&output));
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["relay"]["state"], "running");
    assert_eq!(json["tunnels"]["live"], 1);
    assert_eq!(json["tunnels"]["online"], 1);
    assert_eq!(json["certificates"]["ready"], 1);
    assert_eq!(json["budget"]["used"], 1);

    let text = run_relay(&["status", "--data-dir", dir_arg]);
    assert!(text.status.success(), "{}", stderr(&text));
    assert!(stdout(&text).starts_with("Relay"), "{}", stdout(&text));
    assert!(stdout(&text).contains("running"), "{}", stdout(&text));

    let raw = Connection::open(dir.join(db::DATABASE_FILE)).unwrap();
    let state: String = raw
        .query_row("SELECT state FROM tunnels WHERE id = 't1'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(state, "online");

    drop(raw);
    drop(db);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn tunnels_show_no_tunnel_online_once_the_relay_has_stopped() {
    let dir = data_dir("stopped");
    let db = seeded_database(&dir).await;
    db.set_meta(META_HEARTBEAT_AT, "2020-01-01T00:00:00.000Z")
        .await
        .unwrap();
    drop(db);
    let dir_arg = dir.to_str().unwrap();

    let json = run_relay(&["tunnels", "--json", "--data-dir", dir_arg]);
    assert!(json.status.success(), "{}", stderr(&json));
    let rows: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(rows[0]["id"], "t1");
    assert_eq!(rows[0]["state"], "offline");

    let text = run_relay(&["tunnels", "--data-dir", dir_arg]);
    assert!(text.status.success(), "{}", stderr(&text));
    assert!(
        stdout(&text).starts_with("note: the relay is not running"),
        "{}",
        stdout(&text)
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn inspection_output_never_contains_secrets() {
    let dir = data_dir("secrets");
    let db = seeded_database(&dir).await;
    db.set_meta(META_HEARTBEAT_AT, &now_rfc3339())
        .await
        .unwrap();
    drop(db);
    let dir_arg = dir.to_str().unwrap();

    let invocations: [&[&str]; 8] = [
        &["status"],
        &["status", "--json"],
        &["tunnels", "--all"],
        &["tunnels", "--all", "--json"],
        &["tunnel", "t1"],
        &["tunnel", "t1", "--json"],
        &["issuances"],
        &["issuances", "--json"],
    ];
    for args in invocations {
        let mut full = args.to_vec();
        full.extend(["--data-dir", dir_arg]);
        let output = run_relay(&full);
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        let text = stdout(&output);
        for secret in SECRETS {
            assert!(!text.contains(secret), "{secret} printed by {args:?}");
        }
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn unknown_tunnel_is_an_error() {
    let dir = data_dir("unknown");
    let db = seeded_database(&dir).await;
    drop(db);

    let output = run_relay(&["tunnel", "nope", "--data-dir", dir.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no tunnel with id nope"),
        "{}",
        stderr(&output)
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_missing_database_is_an_error_and_is_not_created() {
    let dir = data_dir("missing");
    let output = run_relay(&["status", "--data-dir", dir.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no relay database"),
        "{}",
        stderr(&output)
    );
    assert!(!dir.join(db::DATABASE_FILE).exists());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn serving_without_a_subcommand_still_requires_a_domain() {
    let output = run_relay(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--domain"), "{}", stderr(&output));
}
