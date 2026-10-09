//! End-to-end test over real sockets: TCP ingress -> SNI routing ->
//! API TLS -> REST -> bridge WebSocket -> proxied connection `open`.
//!
//! No DNS or network access needed: TLS is done manually against a throwaway
//! self-signed API certificate, and ACME is bypassed by marking the test
//! tunnel's certificate ready directly in the database.

use std::sync::Arc;
use std::time::Duration;

use opentunnel_relay::{
    acme, api,
    bridge::SessionManager,
    config::Config,
    db::Db,
    ingress,
    state::AppState,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DOMAIN: &str = "relay.test";

struct TestServer {
    port: u16,
    cert_pem: String,
    state: Arc<AppState>,
}

fn test_config(data_dir: &std::path::Path) -> Config {
    Config {
        domain: DOMAIN.to_string(),
        listen: "127.0.0.1:0".to_string(),
        data_dir: data_dir.to_path_buf(),
        cf_token: "test".to_string(),
        cf_zone_id: "test".to_string(),
        acme_eab_kid: "test".to_string(),
        acme_eab_hmac: "test".to_string(),
        acme_url: "https://example.invalid".to_string(),
        acme_email: "test@example.invalid".to_string(),
    }
}

fn init_log() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("opentunnel_relay=debug")
            .try_init();
    });
}

async fn start_server() -> TestServer {
    init_log();
    let data_dir = std::env::temp_dir().join(format!(
        "ot-relay-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&data_dir).unwrap();

    // Throwaway self-signed API certificate (ACME is bypassed: the files
    // already exist, so ensure_api_cert never dials out).
    let certified =
        rcgen::generate_simple_self_signed(vec![DOMAIN.to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    std::fs::write(data_dir.join("api-cert.pem"), &cert_pem).unwrap();
    std::fs::write(
        data_dir.join("api-key.pem"),
        certified.key_pair.serialize_pem(),
    )
    .unwrap();

    let config = test_config(&data_dir);
    let db = Arc::new(Db::open(&data_dir.join("relay.db")).unwrap());
    let http = reqwest::Client::builder().build().unwrap();
    let api_tls = acme::ensure_api_cert(&config, &db, &http).await.unwrap();

    let state = Arc::new(AppState {
        config,
        db,
        sessions: SessionManager::default(),
        api_tls,
        http,
    });
    let router = api::router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(ingress::run_on(listener, state.clone(), router));

    TestServer {
        port,
        cert_pem,
        state,
    }
}

/// TLS to 127.0.0.1 with SNI = relay.test, trusting the test CA.
async fn tls_connect(
    port: u16,
    cert_pem: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(DOMAIN)
        .unwrap()
        .to_owned();
    connector.connect(name, tcp).await.unwrap()
}

/// Minimal HTTP/1.1 over the test TLS stream. Returns (status, body).
async fn http_request(
    srv: &TestServer,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut tls = tls_connect(srv.port, &srv.cert_pem).await;
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {DOMAIN}\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, body.to_string())
}

/// Builds a minimal well-formed ClientHello carrying `sni`
/// (same construction as the parser unit tests in src/sni.rs).
fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sn_body = vec![0u8]; // host_name
    sn_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sn_body.extend_from_slice(name);
    let mut sn_list = Vec::new();
    sn_list.extend_from_slice(&(sn_body.len() as u16).to_be_bytes());
    sn_list.extend_from_slice(&sn_body);
    let mut ext = Vec::new();
    ext.extend_from_slice(&0u16.to_be_bytes()); // server_name
    ext.extend_from_slice(&(sn_list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sn_list);

    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0xAA; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    hello.push(1);
    hello.push(0);
    hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    let len = hello.len() as u32;
    hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    hs.extend_from_slice(&hello);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

async fn recv_text<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for bridge message")
        .expect("bridge closed")
        .unwrap();
    match msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
        other => panic!("expected text, got {other:?}"),
    }
}

/// Reads bridge messages until the next `open` control message, skipping
/// replayed data frames from earlier connections.
async fn expect_open<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, expected_sni: &str) -> u32
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for open")
            .expect("bridge closed")
            .unwrap();
        match msg {
            tokio_tungstenite::tungstenite::Message::Text(t) => {
                let open: serde_json::Value = serde_json::from_str(&t).unwrap();
                if open["type"] == "open" {
                    assert_eq!(open["sni"], expected_sni);
                    return open["conn"].as_u64().unwrap() as u32;
                }
            }
            tokio_tungstenite::tungstenite::Message::Binary(_) => {}
            other => panic!("unexpected bridge message: {other:?}"),
        }
    }
}

#[tokio::test]
async fn api_provisioning_flow() {
    let srv = start_server().await;

    let (status, body) = http_request(&srv, "GET", "/health", None, "").await;
    assert_eq!(status, 200);
    assert!(body.contains("\"ok\":true"), "{body}");

    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["tunnel"]["id"].as_str().unwrap().to_string();
    let hostname = created["tunnel"]["hostname"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();
    assert_eq!(hostname, format!("{id}.{DOMAIN}"));
    assert!(token.starts_with("rly_"));

    let (status, _) = http_request(&srv, "GET", &format!("/api/tunnel/{id}"), None, "").await;
    assert_eq!(status, 401);

    let (status, body) = http_request(
        &srv,
        "GET",
        &format!("/api/tunnel/{id}"),
        Some(&token),
        "",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(&hostname));

    // No certificate yet.
    let (status, _) = http_request(
        &srv,
        "GET",
        &format!("/api/tunnel/{id}/certificate"),
        Some(&token),
        "",
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn bridge_attach_and_sni_routing() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let srv = start_server().await;

    // Provision a tunnel, then fake a ready certificate (ACME is out of scope
    // for this test; issuance itself is exercised against staging CAs).
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["tunnel"]["id"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();
    srv.state
        .db
        .begin_issuance(&id, "cert_e2e", "dummy-csr")
        .unwrap();
    srv.state
        .db
        .set_ready("cert_e2e", "CERT", "CHAIN", "2099-01-01T00:00:00Z")
        .unwrap();

    // Open the bridge WebSocket manually over our own TLS stream (no DNS).
    let tls = tls_connect(srv.port, &srv.cert_pem).await;
    let mut req = format!("wss://{DOMAIN}:{}/api/tunnel/{id}/connect", srv.port)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("sec-websocket-protocol", "opentunnel".parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::client_async(req, tls).await.unwrap();

    let attach = serde_json::json!({
        "type": "attach",
        "token": token,
        "transport": "ws",
        "routes": ["@", "api"],
        "client": {"version": "0.1.0", "max_conns": 256},
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        attach.to_string().into(),
    ))
    .await
    .unwrap();

    let attached: serde_json::Value =
        serde_json::from_str(&recv_text(&mut ws).await).unwrap();
    assert_eq!(attached["type"], "attached");
    assert_eq!(attached["heartbeat_ms"], 15000);

    // A public TCP connection with SNI = <id>.relay.test must produce `open`.
    let mut public = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    public
        .write_all(&client_hello(&format!("{id}.{DOMAIN}")))
        .await
        .unwrap();
    let conn1 = expect_open(&mut ws, &format!("{id}.{DOMAIN}")).await;
    assert_eq!(conn1, 1);

    // Same for a named route: api.<id>.relay.test -> route "api".
    let mut public2 = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    public2
        .write_all(&client_hello(&format!("api.{id}.{DOMAIN}")))
        .await
        .unwrap();
    let conn2 = expect_open(&mut ws, &format!("api.{id}.{DOMAIN}")).await;
    assert_eq!(conn2, 2);

    // Unknown SNI: connection is dropped, nothing arrives on the bridge.
    let mut public3 = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    public3
        .write_all(&client_hello("other.example.com"))
        .await
        .unwrap();
    drop(public3);
}
