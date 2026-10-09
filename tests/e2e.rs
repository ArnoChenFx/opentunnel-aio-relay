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
    config::{Config, Timeouts},
    db::{Claim, Db},
    guard::{CidrList, RateLimiter},
    ingress,
    state::{now_millis, AppState},
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
        max_tunnels: 0,
        max_certs_per_day: 0,
        max_connections: 1024,
        reserved_connections: 64,
        max_connections_per_ip: 0,
        stream_buffer_bytes: 2 * 1024 * 1024,
        stream_idle: Duration::from_secs(3600),
        create_allow_cidrs: CidrList::default(),
        rate_limit_per_hour: 0,
        timeouts: Timeouts {
            bridge_stall: Duration::from_millis(500),
            ..Timeouts::default()
        },
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
    start_server_with(|_| {}).await
}

async fn start_server_with(tweak: impl FnOnce(&mut Config)) -> TestServer {
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
    let certified = rcgen::generate_simple_self_signed(vec![DOMAIN.to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    std::fs::write(data_dir.join("api-cert.pem"), &cert_pem).unwrap();
    std::fs::write(
        data_dir.join("api-key.pem"),
        certified.key_pair.serialize_pem(),
    )
    .unwrap();

    let mut config = test_config(&data_dir);
    tweak(&mut config);
    let db = Arc::new(Db::open(&data_dir.join("relay.db")).unwrap());
    let http = reqwest::Client::builder().build().unwrap();
    let api_tls = acme::ensure_api_cert(&config, &db, &http).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(data_dir.join("api-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let rate_limit = config.rate_limit_per_hour;
    let state = Arc::new(AppState {
        config,
        db,
        sessions: SessionManager::default(),
        api_tls: Arc::new(tokio::sync::RwLock::new(api_tls)),
        http,
        limiter: RateLimiter::new(rate_limit),
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

/// Moves a tunnel into the issuing state for `cert_id`, as a certificate POST
/// does, without contacting ACME.
async fn begin_issuance(db: &Db, id: &str, cert_id: &str, csr: &str) {
    let claim = db
        .claim_issuance(id, cert_id, csr, now_millis(), 20 * 60 * 1000, 0)
        .await
        .unwrap();
    assert_eq!(claim, Claim::Claimed);
}

/// TLS to 127.0.0.1 with SNI = relay.test, trusting the test CA.
async fn tls_connect(port: u16, cert_pem: &str) -> tokio_rustls::client::TlsStream<TcpStream> {
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
    let (status, _, body) = http_exchange(srv, method, path, token, body).await;
    (status, body)
}

/// Like `http_request`, but also returns the raw response header block.
async fn http_exchange(
    srv: &TestServer,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, String, String) {
    let mut tls = tls_connect(srv.port, &srv.cert_pem).await;
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {DOMAIN}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    (status, head.to_string(), body.to_string())
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

async fn expect_end<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, expected_conn: u32)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for end")
            .expect("bridge closed")
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            let control: serde_json::Value = serde_json::from_str(&text).unwrap();
            if control["type"] == "end" && control["conn"].as_u64() == Some(expected_conn as u64) {
                return;
            }
        }
    }
}

async fn expect_close<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for WebSocket close")
            .expect("WebSocket ended without a close frame")
            .unwrap();
        if matches!(msg, tokio_tungstenite::tungstenite::Message::Close(_)) {
            return;
        }
    }
}

async fn expect_data<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    expected_conn: u32,
    expected_payload: &[u8],
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for proxied data")
            .expect("bridge closed")
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Binary(frame) = msg {
            if let Some((conn, payload)) =
                opentunnel_relay::proto::bridge::decode_data_frame(&frame)
            {
                if conn == expected_conn && payload == expected_payload {
                    return;
                }
            }
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

    let (status, body) =
        http_request(&srv, "GET", &format!("/api/tunnel/{id}"), Some(&token), "").await;
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
async fn retrying_same_csr_does_not_restart_active_issuance() {
    let srv = start_server().await;
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["tunnel"]["id"].as_str().unwrap().to_string();
    let hostname = created["tunnel"]["hostname"].as_str().unwrap();
    let token = created["token"].as_str().unwrap().to_string();

    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    begin_issuance(&srv.state.db, &id, "cert_already_issuing", &csr).await;

    let body = serde_json::json!({"csr": csr}).to_string();
    let (status, response) = http_request(
        &srv,
        "POST",
        &format!("/api/tunnel/{id}/certificate"),
        Some(&token),
        &body,
    )
    .await;
    assert_eq!(status, 202, "{response}");
    assert_eq!(
        srv.state
            .db
            .get_tunnel(&id)
            .await
            .unwrap()
            .unwrap()
            .cert_id
            .as_deref(),
        Some("cert_already_issuing")
    );
}

#[tokio::test]
async fn retrying_same_csr_restarts_failed_issuance() {
    let srv = start_server().await;
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["tunnel"]["id"].as_str().unwrap().to_string();
    let hostname = created["tunnel"]["hostname"].as_str().unwrap();
    let token = created["token"].as_str().unwrap().to_string();

    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    begin_issuance(&srv.state.db, &id, "cert_failed", &csr).await;
    assert!(srv
        .state
        .db
        .set_failed("cert_failed", "temporary CA outage")
        .await
        .unwrap());

    let body = serde_json::json!({"csr": csr.clone()}).to_string();
    let (status, response) = http_request(
        &srv,
        "POST",
        &format!("/api/tunnel/{id}/certificate"),
        Some(&token),
        &body,
    )
    .await;
    assert_eq!(status, 202, "{response}");
    let record = srv.state.db.get_tunnel(&id).await.unwrap().unwrap();
    assert_ne!(record.cert_id.as_deref(), Some("cert_failed"));
    assert_eq!(record.csr_pem.as_deref(), Some(csr.as_str()));
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
    begin_issuance(&srv.state.db, &id, "cert_e2e", "dummy-csr").await;
    assert!(srv
        .state
        .db
        .set_ready("cert_e2e", "CERT", "CHAIN", "2099-01-01T00:00:00Z")
        .await
        .unwrap());

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
        "token": token.clone(),
        "transport": "ws",
        "routes": ["@", "api"],
        "client": {"version": "0.1.0", "max_conns": 256},
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        attach.to_string().into(),
    ))
    .await
    .unwrap();

    let attached: serde_json::Value = serde_json::from_str(&recv_text(&mut ws).await).unwrap();
    assert_eq!(attached["type"], "attached");
    assert_eq!(attached["heartbeat_ms"], 15000);

    // Attach a second bridge to a disjoint route in the same tunnel session.
    let tls2 = tls_connect(srv.port, &srv.cert_pem).await;
    let mut req2 = format!("wss://{DOMAIN}:{}/api/tunnel/{id}/connect", srv.port)
        .into_client_request()
        .unwrap();
    req2.headers_mut()
        .insert("sec-websocket-protocol", "opentunnel".parse().unwrap());
    let (mut ws2, _) = tokio_tungstenite::client_async(req2, tls2).await.unwrap();
    let attach2 = serde_json::json!({
        "type": "attach",
        "token": token.clone(),
        "transport": "ws",
        "routes": ["extra"],
        "client": {"version": "0.1.0", "max_conns": 256},
    });
    ws2.send(tokio_tungstenite::tungstenite::Message::Text(
        attach2.to_string().into(),
    ))
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&recv_text(&mut ws2).await).unwrap()["type"],
        "attached"
    );

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

    let mut public_extra = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    public_extra
        .write_all(&client_hello(&format!("extra.{id}.{DOMAIN}")))
        .await
        .unwrap();
    let conn3 = expect_open(&mut ws2, &format!("extra.{id}.{DOMAIN}")).await;
    assert_eq!(conn3, 3);

    let request = b"client request before half-close";
    public.write_all(request).await.unwrap();
    expect_data(&mut ws, conn1, request).await;

    // A client half-close must signal End upstream but keep the reverse pump
    // alive long enough to deliver the server's final response.
    public.shutdown().await.unwrap();
    expect_end(&mut ws, conn1).await;
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        opentunnel_relay::proto::bridge::encode_data_frame(conn1, b"response after half-close")
            .into(),
    ))
    .await
    .unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({"type": "end", "conn": conn1})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), public.read_to_end(&mut response))
        .await
        .expect("response after half-close was not completed")
        .unwrap();
    assert_eq!(response, b"response after half-close");

    // A bridge disconnect must reset only its own channels. The second
    // bridge's already-open connection remains usable.
    ws.close(None).await.unwrap();
    expect_close(&mut ws).await;
    let mut disconnected_response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        public2.read_to_end(&mut disconnected_response),
    )
    .await
    .expect("connection owned by the disconnected bridge stayed open")
    .unwrap();
    ws2.send(tokio_tungstenite::tungstenite::Message::Binary(
        opentunnel_relay::proto::bridge::encode_data_frame(conn3, b"other bridge survived").into(),
    ))
    .await
    .unwrap();
    ws2.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({"type": "end", "conn": conn3})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut extra_response = [0u8; 21];
    tokio::time::timeout(
        Duration::from_secs(3),
        public_extra.read_exact(&mut extra_response),
    )
    .await
    .expect("other bridge channel was incorrectly reset")
    .unwrap();
    assert_eq!(&extra_response, b"other bridge survived");

    // Unknown SNI: connection is dropped, nothing arrives on the bridge.
    let mut public3 = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    public3
        .write_all(&client_hello("other.example.com"))
        .await
        .unwrap();
    drop(public3);

    // Deleting the tunnel closes its bridge WebSocket and active public socket.
    let (status, _) = http_request(
        &srv,
        "DELETE",
        &format!("/api/tunnel/{id}"),
        Some(&token),
        "",
    )
    .await;
    assert_eq!(status, 204);
    let mut deleted_conn = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        public_extra.read_to_end(&mut deleted_conn),
    )
    .await
    .expect("active public connection stayed open after tunnel deletion")
    .unwrap();
    expect_close(&mut ws2).await;
}

type Bridge = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Provisions a tunnel with a ready certificate and attaches one bridge that
/// serves the base route.
async fn attached_bridge(srv: &TestServer) -> (String, Bridge) {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let (status, body) = http_request(srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["tunnel"]["id"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();
    // Certificate ids are shared by every tunnel that uses them, so each
    // tunnel gets its own.
    let cert_id = format!("cert_{}", opentunnel_relay::bridge::random_session_id());
    begin_issuance(&srv.state.db, &id, &cert_id, "dummy-csr").await;
    assert!(srv
        .state
        .db
        .set_ready(&cert_id, "CERT", "CHAIN", "2099-01-01T00:00:00Z")
        .await
        .unwrap());

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
        "routes": ["@"],
        "client": {"version": "0.1.0", "max_conns": 256},
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        attach.to_string().into(),
    ))
    .await
    .unwrap();
    let attached: serde_json::Value = serde_json::from_str(&recv_text(&mut ws).await).unwrap();
    assert_eq!(attached["type"], "attached");
    (id, ws)
}

/// Connects a visitor with the given SNI and waits for the bridge to announce
/// the connection. `recv_buffer` shrinks the visitor's kernel receive buffer so
/// a visitor that stops reading backs up quickly.
async fn open_visitor(
    port: u16,
    bridge: &mut Bridge,
    sni: &str,
    recv_buffer: Option<u32>,
) -> (TcpStream, u32) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    if let Some(size) = recv_buffer {
        socket.set_recv_buffer_size(size).unwrap();
    }
    let mut public = socket.connect(([127, 0, 0, 1], port).into()).await.unwrap();
    public.write_all(&client_hello(sni)).await.unwrap();
    let conn = expect_open(bridge, sni).await;
    (public, conn)
}

async fn expect_reset<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    expected_conn: u32,
    expected_code: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for reset")
            .expect("bridge closed")
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            let control: serde_json::Value = serde_json::from_str(&text).unwrap();
            if control["type"] == "reset" && control["conn"].as_u64() == Some(expected_conn as u64)
            {
                assert_eq!(control["code"], expected_code);
                return;
            }
        }
    }
}

/// A control message as a WebSocket text frame.
fn control_message(value: serde_json::Value) -> tokio_tungstenite::tungstenite::Message {
    tokio_tungstenite::tungstenite::Message::Text(value.to_string().into())
}

/// Reads bridge messages until a pong echoing `time_sent` and a reset of
/// `conn` with `code` have both arrived, in either order.
async fn await_pong_and_reset<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    time_sent: u64,
    conn: u32,
    code: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;
    let (mut pong, mut reset) = (false, false);
    while !(pong && reset) {
        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("bridge sent neither the heartbeat reply nor the reset in time")
            .expect("bridge closed")
            .unwrap();
        let tokio_tungstenite::tungstenite::Message::Text(text) = msg else {
            continue;
        };
        let control: serde_json::Value = serde_json::from_str(&text).unwrap();
        match control["type"].as_str() {
            Some("pong") if control["time_sent"].as_u64() == Some(time_sent) => pong = true,
            Some("reset") if control["conn"].as_u64() == Some(conn as u64) => {
                assert_eq!(control["code"], code);
                reset = true;
            }
            _ => {}
        }
    }
}

/// Floods one visitor that never reads, then checks that the bridge still
/// answers heartbeats and carries another visitor's traffic in both directions.
#[tokio::test]
async fn stalled_visitor_does_not_hold_up_heartbeats_or_other_streams() {
    use futures_util::SinkExt;
    use opentunnel_relay::proto::bridge::{encode_data_frame, MAX_PAYLOAD_SIZE};

    // The production stall budget. A reader blocked on the stalled visitor
    // would hold the heartbeat for all of it, far past the deadline below.
    let srv = start_server_with(|c| {
        c.timeouts.bridge_stall = Duration::from_secs(10);
        c.stream_buffer_bytes = 1 << 20;
    })
    .await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");
    let (_stalled, stalled_conn) = open_visitor(srv.port, &mut ws, &sni, Some(4096)).await;
    let (mut healthy, healthy_conn) = open_visitor(srv.port, &mut ws, &sni, None).await;

    // 16 MiB at a visitor that never reads: far beyond its buffer and the kernel's.
    // Timing starts before the flood, because a blocked bridge also stalls the
    // sends below rather than the heartbeat alone.
    let flooded = std::time::Instant::now();
    let frame = encode_data_frame(stalled_conn, &vec![0xEE; MAX_PAYLOAD_SIZE]);
    for _ in 0..512 {
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            frame.clone().into(),
        ))
        .await
        .unwrap();
    }
    ws.send(control_message(
        serde_json::json!({"type": "ping", "time_sent": 7}),
    ))
    .await
    .unwrap();
    await_pong_and_reset(&mut ws, 7, stalled_conn, "backpressure").await;
    assert!(
        flooded.elapsed() < Duration::from_secs(5),
        "bridge answered the heartbeat after {:?}",
        flooded.elapsed()
    );

    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        encode_data_frame(healthy_conn, b"to visitor").into(),
    ))
    .await
    .unwrap();
    let mut received = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(3), healthy.read_exact(&mut received))
        .await
        .expect("other stream stopped flowing")
        .unwrap();
    assert_eq!(&received, b"to visitor");

    healthy.write_all(b"from visitor").await.unwrap();
    expect_data(&mut ws, healthy_conn, b"from visitor").await;
}

/// The cap is larger than the flood, so only the stall budget can reset the visitor.
#[tokio::test]
async fn visitor_that_stops_reading_is_reset_once_its_stall_budget_expires() {
    use futures_util::SinkExt;
    use opentunnel_relay::proto::bridge::{encode_data_frame, MAX_PAYLOAD_SIZE};

    let srv = start_server_with(|c| c.stream_buffer_bytes = 64 << 20).await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");
    let (mut stalled, stalled_conn) = open_visitor(srv.port, &mut ws, &sni, Some(4096)).await;

    let frame = encode_data_frame(stalled_conn, &vec![0xEE; MAX_PAYLOAD_SIZE]);
    for _ in 0..512 {
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            frame.clone().into(),
        ))
        .await
        .unwrap();
    }
    expect_reset(&mut ws, stalled_conn, "backpressure").await;

    let mut drained = Vec::new();
    let closed =
        tokio::time::timeout(Duration::from_secs(5), stalled.read_to_end(&mut drained)).await;
    assert!(closed.is_ok(), "stalled visitor socket was not closed");
}

/// With a stall budget far longer than the test, a reset can only come from
/// the buffer overflowing, and it must arrive without waiting for the budget.
#[tokio::test]
async fn overflowing_visitor_is_reset_without_waiting_for_the_stall_budget() {
    use futures_util::SinkExt;
    use opentunnel_relay::proto::bridge::{encode_data_frame, MAX_PAYLOAD_SIZE};

    let srv = start_server_with(|c| {
        c.timeouts.bridge_stall = Duration::from_secs(60);
        c.stream_buffer_bytes = 1 << 20;
    })
    .await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");
    let (mut stalled, stalled_conn) = open_visitor(srv.port, &mut ws, &sni, Some(4096)).await;

    let flooded = std::time::Instant::now();
    let frame = encode_data_frame(stalled_conn, &vec![0xEE; MAX_PAYLOAD_SIZE]);
    for _ in 0..512 {
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            frame.clone().into(),
        ))
        .await
        .unwrap();
    }
    expect_reset(&mut ws, stalled_conn, "backpressure").await;
    assert!(
        flooded.elapsed() < Duration::from_secs(5),
        "overflow reset arrived after {:?}",
        flooded.elapsed()
    );

    let mut drained = Vec::new();
    let closed =
        tokio::time::timeout(Duration::from_secs(5), stalled.read_to_end(&mut drained)).await;
    assert!(closed.is_ok(), "overflowed visitor socket was not closed");
}

#[tokio::test]
async fn queued_frames_arrive_in_order_and_end_follows_them() {
    use futures_util::SinkExt;
    use opentunnel_relay::proto::bridge::{encode_data_frame, MAX_PAYLOAD_SIZE};

    let srv = start_server_with(|c| c.stream_buffer_bytes = 64 << 20).await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");
    let (mut visitor, conn) = open_visitor(srv.port, &mut ws, &sni, Some(4096)).await;

    // The visitor waits before reading, so frames queue up and the End frame
    // must wait behind them. Nothing may be dropped, and the stall budget must
    // not expire. Each frame carries its index to catch reordering.
    let frames: Vec<Vec<u8>> = (0..600u32)
        .map(|i| {
            let mut payload = vec![0xAB; MAX_PAYLOAD_SIZE];
            payload[..4].copy_from_slice(&i.to_be_bytes());
            payload
        })
        .collect();
    let expected = frames.concat();
    let reader = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), visitor.read_to_end(&mut received))
            .await
            .expect("visitor never reached end-of-stream")
            .unwrap();
        received
    });
    for payload in &frames {
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            encode_data_frame(conn, payload).into(),
        ))
        .await
        .unwrap();
    }
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({"type": "end", "conn": conn})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();

    let received = reader.await.unwrap();
    assert_eq!(received.len(), expected.len());
    assert!(
        received == expected,
        "visitor received altered or reordered data"
    );
}

#[tokio::test]
async fn client_reset_closes_only_that_visitor_socket() {
    use futures_util::SinkExt;
    use opentunnel_relay::proto::bridge::encode_data_frame;

    let srv = start_server().await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");
    let (mut aborted, aborted_conn) = open_visitor(srv.port, &mut ws, &sni, None).await;
    let (mut kept, kept_conn) = open_visitor(srv.port, &mut ws, &sni, None).await;

    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({"type": "reset", "conn": aborted_conn, "code": "upstream_io_error"})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let mut drained = Vec::new();
    let closed =
        tokio::time::timeout(Duration::from_secs(3), aborted.read_to_end(&mut drained)).await;
    assert!(
        closed.is_ok(),
        "client reset did not close the visitor socket"
    );

    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        encode_data_frame(kept_conn, b"still open").into(),
    ))
    .await
    .unwrap();
    let mut received = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(3), kept.read_exact(&mut received))
        .await
        .expect("unrelated connection was reset")
        .unwrap();
    assert_eq!(&received, b"still open");
}

#[tokio::test]
async fn simultaneous_attach_to_same_route_has_one_winner() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let srv = start_server().await;
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["tunnel"]["id"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();
    begin_issuance(&srv.state.db, &id, "cert_concurrent_attach", "dummy-csr").await;
    assert!(srv
        .state
        .db
        .set_ready(
            "cert_concurrent_attach",
            "CERT",
            "CHAIN",
            "2099-01-01T00:00:00Z",
        )
        .await
        .unwrap());

    let tls1 = tls_connect(srv.port, &srv.cert_pem).await;
    let mut req1 = format!("wss://{DOMAIN}:{}/api/tunnel/{id}/connect", srv.port)
        .into_client_request()
        .unwrap();
    req1.headers_mut()
        .insert("sec-websocket-protocol", "opentunnel".parse().unwrap());
    let (mut ws1, _) = tokio_tungstenite::client_async(req1, tls1).await.unwrap();

    let tls2 = tls_connect(srv.port, &srv.cert_pem).await;
    let mut req2 = format!("wss://{DOMAIN}:{}/api/tunnel/{id}/connect", srv.port)
        .into_client_request()
        .unwrap();
    req2.headers_mut()
        .insert("sec-websocket-protocol", "opentunnel".parse().unwrap());
    let (mut ws2, _) = tokio_tungstenite::client_async(req2, tls2).await.unwrap();

    let attach = serde_json::json!({
        "type": "attach",
        "token": token,
        "transport": "ws",
        "routes": ["@"],
        "client": {"version": "0.1.0", "max_conns": 256},
    });
    let message = tokio_tungstenite::tungstenite::Message::Text(attach.to_string().into());
    let (sent1, sent2) = tokio::join!(ws1.send(message.clone()), ws2.send(message));
    sent1.unwrap();
    sent2.unwrap();

    let response1: serde_json::Value = serde_json::from_str(&recv_text(&mut ws1).await).unwrap();
    let response2: serde_json::Value = serde_json::from_str(&recv_text(&mut ws2).await).unwrap();
    let kinds = [
        response1["type"].as_str().unwrap(),
        response2["type"].as_str().unwrap(),
    ];
    assert!(
        kinds.contains(&"attached"),
        "responses: {response1}, {response2}"
    );
    assert!(
        kinds.contains(&"attach_error"),
        "responses: {response1}, {response2}"
    );
    let error = if response1["type"] == "attach_error" {
        &response1
    } else {
        &response2
    };
    assert_eq!(error["code"], "route_conflict");
}

#[tokio::test]
async fn idle_stream_is_closed_and_the_bridge_is_told() {
    let srv = start_server_with(|c| c.stream_idle = Duration::from_millis(300)).await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");
    let (mut visitor, conn) = open_visitor(srv.port, &mut ws, &sni, None).await;

    expect_reset(&mut ws, conn, "connection_terminated").await;
    let mut drained = Vec::new();
    let closed =
        tokio::time::timeout(Duration::from_secs(3), visitor.read_to_end(&mut drained)).await;
    assert!(closed.is_ok(), "idle visitor socket was not closed");
}

#[tokio::test]
async fn traffic_in_either_direction_keeps_a_stream_open() {
    use futures_util::SinkExt;
    use opentunnel_relay::proto::bridge::encode_data_frame;

    let srv = start_server_with(|c| c.stream_idle = Duration::from_millis(400)).await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");
    let (mut visitor, conn) = open_visitor(srv.port, &mut ws, &sni, None).await;

    // Six round trips span well over the idle limit; each gap is far below it.
    for beat in 0..6u8 {
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            encode_data_frame(conn, &[beat]).into(),
        ))
        .await
        .unwrap();
        let mut got = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(2), visitor.read_exact(&mut got))
            .await
            .expect("visitor stalled")
            .unwrap();
        assert_eq!(got[0], beat);

        visitor.write_all(&[beat]).await.unwrap();
        expect_data(&mut ws, conn, &[beat]).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    expect_reset(&mut ws, conn, "connection_terminated").await;
}

#[tokio::test]
async fn stalled_api_request_is_closed_by_the_header_timeout() {
    let srv = start_server_with(|c| c.timeouts.client_hello = Duration::from_millis(300)).await;
    let mut tls = tls_connect(srv.port, &srv.cert_pem).await;
    tls.write_all(b"GET /health HTTP/1.1\r\nHost: relay.test\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut rest)).await;
    assert!(closed.is_ok(), "stalled API request was not closed");
}

#[tokio::test]
async fn connection_limit_refuses_excess_and_recovers() {
    let srv = start_server_with(|c| {
        c.max_connections = 1;
        c.reserved_connections = 0;
    })
    .await;

    let holder = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut refused = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), refused.read(&mut buf))
        .await
        .expect("refused connection was left open")
        .unwrap_or(0);
    assert_eq!(n, 0, "excess connection must be closed without service");

    drop(holder);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, _) = http_request(&srv, "GET", "/health", None, "").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn one_address_cannot_hold_more_than_its_share_of_connections() {
    let srv = start_server_with(|c| c.max_connections_per_ip = 2).await;

    let first = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    let _second = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut third = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf))
        .await
        .expect("connection beyond the per-address share was left open")
        .unwrap_or(0);
    assert_eq!(
        n, 0,
        "connection beyond the per-address share must be closed"
    );

    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, _) = http_request(&srv, "GET", "/health", None, "").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn visitors_cannot_take_the_slots_reserved_for_bridges() {
    let srv = start_server_with(|c| {
        c.max_connections = 6;
        c.reserved_connections = 4;
        c.max_connections_per_ip = 0;
    })
    .await;
    let (id, mut ws) = attached_bridge(&srv).await;
    let sni = format!("{id}.{DOMAIN}");

    // Visitors may hold only max - reserved = 2 connections.
    let (_first, _) = open_visitor(srv.port, &mut ws, &sni, None).await;
    let (_second, _) = open_visitor(srv.port, &mut ws, &sni, None).await;

    let mut third = TcpStream::connect(("127.0.0.1", srv.port)).await.unwrap();
    third.write_all(&client_hello(&sni)).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf))
        .await
        .expect("visitor beyond its pool was left open")
        .unwrap_or(0);
    assert_eq!(n, 0, "visitor beyond its pool must be closed");

    let (_other_id, _other_ws) = attached_bridge(&srv).await;
}

#[tokio::test]
async fn allowlist_refuses_sources_outside_it() {
    let srv = start_server_with(|c| {
        c.create_allow_cidrs = "10.0.0.0/8".parse::<CidrList>().unwrap();
    })
    .await;
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("ForbiddenError"), "{body}");

    let srv = start_server_with(|c| {
        c.create_allow_cidrs = "127.0.0.1".parse::<CidrList>().unwrap();
    })
    .await;
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
}

#[tokio::test]
async fn rate_limit_answers_429_with_retry_after_and_leaves_reads_alone() {
    let srv = start_server_with(|c| c.rate_limit_per_hour = 2).await;

    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = created["tunnel"]["id"].as_str().unwrap().to_string();
    let token = created["token"].as_str().unwrap().to_string();
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");

    let (status, headers, body) = http_exchange(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 429, "{body}");
    assert!(body.contains("RateLimitedError"), "{body}");
    assert!(
        headers.lines().any(|line| {
            line.to_ascii_lowercase().starts_with("retry-after:")
                && line
                    .split(':')
                    .nth(1)
                    .unwrap()
                    .trim()
                    .parse::<u64>()
                    .unwrap()
                    >= 1
        }),
        "{headers}"
    );

    let (status, body) =
        http_request(&srv, "GET", &format!("/api/tunnel/{id}"), Some(&token), "").await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn tunnel_cap_answers_503() {
    let srv = start_server_with(|c| c.max_tunnels = 1).await;
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("ServiceUnavailableError"), "{body}");
}
