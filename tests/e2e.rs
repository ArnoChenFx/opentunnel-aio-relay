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
    config::{Config, IpNetwork},
    db::Db,
    ingress,
    state::{AppState, TunnelCreationPolicy},
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
        tunnel_create_ip_allowlist: vec![],
        tunnel_create_rate_limit: 5,
        tunnel_create_rate_window_secs: 60,
        max_active_tunnels: 1000,
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
    start_server_with_config(|_| {}).await
}

async fn start_server_with_config(configure: impl FnOnce(&mut Config)) -> TestServer {
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
    configure(&mut config);
    let db = Arc::new(Db::open(&data_dir.join("relay.db")).unwrap());
    let http = reqwest::Client::builder().build().unwrap();
    let api_tls = acme::ensure_api_cert(&config, db.clone(), &http)
        .await
        .unwrap();
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

    let tunnel_creation_policy = TunnelCreationPolicy::new(&config);
    let state = Arc::new(AppState {
        config,
        db,
        sessions: SessionManager::default(),
        tunnel_creation_policy,
        api_tls: Arc::new(tokio::sync::RwLock::new(api_tls)),
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

    // Stock clients create tunnels without a server-wide admin token.
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
async fn tunnel_creation_enforces_source_ip_allowlist() {
    let srv = start_server_with_config(|config| {
        config.tunnel_create_ip_allowlist = vec!["192.0.2.0/24".parse::<IpNetwork>().unwrap()];
    })
    .await;

    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("source IP is not allowed"), "{body}");
}

#[tokio::test]
async fn tunnel_creation_is_rate_limited_per_source_ip() {
    let srv = start_server_with_config(|config| config.tunnel_create_rate_limit = 1).await;

    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 429, "{body}");
}

#[tokio::test]
async fn tunnel_creation_respects_active_tunnel_cap() {
    let srv = start_server_with_config(|config| config.max_active_tunnels = 1).await;

    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = http_request(&srv, "POST", "/api/tunnel", None, "{}").await;
    assert_eq!(status, 503, "{body}");
    assert!(
        body.contains("configured active tunnel cap (1) reached"),
        "{body}"
    );
}

#[tokio::test]
async fn ordinary_api_response_closes_http_keep_alive_connection() {
    let srv = start_server().await;
    let mut tls = tls_connect(srv.port, &srv.cert_pem).await;
    tls.write_all(format!("GET /health HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut response))
        .await
        .expect("server left an ordinary keep-alive connection open")
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.to_ascii_lowercase().contains("connection: close"),
        "{response}"
    );
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
    srv.state
        .db
        .begin_issuance(&id, "cert_already_issuing", &csr)
        .unwrap();

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
            .unwrap()
            .unwrap()
            .cert_id
            .as_deref(),
        Some("cert_already_issuing")
    );
}

#[tokio::test]
async fn failed_issuance_obeys_backoff_but_new_csr_can_restart() {
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
    srv.state
        .db
        .begin_issuance(&id, "cert_failed", &csr)
        .unwrap();
    srv.state
        .db
        .set_failed("cert_failed", "temporary CA outage")
        .unwrap();

    let body = serde_json::json!({"csr": csr.clone()}).to_string();
    let (status, response) = http_request(
        &srv,
        "POST",
        &format!("/api/tunnel/{id}/certificate"),
        Some(&token),
        &body,
    )
    .await;
    assert_eq!(status, 409, "{response}");
    let record = srv.state.db.get_tunnel(&id).unwrap().unwrap();
    assert_eq!(record.cert_id.as_deref(), Some("cert_failed"));
    assert_eq!(record.cert_state, opentunnel_relay::db::CertState::Failed);

    let replacement_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let replacement_csr = params
        .serialize_request(&replacement_key)
        .unwrap()
        .pem()
        .unwrap();
    let body = serde_json::json!({"csr": replacement_csr.clone()}).to_string();
    let (status, response) = http_request(
        &srv,
        "POST",
        &format!("/api/tunnel/{id}/certificate"),
        Some(&token),
        &body,
    )
    .await;
    assert_eq!(status, 202, "{response}");
    let record = srv.state.db.get_tunnel(&id).unwrap().unwrap();
    assert_ne!(record.cert_id.as_deref(), Some("cert_failed"));
    assert_eq!(record.csr_pem.as_deref(), Some(replacement_csr.as_str()));
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
    srv.state
        .db
        .begin_issuance(&id, "cert_concurrent_attach", "dummy-csr")
        .unwrap();
    srv.state
        .db
        .set_ready(
            "cert_concurrent_attach",
            "CERT",
            "CHAIN",
            "2099-01-01T00:00:00Z",
        )
        .unwrap();

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
