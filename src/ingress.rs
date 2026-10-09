//! TCP ingress: one listener demultiplexed by TLS SNI.
//!
//! Every inbound connection is peeked for its ClientHello (never terminated
//! here). SNI == the API domain is terminated locally with the API certificate
//! and served the HTTP API; SNI == `<route>.`<tunnel-id>.<domain> is forwarded
//! as opaque encrypted bytes to the tunnel's bridge WebSocket. The relay
//! never sees plaintext.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;

use crate::bridge::{ChannelMsg, OutMsg};
use crate::error::{Error, Result};
use crate::proto::{bridge as proto, names};
use crate::sni::{parse_client_hello, Parse};
use crate::state::AppState;

const CLIENT_HELLO_LIMIT: usize = 64 * 1024;
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_HANDSHAKES: usize = 256;

pub async fn run(state: Arc<AppState>, router: Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&state.config.listen).await?;
    tracing::info!(listen = %state.config.listen, domain = %state.config.domain, "relay listening");
    run_on(listener, state, router).await
}

pub async fn run_on(
    listener: TcpListener,
    state: Arc<AppState>,
    router: Router,
) -> anyhow::Result<()> {
    let handshake_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES));
    loop {
        let (socket, peer) = listener.accept().await?;
        let Some(permit) = try_acquire_handshake(&handshake_permits) else {
            drop(socket);
            continue;
        };
        let state = state.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, peer, state, router, permit).await {
                tracing::debug!(%peer, error = %e, "ingress connection closed");
            }
        });
    }
}

fn try_acquire_handshake(permits: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(permits).try_acquire_owned().ok()
}

async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    router: Router,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + CLIENT_HELLO_TIMEOUT;
    let (buf, hello) = read_client_hello_until(&mut socket, deadline).await?;

    let domain = state.config.domain.to_lowercase();
    if hello.server_name == domain {
        return serve_api(socket, buf, state, router, deadline, permit).await;
    }
    drop(permit);
    serve_tunnel(socket, peer, buf, hello.server_name, hello.alpn, state).await
}

async fn read_client_hello_until(
    socket: &mut TcpStream,
    deadline: tokio::time::Instant,
) -> Result<(Vec<u8>, crate::sni::ClientHello)> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let hello = loop {
        let n = tokio::time::timeout_at(deadline, socket.read(&mut chunk))
            .await
            .map_err(|_| Error::Internal("ClientHello timeout".into()))?
            .map_err(Error::Io)?;
        if n == 0 {
            return Err(Error::Internal(
                "connection closed before ClientHello".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        match parse_client_hello(&buf) {
            Parse::Complete(hello) => break hello,
            Parse::Invalid(reason) => {
                return Err(Error::Internal(format!("bad ClientHello: {reason}")))
            }
            Parse::Incomplete => {
                if buf.len() >= CLIENT_HELLO_LIMIT {
                    return Err(Error::Internal(
                        "ClientHello exceeded inspection limit".into(),
                    ));
                }
            }
        }
    };
    Ok((buf, hello))
}

/// A stream with already-read bytes prepended back in front.
/// The ingress peeks the ClientHello before deciding; the API branch must
/// hand those bytes to the TLS acceptor as if they were never consumed.
struct Prepended<R> {
    buf: std::io::Cursor<Vec<u8>>,
    inner: R,
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Prepended<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.buf.position() < self.buf.get_ref().len() as u64 {
            std::pin::Pin::new(&mut self.buf).poll_read(cx, buf)
        } else {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl<R: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Prepended<R> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Terminates TLS for the API domain and serves the axum router over it.
async fn serve_api(
    socket: TcpStream,
    initial: Vec<u8>,
    state: Arc<AppState>,
    router: Router,
    deadline: tokio::time::Instant,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    let tls_config = state.api_tls.read().await.clone();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let stream = Prepended {
        buf: std::io::Cursor::new(initial),
        inner: socket,
    };
    let tls = accept_tls_until(&acceptor, stream, deadline).await?;
    drop(permit);
    let io = TokioIo::new(tls);
    let svc = hyper_util::service::TowerToHyperService::new(tower::service_fn(
        move |req: hyper::Request<hyper::body::Incoming>| {
            let router = router.clone();
            async move {
                match router.oneshot(req.map(axum::body::Body::new)).await {
                    Ok(res) => Ok(res),
                    Err(never) => Err(std::io::Error::other(format!("router error: {never:?}"))),
                }
            }
        },
    ));
    // NOTE: `.with_upgrades()` is required: without it hyper completes the
    // server-side upgrade future with an error and the bridge WebSocket
    // handshake silently dies after the 101 is sent.
    http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades()
        .await
        .map_err(|e| Error::Internal(format!("API connection error: {e}")))?;
    Ok(())
}

async fn accept_tls_until<S>(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: S,
    deadline: tokio::time::Instant,
) -> Result<tokio_rustls::server::TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout_at(deadline, acceptor.accept(stream))
        .await
        .map_err(|_| Error::Internal("API TLS handshake timeout".into()))?
        .map_err(|e| Error::Internal(format!("API TLS accept failed: {e}")))
}

/// Blind passthrough: route by SNI to the tunnel's bridge without
/// terminating TLS.
async fn serve_tunnel(
    socket: TcpStream,
    peer: SocketAddr,
    initial: Vec<u8>,
    sni: String,
    alpn: String,
    state: Arc<AppState>,
) -> Result<()> {
    let domain = state.config.domain.to_lowercase();
    let suffix = format!(".{domain}");
    let Some(labels) = sni.strip_suffix(&suffix) else {
        return Err(Error::Internal("SNI is not an OpenTunnel hostname".into()));
    };
    // The tunnel id is the last label before the domain, as in the original.
    let tunnel_id = labels.rsplit('.').next().unwrap_or("");
    if tunnel_id.is_empty() {
        return Err(Error::Internal("SNI is not an OpenTunnel hostname".into()));
    }

    let session = state
        .sessions
        .get_or_load(&state.db, tunnel_id)
        .await?
        .ok_or_else(|| Error::Internal("unknown tunnel".into()))?;
    let mut shutdown_rx = session.subscribe_shutdown();
    if session.is_closed() {
        return Err(Error::Internal("tunnel was deleted".into()));
    }
    if !session.cert_ready.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Error::Internal("certificate not ready".into()));
    }
    let route = names::route_for_sni(&sni, &session.hostname)
        .ok_or_else(|| Error::Internal("unknown route".into()))?;
    let (conn, mut chan_rx, mut channel_shutdown, bridge_tx) = session
        .open_channel_for_route(&route)
        .await
        .ok_or_else(|| Error::Internal("no bridge for route".into()))?;
    tracing::debug!(tunnel = %session.id, %route, %conn, %peer, "proxying connection");

    // Tell the bridge about the new connection, then replay the buffered
    // bytes (starting with the ClientHello) as data frames.
    let open = serde_json::to_string(&proto::ServerMessage::Open {
        conn,
        peer: peer.to_string(),
        sni: sni.clone(),
        alpn,
    })?;
    if bridge_tx.send(OutMsg::Text(open)).await.is_err() {
        session.close_channel(conn).await;
        return Err(Error::Internal("bridge gone".into()));
    }
    if !session.send_data(&bridge_tx, conn, &initial).await {
        session.close_channel(conn).await;
        return Err(Error::Internal("bridge gone".into()));
    }

    let (mut reader, mut writer) = socket.into_split();

    // Public socket -> bridge.
    let bridge_up = bridge_tx.clone();
    let session_up = session.clone();
    let pump_up = async move {
        let mut chunk = [0u8; 32 * 1024];
        loop {
            let n = reader.read(&mut chunk).await?;
            if n == 0 {
                let _ = bridge_up
                    .send(OutMsg::Text(
                        serde_json::to_string(&proto::ServerMessage::End { conn }).unwrap(),
                    ))
                    .await;
                break;
            }
            if !session_up.send_data(&bridge_up, conn, &chunk[..n]).await {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    // Bridge -> public socket.
    let pump_down = async move {
        loop {
            let message = tokio::select! {
                changed = channel_shutdown.changed() => {
                    let _ = changed;
                    return Err(anyhow::anyhow!("bridge channel cancelled: {}", channel_cancel_reason(&channel_shutdown)));
                }
                message = chan_rx.recv() => message,
            };
            match message {
                Some(ChannelMsg::Data(data)) => {
                    tokio::select! {
                        result = writer.write_all(&data) => result?,
                        changed = channel_shutdown.changed() => {
                            let _ = changed;
                            return Err(anyhow::anyhow!("bridge channel cancelled: {}", channel_cancel_reason(&channel_shutdown)));
                        }
                    }
                }
                Some(ChannelMsg::End) => {
                    tokio::select! {
                        result = writer.shutdown() => result?,
                        changed = channel_shutdown.changed() => {
                            let _ = changed;
                            return Err(anyhow::anyhow!("bridge channel cancelled: {}", channel_cancel_reason(&channel_shutdown)));
                        }
                    }
                    return Ok::<(), anyhow::Error>(());
                }
                Some(ChannelMsg::Reset(reason)) => {
                    return Err(anyhow::anyhow!("bridge reset: {reason}"));
                }
                None => return Err(anyhow::anyhow!("bridge channel closed")),
            }
        }
    };

    let result = tokio::select! {
        _ = shutdown_rx.changed() => Err(anyhow::anyhow!("tunnel was deleted")),
        result = async { tokio::try_join!(pump_up, pump_down).map(|_| ()) } => result,
    };
    if let Err(error) = result {
        let reset = serde_json::to_string(&proto::ServerMessage::Reset {
            conn,
            code: "connection_terminated".into(),
        })
        .unwrap();
        let _ = bridge_tx.try_send(OutMsg::Text(reset));
        tracing::debug!(%conn, error = %error, "proxy connection terminated");
    }
    session.close_channel(conn).await;
    Ok(())
}

fn channel_cancel_reason(shutdown: &tokio::sync::watch::Receiver<Option<String>>) -> String {
    shutdown
        .borrow()
        .clone()
        .unwrap_or_else(|| "channel closed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_hello_slow_drip_cannot_extend_total_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_client_hello_until(
                &mut socket,
                tokio::time::Instant::now() + Duration::from_millis(220),
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x16]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = client.write_all(&[0x03]).await;

        let result = tokio::time::timeout(Duration::from_millis(300), server)
            .await
            .expect("ClientHello deadline should be absolute")
            .unwrap();
        assert!(result.unwrap_err().to_string().contains("timeout"));
    }

    #[tokio::test]
    async fn api_tls_handshake_obeys_client_hello_deadline() {
        let certified = rcgen::generate_simple_self_signed(vec!["relay.test".to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            accept_tls_until(&acceptor, socket, deadline)
                .await
                .map(|_| ())
        });

        let socket = TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("relay.test")
            .unwrap()
            .to_owned();
        let client = tokio::spawn(async move {
            let _ = connector
                .connect(server_name, StallClientReads(socket))
                .await;
        });
        let server = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert!(server.unwrap_err().to_string().contains("timeout"));
        client.abort();
    }

    #[tokio::test]
    async fn concurrent_handshake_limit_rejects_excess_and_releases_capacity() {
        let permits = Arc::new(Semaphore::new(2));
        let first = try_acquire_handshake(&permits).expect("first permit");
        let second = try_acquire_handshake(&permits).expect("second permit");
        assert!(try_acquire_handshake(&permits).is_none());

        drop(first);
        assert!(try_acquire_handshake(&permits).is_some());
        drop(second);
    }

    struct StallClientReads(TcpStream);

    impl tokio::io::AsyncRead for StallClientReads {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for StallClientReads {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }
}
