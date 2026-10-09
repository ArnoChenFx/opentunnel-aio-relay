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
use tower::ServiceExt;

use crate::bridge::{ChannelMsg, OutMsg};
use crate::error::{Error, Result};
use crate::proto::{bridge as proto, names};
use crate::sni::{Parse, parse_client_hello};
use crate::state::AppState;

const CLIENT_HELLO_LIMIT: usize = 64 * 1024;
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

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
    loop {
        let (socket, peer) = listener.accept().await?;
        let state = state.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, peer, state, router).await {
                tracing::debug!(%peer, error = %e, "ingress connection closed");
            }
        });
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    router: Router,
) -> Result<()> {
    // Read just enough to parse the ClientHello.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let hello = loop {
        let n = tokio::time::timeout(CLIENT_HELLO_TIMEOUT, socket.read(&mut chunk))
            .await
            .map_err(|_| Error::Internal("ClientHello timeout".into()))?
            .map_err(Error::Io)?;
        if n == 0 {
            return Err(Error::Internal("connection closed before ClientHello".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        match parse_client_hello(&buf) {
            Parse::Complete(hello) => break hello,
            Parse::Invalid(reason) => return Err(Error::Internal(format!("bad ClientHello: {reason}"))),
            Parse::Incomplete => {
                if buf.len() >= CLIENT_HELLO_LIMIT {
                    return Err(Error::Internal("ClientHello exceeded inspection limit".into()));
                }
            }
        }
    };

    let domain = state.config.domain.to_lowercase();
    if hello.server_name == domain {
        return serve_api(socket, buf, state, router).await;
    }
    serve_tunnel(socket, peer, buf, hello.server_name, hello.alpn, state).await
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
async fn serve_api(socket: TcpStream, initial: Vec<u8>, state: Arc<AppState>, router: Router) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(state.api_tls.clone());
    let stream = Prepended {
        buf: std::io::Cursor::new(initial),
        inner: socket,
    };
    let tls = acceptor
        .accept(stream)
        .await
        .map_err(|e| Error::Internal(format!("API TLS accept failed: {e}")))?;
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
    if !session.cert_ready.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Error::Internal("certificate not ready".into()));
    }
    let route =
        names::route_for_sni(&sni, &session.hostname).ok_or_else(|| Error::Internal("unknown route".into()))?;
    let bridge_tx = session
        .bridge_for_route(&route)
        .await
        .ok_or_else(|| Error::Internal("no bridge for route".into()))?;

    let (conn, mut chan_rx) = session.open_channel().await;
    tracing::debug!(tunnel = %session.id, %route, %conn, %peer, "proxying connection");

    // Tell the bridge about the new connection, then replay the buffered
    // bytes (starting with the ClientHello) as data frames.
    let open = serde_json::to_string(&proto::ServerMessage::Open {
        conn,
        peer: peer.to_string(),
        sni: sni.clone(),
        alpn,
    })?;
    bridge_tx
        .send(OutMsg::Text(open))
        .await
        .map_err(|_| Error::Internal("bridge gone".into()))?;
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
        while let Some(msg) = chan_rx.recv().await {
            match msg {
                ChannelMsg::Data(data) => writer.write_all(&data).await?,
                ChannelMsg::End => {
                    writer.shutdown().await.ok();
                    break;
                }
                ChannelMsg::Reset(_) => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = pump_up => {
            if let Err(e) = result {
                let _ = bridge_tx.send(OutMsg::Text(
                    serde_json::to_string(&proto::ServerMessage::Reset { conn, code: "client_io_error".into() }).unwrap(),
                )).await;
                tracing::debug!(%conn, error = %e, "upstream pump failed");
            }
        }
        _ = pump_down => {}
    }
    session.close_channel(conn).await;
    Ok(())
}
