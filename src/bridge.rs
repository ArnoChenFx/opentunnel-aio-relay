//! Bridge session management: one WebSocket per client session.
//!
//! This replaces the per-tunnel Durable Object of the Cloudflare deployment.
//! Each [`Session`] owns the attached bridges (each with its claimed routes)
//! and the active proxied TCP channels. The wire protocol is unchanged, so
//! existing clients work without modification.

use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, RwLock, mpsc};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::proto::bridge::{
    self, ClientMessage, ConnId, ServerMessage, Transport, decode_data_frame, encode_data_frame,
};
use crate::proto::names;
use crate::state::{AppState, now_rfc3339};

/// Outgoing frames queued for one bridge WebSocket.
#[derive(Debug)]
pub enum OutMsg {
    Text(String),
    Binary(Vec<u8>),
}

/// Incoming traffic for one proxied TCP connection, delivered to the task
/// that owns the public socket.
#[derive(Debug)]
pub enum ChannelMsg {
    Data(Vec<u8>),
    End,
    Reset(String),
}

pub struct BridgeHandle {
    pub id: String,
    pub routes: Vec<String>,
    pub tx: mpsc::Sender<OutMsg>,
}

pub struct Session {
    pub id: String,
    pub hostname: String,
    pub token_hash: String,
    pub cert_ready: AtomicBool,
    bridges: AsyncMutex<Vec<BridgeHandle>>,
    channels: AsyncMutex<HashMap<ConnId, mpsc::Sender<ChannelMsg>>>,
    next_conn: AtomicU32,
}

#[derive(Default)]
pub struct SessionManager {
    inner: RwLock<HashMap<String, Arc<Session>>>,
}

impl SessionManager {
    /// Returns the in-memory session, loading it from the DB on first use.
    pub async fn get_or_load(&self, db: &Db, id: &str) -> Result<Option<Arc<Session>>> {
        if let Some(session) = self.inner.read().await.get(id) {
            return Ok(Some(session.clone()));
        }
        let record = match db.get_tunnel(id)? {
            Some(record) if record.deleted_at.is_none() => record,
            _ => return Ok(None),
        };
        let session = Arc::new(Session {
            id: record.id.clone(),
            hostname: record.hostname.clone(),
            token_hash: record.token_hash.clone(),
            cert_ready: AtomicBool::new(record.cert_pem.is_some()),
            bridges: AsyncMutex::new(Vec::new()),
            channels: AsyncMutex::new(HashMap::new()),
            next_conn: AtomicU32::new(1),
        });
        self.inner.write().await.insert(id.to_string(), session.clone());
        Ok(Some(session))
    }

    pub async fn insert(&self, session: Arc<Session>) {
        self.inner.write().await.insert(session.id.clone(), session);
    }

    pub async fn remove(&self, id: &str) {
        self.inner.write().await.remove(id);
    }
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

const TUNNEL_ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn random_tunnel_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| TUNNEL_ID_ALPHABET[(b & 31) as usize] as char)
        .collect()
}

pub fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "rly_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

use base64::Engine as _;

/// Runs one bridge WebSocket: attach handshake, then bidirectional relay.
/// Called from the axum `/connect` handler after the HTTP upgrade.
pub async fn run_bridge(state: Arc<AppState>, tunnel_id: String, mut socket: WebSocket) {
    if let Err(e) = bridge_loop(state, &tunnel_id, &mut socket).await {
        tracing::debug!(tunnel = %tunnel_id, error = %e, "bridge ended");
    }
}

async fn bridge_loop(state: Arc<AppState>, tunnel_id: &str, socket: &mut WebSocket) -> Result<()> {
    // The client must send `attach` within 10 seconds (protocol spec).
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), socket.next())
        .await
        .map_err(|_| Error::Internal("attach timeout".into()))?
        .ok_or_else(|| Error::Internal("bridge closed before attach".into()))?;
    let first = first.map_err(|e| Error::Internal(format!("websocket error: {e}")))?;

    let attach = match first {
        Message::Text(text) => parse_client_message(&text),
        _ => None,
    };
    let (token, routes, _client) = match attach {
        Some(ClientMessage::Attach {
            token,
            transport: Transport::Ws,
            routes,
            client,
        }) => (token, routes, client),
        _ => {
            let _ = socket.close().await;
            return Err(Error::Internal("attach required".into()));
        }
    };

    let session = match state.sessions.get_or_load(&state.db, tunnel_id).await? {
        Some(s) => s,
        None => {
            send_text(
                socket,
                &ServerMessage::AttachError {
                    code: bridge::codes::BAD_TOKEN.to_string(),
                },
            )
            .await?;
            let _ = socket.close().await;
            return Ok(());
        }
    };

    if hash_token(&token) != session.token_hash {
        send_text(
            socket,
            &ServerMessage::AttachError {
                code: bridge::codes::BAD_TOKEN.to_string(),
            },
        )
        .await?;
        let _ = socket.close().await;
        return Ok(());
    }
    if !session.cert_ready.load(Ordering::SeqCst) {
        send_text(
            socket,
            &ServerMessage::AttachError {
                code: bridge::codes::CERT_NOT_READY.to_string(),
            },
        )
        .await?;
        let _ = socket.close().await;
        return Ok(());
    }

    // Legacy clients attach the base hostname.
    let mut routes: Vec<String> = {
        let mut seen = HashSet::new();
        routes
            .into_iter()
            .filter(|r| seen.insert(r.clone()))
            .collect()
    };
    if routes.is_empty() {
        routes.push(names::ROOT_ROUTE.to_string());
    }
    if routes.iter().any(|r| !names::is_valid_route(r)) {
        send_text(
            socket,
            &ServerMessage::AttachError {
                code: "invalid_route".to_string(),
            },
        )
        .await?;
        let _ = socket.close().await;
        return Ok(());
    }
    // A route belongs to one bridge at a time (takeover via retry).
    {
        let bridges = session.bridges.lock().await;
        let conflict = bridges.iter().any(|b| {
            b.routes
                .iter()
                .any(|r| routes.iter().any(|want| want == r))
        });
        if conflict {
            drop(bridges);
            send_text(
                socket,
                &ServerMessage::AttachError {
                    code: "route_conflict".to_string(),
                },
            )
            .await?;
            let _ = socket.close().await;
            return Ok(());
        }
    }

    let bridge_id = format!("sess_{}", random_session_id());
    let (tx, mut rx) = mpsc::channel::<OutMsg>(512);
    {
        let mut bridges = session.bridges.lock().await;
        bridges.push(BridgeHandle {
            id: bridge_id.clone(),
            routes: routes.clone(),
            tx,
        });
    }
    state.db.set_online(tunnel_id, true, &now_rfc3339())?;
    state.db.touch_connected(tunnel_id, &now_rfc3339())?;
    tracing::info!(tunnel = %tunnel_id, bridge = %bridge_id, routes = ?routes, "bridge attached");

    send_text(
        socket,
        &ServerMessage::Attached {
            session: bridge_id.clone(),
            routes: routes.clone(),
            heartbeat_ms: bridge::HEARTBEAT_MS,
            idle_timeout_ms: bridge::IDLE_TIMEOUT_MS,
        },
    )
    .await?;

    // Renew now if the certificate is close to expiry (covers idle tunnels
    // coming back). Runs in the background; the current cert keeps serving.
    crate::acme::maybe_renew_on_attach(state.clone(), tunnel_id).await;

    let idle = tokio::time::sleep(std::time::Duration::from_millis(bridge::IDLE_TIMEOUT_MS));
    tokio::pin!(idle);

    loop {
        tokio::select! {
            _ = &mut idle => {
                tracing::debug!(tunnel = %tunnel_id, "bridge idle timeout");
                break;
            }
            out = rx.recv() => {
                let Some(out) = out else { break };
                let msg = match out {
                    OutMsg::Text(t) => Message::Text(t.into()),
                    OutMsg::Binary(b) => Message::Binary(b.into()),
                };
                if socket.send(msg).await.is_err() { break; }
            }
            incoming = socket.next() => {
                let Some(incoming) = incoming else { break };
                let msg = match incoming {
                    Ok(m) => m,
                    Err(_) => break,
                };
                idle.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_millis(bridge::IDLE_TIMEOUT_MS));
                match msg {
                    Message::Text(text) => {
                        if let Some(control) = parse_client_message(&text) {
                            if let Some(reply) = handle_control(&session, control).await {
                                if send_text(socket, &reply).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Message::Binary(data) => {
                        if let Some((conn, payload)) = decode_data_frame(&data) {
                            let channels = session.channels.lock().await;
                            if let Some(tx) = channels.get(&conn) {
                                let _ = tx.send(ChannelMsg::Data(payload.to_vec())).await;
                            }
                        }
                    }
                    Message::Ping(data) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    detach_bridge(&state, &session, &bridge_id).await;
    let _ = socket.close().await;
    Ok(())
}

async fn detach_bridge(state: &AppState, session: &Arc<Session>, bridge_id: &str) {
    let remaining;
    {
        let mut bridges = session.bridges.lock().await;
        bridges.retain(|b| b.id != bridge_id);
        remaining = bridges.len();
    }
    // Abort channels owned by this bridge.
    {
        let mut channels = session.channels.lock().await;
        let owned: Vec<ConnId> = channels.keys().copied().collect();
        for conn in owned {
            if let Some(tx) = channels.remove(&conn) {
                let _ = tx.send(ChannelMsg::Reset("bridge_disconnected".into())).await;
            }
        }
    }
    if remaining == 0 {
        let _ = state.db.set_online(&session.id, false, &now_rfc3339());
    }
    tracing::info!(tunnel = %session.id, bridge = %bridge_id, "bridge detached");
}

/// Handles an incoming control message. Returns a reply to send, if any.
async fn handle_control(session: &Arc<Session>, control: ClientMessage) -> Option<ServerMessage> {
    match control {
        ClientMessage::Ping { time_sent } => Some(ServerMessage::Pong { time_sent }),
        ClientMessage::Pong { .. } => None,
        ClientMessage::End { conn } | ClientMessage::Reset { conn, .. } => {
            let is_reset = matches!(control, ClientMessage::Reset { .. });
            let channels = session.channels.lock().await;
            if let Some(tx) = channels.get(&conn) {
                let _ = tx
                    .send(if is_reset {
                        ChannelMsg::Reset("reset".into())
                    } else {
                        ChannelMsg::End
                    })
                    .await;
            }
            None
        }
        ClientMessage::Attach { .. } => None,
    }
}

/// Lenient decode: unknown message types are ignored per the protocol spec.
fn parse_client_message(text: &str) -> Option<ClientMessage> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let kind = value.get("type")?.as_str()?;
    match kind {
        "attach" | "ping" | "pong" | "end" | "reset" => {
            serde_json::from_value(value).ok()
        }
        _ => None,
    }
}

async fn send_text(socket: &mut WebSocket, msg: &ServerMessage) -> Result<()> {
    let text = serde_json::to_string(msg)?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| Error::Internal(format!("websocket send error: {e}")))?;
    Ok(())
}

pub fn random_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl Session {
    /// Finds the bridge currently holding `route`, if any.
    pub async fn bridge_for_route(&self, route: &str) -> Option<mpsc::Sender<OutMsg>> {
        let bridges = self.bridges.lock().await;
        bridges
            .iter()
            .find(|b| b.routes.iter().any(|r| r == route))
            .map(|b| b.tx.clone())
    }

    /// Registers a new proxied connection; returns its connection id.
    pub async fn open_channel(&self) -> (ConnId, mpsc::Receiver<ChannelMsg>) {
        let mut conn = self.next_conn.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<ChannelMsg>(256);
        let mut channels = self.channels.lock().await;
        while conn == 0 || channels.contains_key(&conn) {
            conn = self.next_conn.fetch_add(1, Ordering::SeqCst);
        }
        channels.insert(conn, tx);
        (conn, rx)
    }

    pub async fn channel_sender(&self, conn: ConnId) -> Option<mpsc::Sender<ChannelMsg>> {
        self.channels.lock().await.get(&conn).cloned()
    }

    pub async fn close_channel(&self, conn: ConnId) {
        self.channels.lock().await.remove(&conn);
    }

    pub async fn send_data(
        &self,
        bridge_tx: &mpsc::Sender<OutMsg>,
        conn: ConnId,
        payload: &[u8],
    ) -> bool {
        for chunk in payload.chunks(bridge::MAX_PAYLOAD_SIZE) {
            let frame = encode_data_frame(conn, chunk);
            if bridge_tx.send(OutMsg::Binary(frame)).await.is_err() {
                return false;
            }
        }
        true
    }
}
